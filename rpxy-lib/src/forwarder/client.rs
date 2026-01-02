#[allow(unused)]
use crate::{
  error::{RpxyError, RpxyResult},
  globals::Globals,
  hyper_ext::{body::ResponseBody, rt::LocalExecutor},
  log::*,
};
use async_trait::async_trait;
use http::{Request, Response, Version};
use hyper::body::{Body, Incoming};
use hyper_util::client::legacy::{
  Client,
  connect::{Connect, HttpConnector},
};

use std::sync::Arc;
#[cfg(feature = "custom")]
use {
  cookie::Cookie,
  hex,
  http::header::COOKIE,
  jsonwebtoken::{Algorithm, DecodingKey, Validation, decode},
  moka::future::Cache,
  serde::Deserialize,
  sha2::{Digest, Sha256},
  std::{
    collections::HashSet,
    env,
    sync::atomic::{AtomicI64, Ordering::Relaxed},
    time::Duration,
  },
};

#[cfg(feature = "cache")]
use super::cache::{RpxyCache, get_policy_if_cacheable};

#[derive(Clone, Debug)]
pub struct CustomSettings {
  fast_moka_cache: Cache<String, Arc<AtomicI64>>,
  fast_paths: HashSet<String>,
  slow_moka_cache: Cache<String, Arc<AtomicI64>>,
  jwt_key: String,
}

impl CustomSettings {
  pub(crate) async fn new(globals: &Globals) -> Self {
    Self {
      fast_moka_cache: Cache::builder()
        .max_capacity(globals.proxy_config.custom_max_entries as u64)
        .time_to_live(Duration::from_millis(globals.proxy_config.custom_fast_rate_limit_ms as u64))
        .build(),
      fast_paths: globals.proxy_config.custom_fast_paths.clone(),
      slow_moka_cache: Cache::builder()
        .max_capacity(globals.proxy_config.custom_max_entries as u64)
        .time_to_live(Duration::from_millis(globals.proxy_config.custom_slow_rate_limit_ms as u64))
        .build(),
      jwt_key: env::var("JWT_KEY").expect("JWT_KEY must be set"),
    }
  }
}

#[derive(Deserialize)]
struct Claims {
  #[allow(unused)]
  exp: usize,
}

#[async_trait]
/// Definition of the forwarder that simply forward requests from downstream client to upstream app servers.
pub trait ForwardRequest<B1, B2> {
  type Error;
  async fn request(&self, req: Request<B1>) -> Result<Response<B2>, Self::Error>;
}

/// Forwarder http client struct responsible to cache handling
pub struct Forwarder<C, B> {
  #[cfg(feature = "cache")]
  cache: Option<RpxyCache>,
  #[cfg(feature = "custom")]
  custom: CustomSettings,
  inner: Client<C, B>,
  inner_h2: Client<C, B>, // `h2c` or http/2-only client is defined separately
}

#[async_trait]
impl<C, B1> ForwardRequest<B1, ResponseBody> for Forwarder<C, B1>
where
  C: Send + Sync + Connect + Clone + 'static,
  B1: Body + Send + Sync + Unpin + 'static,
  <B1 as Body>::Data: Send,
  <B1 as Body>::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
{
  type Error = RpxyError;

  async fn request(&self, req: Request<B1>) -> Result<Response<ResponseBody>, Self::Error> {
    #[cfg(feature = "custom")]
    {
      let mut user_jwt = None;

      // check if user has jwt cookie
      if let Some(cookie_header) = req.headers().get(COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
          for cookie in Cookie::split_parse(cookie_str) {
            let cookie = cookie.unwrap();

            if cookie.name() == "user_jwt" {
              user_jwt = Some(cookie.value().to_string());
            }
          }
        }
      }

      if user_jwt.is_none() {
        return Err(Self::Error::InvalidCredentials(
          "Missing or invalid user_jwt cookie".to_string(),
        ));
      }

      // check if valid signature and expiration
      if decode::<Claims>(
        user_jwt.as_ref().expect("cookie should be here"),
        &DecodingKey::from_secret(self.custom.jwt_key.as_bytes()),
        &Validation::new(Algorithm::HS256),
      )
      .is_err()
      {
        return Err(Self::Error::InvalidCredentials(
          "Missing or invalid user_jwt cookie".to_string(),
        ));
      };

      // generate hash string to lookup
      let mut hasher = Sha256::new();
      hasher.update(user_jwt.expect("cookie has been verified"));
      let hashed_string = hex::encode(hasher.finalize());

      let host = req.uri().host().unwrap_or_default().to_string();
      let path = req.uri().path().to_string();
      let full_path = format!("{}{}", host, path);

      let mut _counter = None;
      if !full_path.is_empty() && self.custom.fast_paths.contains(&full_path) {
        _counter = Some(
          self
            .custom
            .fast_moka_cache
            .get_with(hashed_string.clone(), async { Arc::new(AtomicI64::new(0)) })
            .await,
        );
      } else {
        _counter = Some(
          self
            .custom
            .slow_moka_cache
            .get_with(hashed_string.clone(), async { Arc::new(AtomicI64::new(0)) })
            .await,
        );
      }

      // atomically fetch add the same arc reference
      if _counter.expect("counter should be processed").fetch_add(1, Relaxed) > 0 {
        return Err(Self::Error::RateLimitExceeded(
          "Too many requests - Rate limit exceeded".to_string(),
        ));
      }
    }

    // TODO: cache handling
    #[cfg(feature = "cache")]
    {
      let mut synth_req = None;
      if self.cache.is_some() {
        // try reading from cache
        if let Some(cached_response) = self.cache.as_ref().unwrap().get(&req).await {
          // if found, return it as response.
          info!("Cache hit - Return from cache");
          return Ok(cached_response);
        };

        // Synthetic request copy used just for caching (cannot clone request object...)
        synth_req = Some(build_synth_req_for_cache(&req));
      }
      let res = self.request_directly(req).await;

      if self.cache.is_none() {
        return res.map(|inner| inner.map(ResponseBody::Incoming));
      }

      // check cacheability and store it if cacheable
      let Ok(Some(cache_policy)) = get_policy_if_cacheable(synth_req.as_ref(), res.as_ref().ok()) else {
        return res.map(|inner| inner.map(ResponseBody::Incoming));
      };
      let (parts, body) = res.unwrap().into_parts();

      // Get streamed body without waiting for the arrival of the body,
      // which is done simultaneously with caching.
      let stream_body = self
        .cache
        .as_ref()
        .unwrap()
        .put(synth_req.unwrap().uri(), body, &cache_policy)
        .await?;

      // response with body being cached in background
      let new_res = Response::from_parts(parts, ResponseBody::Streamed(stream_body));
      Ok(new_res)
    }

    // No cache handling
    #[cfg(not(feature = "cache"))]
    {
      self
        .request_directly(req)
        .await
        .map(|inner| inner.map(ResponseBody::Incoming))
    }
  }
}

impl<C, B1> Forwarder<C, B1>
where
  C: Send + Sync + Connect + Clone + 'static,
  B1: Body + Send + Unpin + 'static,
  <B1 as Body>::Data: Send,
  <B1 as Body>::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
{
  async fn request_directly(&self, req: Request<B1>) -> RpxyResult<Response<Incoming>> {
    // TODO: This 'match' condition is always evaluated at every 'request' invocation. So, it is inefficient.
    // Needs to be reconsidered. Currently, this is a kind of work around.
    // This possibly relates to https://github.com/hyperium/hyper/issues/2417.
    match req.version() {
      Version::HTTP_2 => self.inner_h2.request(req).await, // handles `h2c` requests
      _ => self.inner.request(req).await,
    }
    .map_err(|e| RpxyError::FailedToFetchFromUpstream(e.to_string()))
  }
}

#[cfg(not(any(feature = "native-tls-backend", feature = "rustls-backend")))]
impl<B> Forwarder<HttpConnector, B>
where
  B: Body + Send + Unpin + 'static,
  <B as Body>::Data: Send,
  <B as Body>::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
{
  /// Build inner client with http
  pub async fn try_new(_globals: &Arc<Globals>) -> RpxyResult<Self> {
    warn!(
      "
--------------------------------------------------------------------------------------------------
Request forwarder is working without TLS support!
This mode is intended for testing only.
Enable 'native-tls-backend' or 'rustls-backend' feature for TLS support.
--------------------------------------------------------------------------------------------------"
    );
    let executor = LocalExecutor::new(_globals.runtime_handle.clone());
    let mut http = HttpConnector::new();
    http.enforce_http(true);
    http.set_reuse_address(true);
    http.set_keepalive(Some(_globals.proxy_config.upstream_idle_timeout));
    let inner = Client::builder(executor).build::<_, B>(http);
    let inner_h2 = inner.clone();

    Ok(Self {
      inner,
      inner_h2,
      #[cfg(feature = "cache")]
      cache: RpxyCache::new(_globals).await,
      #[cfg(feature = "custom")]
      custom: CustomSettings::new(_globals).await,
    })
  }
}

#[cfg(all(feature = "native-tls-backend", not(feature = "rustls-backend")))]
/// Build forwarder with hyper-tls (native-tls)
impl<B1> Forwarder<hyper_tls::HttpsConnector<HttpConnector>, B1>
where
  B1: Body + Send + Unpin + 'static,
  <B1 as Body>::Data: Send,
  <B1 as Body>::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
{
  /// Build forwarder
  pub async fn try_new(_globals: &Arc<Globals>) -> RpxyResult<Self> {
    // build hyper client with hyper-tls
    info!("Native TLS support enabled for backend connections (native-tls)");
    let executor = LocalExecutor::new(_globals.runtime_handle.clone());

    let try_build_connector = |alpns: &[&str]| {
      hyper_tls::native_tls::TlsConnector::builder()
        .request_alpns(alpns)
        .build()
        .map_err(|e| RpxyError::FailedToBuildForwarder(e.to_string()))
        .map(|tls| {
          let mut http = HttpConnector::new();
          http.enforce_http(false);
          http.set_reuse_address(true);
          http.set_keepalive(Some(_globals.proxy_config.upstream_idle_timeout));
          hyper_tls::HttpsConnector::from((http, tls.into()))
        })
    };

    let connector = try_build_connector(&["h2", "http/1.1"])?;
    let inner = Client::builder(executor.clone()).build::<_, B1>(connector);

    let connector_h2 = try_build_connector(&["h2"])?;
    let inner_h2 = Client::builder(executor.clone())
      .http2_only(true)
      .build::<_, B1>(connector_h2);

    Ok(Self {
      inner,
      inner_h2,
      #[cfg(feature = "cache")]
      cache: RpxyCache::new(_globals).await,
      #[cfg(feature = "custom")]
      custom: CustomSettings::new(_globals).await,
    })
  }
}

#[cfg(feature = "rustls-backend")]
/// Build forwarder with hyper-rustls (rustls)
impl<B1> Forwarder<hyper_rustls::HttpsConnector<HttpConnector>, B1>
where
  B1: Body + Send + Unpin + 'static,
  <B1 as Body>::Data: Send,
  <B1 as Body>::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
{
  /// Build forwarder
  pub async fn try_new(_globals: &Arc<Globals>) -> RpxyResult<Self> {
    // build hyper client with rustls and webpki, only https is allowed
    #[cfg(feature = "webpki-roots")]
    let builder = hyper_rustls::HttpsConnectorBuilder::new().with_webpki_roots();
    #[cfg(feature = "webpki-roots")]
    let builder_h2 = hyper_rustls::HttpsConnectorBuilder::new().with_webpki_roots();
    #[cfg(feature = "webpki-roots")]
    info!("Rustls backend: Mozilla WebPKI root certs used for backend connections");

    #[cfg(not(feature = "webpki-roots"))]
    let builder = hyper_rustls::HttpsConnectorBuilder::new().with_platform_verifier();
    #[cfg(not(feature = "webpki-roots"))]
    let builder_h2 = hyper_rustls::HttpsConnectorBuilder::new().with_platform_verifier();
    #[cfg(not(feature = "webpki-roots"))]
    info!("Rustls backend: Platform verifier used for backend connections");

    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_reuse_address(true);
    http.set_keepalive(Some(_globals.proxy_config.upstream_idle_timeout));

    let connector = builder.https_or_http().enable_all_versions().wrap_connector(http.clone());
    let connector_h2 = builder_h2.https_or_http().enable_http2().wrap_connector(http);
    let inner = Client::builder(LocalExecutor::new(_globals.runtime_handle.clone())).build::<_, B1>(connector);
    let inner_h2 = Client::builder(LocalExecutor::new(_globals.runtime_handle.clone()))
      .http2_only(true)
      .build::<_, B1>(connector_h2);

    Ok(Self {
      inner,
      inner_h2,
      #[cfg(feature = "cache")]
      cache: RpxyCache::new(_globals).await,
      #[cfg(feature = "custom")]
      custom: CustomSettings::new(_globals).await,
    })
  }
}

#[cfg(feature = "cache")]
/// Build synthetic request to cache
fn build_synth_req_for_cache<T>(req: &Request<T>) -> Request<()> {
  let mut builder = Request::builder().method(req.method()).uri(req.uri()).version(req.version());
  // TODO: omit extensions. is this approach correct?
  for (header_key, header_value) in req.headers() {
    builder = builder.header(header_key, header_value);
  }
  builder.body(()).unwrap()
}
