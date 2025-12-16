# Recompiling

```bash
git submodule update --init
cargo build --release
```

# Running with Config

```bash
./target/release/rpxy --config ../food/rpxy-config.toml
```

# JWT Testers

[Create JWT](http://jwtbuilder.jamiekurtz.com/)  
[Custom JWT Encoder](https://www.jwt.io/)
