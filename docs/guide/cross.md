## Cross-Compilation on Debian

This guide gives example for cross-compiling for aarch64, replace "aarch64" and "arm64" with respective architecture identifier tokens for cross-compiling for other architectures.

### Build Dependencies

Install `libelf` and `zlib1g` as it's required by `libbpf`. Install `gcc-aarch64-linux-gnu` for cross linking. Install `clang` for bindgen and compile eBPF C code in this project.

```
apt install libelf-dev zlib1g-dev gcc-aarch64-linux-gnu clang
```

Install `rustup` to get Rust>=1.74, see https://www.rust-lang.org/tools/install. Also make sure `rustfmt` is installed as it's used by `libbpf-cargo`.

Add required target to Rust toolchain:

```
rustup target add aarch64-unknown-linux-gnu
```

### Target Dependencies

```
dpkg --add-architecture arm64
apt update
apt install libelf-dev:arm64 zlib1g-dev:arm64
```

### Environment Variables

```
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="/usr/bin/aarch64-linux-gnu-gcc"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-feature=+crt-static -L /usr/lib/aarch64-linux-gnu"
export BINDGEN_EXTRA_CLANG_ARGS_aarch64_unknown_linux_gnu="-I /usr/include/aarch64-linux-gnu"

# you may additionally set `CC_<target>` and `CFLAGS_<target>` which read by Rust `cc` crate
export CC_aarch64_unknown_linux_gnu="/usr/bin/aarch64-linux-gnu-gcc"
export CFLAGS_aarch64_unknown_linux_gnu="-I /usr/include/aarch64-linux-gnu -L /usr/lib/aarch64-linux-gnu"
```

### Build static binary

```
cd einat-ebpf
cargo build --target aarch64-unknown-linux-gnu --features static --release
stat ./target/aarch64-unknown-linux-gnu/release/einat
```
