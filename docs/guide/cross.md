# Cross-Compilation on Debian

This guide gives example for cross-compiling for aarch64, replace "aarch64" and "arm64" with respective architecture identifier tokens for cross-compiling for other architectures.

The "aya" loader is used by default.
To enable only the "libbpf" loader, specify Cargo flags `--no-default-features --features aya,pkg-config`.

### Build Dependencies

Install `gcc-aarch64-linux-gnu` for cross linking. Install `clang` for bindgen and compile eBPF C code in this project.

```
apt install gcc-aarch64-linux-gnu clang
# bpftool for BPF object stripping
apt install linux-tools-common
# Or use llvm-strip
apt install llvm
```

Install `rustup` to get Rust>=1.74, see https://www.rust-lang.org/tools/install. Also make sure `rustfmt` is installed as it's used by `libbpf-cargo`.

Add required target to Rust toolchain:

```
rustup target add aarch64-unknown-linux-gnu
```

### Target Dependencies

For "libbpf" loader, you would also need to install `libelf` and `zlib1g` as it's required by `libbpf`.

```
dpkg --add-architecture arm64
apt update
# We only need libbpf headers
apt install libbpf-dev:arm64
# For "libbpf" loader only
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

Specify `EINAT_BPF_CFLAGS` if einat build script failed to locate libbpf headers.

```
export EINAT_BPF_CFLAGS="-I /usr/include/aarch64-linux-gnu"
```

### Build static binary

```
cd einat-ebpf
cargo build --target aarch64-unknown-linux-gnu --features static --release
stat ./target/aarch64-unknown-linux-gnu/release/einat
```
