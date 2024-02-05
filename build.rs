use std::env;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/full_cone_nat.bpf.c";

fn main() {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("full_cone_nat.skel.rs");

    let mut c_args = vec![
        "-Wno-compare-distinct-pointer-types".to_string(),
        "-mcpu=v3".to_string(),
    ];

    if cfg!(feature = "ipv6") {
        c_args.push("-DFEAT_IPV6".to_string());
    }

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(c_args.join(" "))
        .debug(true)
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
}
