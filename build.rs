fn main() {
    #[cfg(feature = "gen-skel")]
    {
        use libbpf_cargo::SkeletonBuilder;
        use std::env;
        use std::path::PathBuf;

        const SRC: &str = "src/bpf/einat.bpf.c";

        let mut out = if cfg!(feature = "gen-skel-source") {
            PathBuf::from("src")
        } else {
            PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"))
        };

        if cfg!(feature = "ipv6") {
            out.push("einat-ipv6.skel.rs");
        } else {
            out.push("einat-ipv4.skel.rs");
        }

        let mut c_args = vec![
            "-Wno-compare-distinct-pointer-types".to_string(),
            "-mcpu=v3".to_string(),
        ];

        if cfg!(feature = "ipv6") {
            c_args.push("-DFEAT_IPV6".to_string());
        }

        SkeletonBuilder::new()
            .source(SRC)
            .clang_args(c_args)
            .debug(true)
            .build_and_generate(&out)
            .unwrap();
        println!("cargo:rerun-if-changed={SRC}");
    }
}
