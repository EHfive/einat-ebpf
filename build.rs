use std::env;
use std::path::PathBuf;

const SRC: &str = "src/bpf/einat.bpf.c";
const SRC_DIR: &str = "src/bpf/";

fn out_path(file: &str) -> PathBuf {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push(file);
    out
}

fn c_args() -> Vec<String> {
    let mut c_args: Vec<String> = [
        "-Wall",
        "-mcpu=v3",
        "-fno-stack-protector",
        // error out if loop is not unrolled
        "-Werror=pass-failed",
        // "-Werror"
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    if cfg!(feature = "ipv6") {
        c_args.push("-DFEAT_IPV6".to_string());
    }

    c_args
}

#[cfg(any(feature = "aya", feature = "libbpf"))]
fn einat_obj_build() {
    use std::process::Command;

    let bpf_obj = &out_path("einat.bpf.o");

    // compile BPF C code
    let mut cmd = Command::new("clang");

    cmd.args(c_args());

    if let Some(cflags) = option_env!("EINAT_BPF_CFLAGS") {
        cmd.arg(cflags);
    }

    // Specify environment variable LIBBPF_NO_PKG_CONFIG=1 to disable pkg-config lookup.
    // Or just disable the "pkg-config" feature.
    #[cfg(feature = "pkg-config")]
    match pkg_config::probe_library("libbpf") {
        Ok(libbpf) => {
            let includes = libbpf
                .include_paths
                .into_iter()
                .map(|i| format!("-I{}", i.to_string_lossy()));
            cmd.args(includes);
        }
        Err(e) => {
            eprintln!("Can not locate libbpf with pkg-config: {}", e)
        }
    }

    let target = if env::var("CARGO_CFG_TARGET_ENDIAN").unwrap() == "little" {
        "bpfel"
    } else {
        "bpfeb"
    };

    cmd.arg("-target")
        .arg(target)
        .arg("-g")
        .arg("-O2")
        .arg("-c")
        .arg(SRC)
        .arg("-o")
        .arg(bpf_obj)
        .status()
        .expect("compile BPF object failed");

    // strip the DWARF debug information
    Command::new("llvm-strip")
        .arg("--strip-debug")
        .arg(bpf_obj)
        .status()
        .expect("llvm-strip BPF object file failed");
}

#[cfg(feature = "libbpf-skel")]
fn libbpf_skel_build() {
    use libbpf_cargo::SkeletonBuilder;

    let out = out_path("einat.skel.rs");

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(c_args())
        .debug(true)
        .build_and_generate(&out)
        .unwrap();
}

fn main() {
    #[cfg(any(feature = "aya", feature = "libbpf"))]
    einat_obj_build();

    #[cfg(feature = "libbpf-skel")]
    libbpf_skel_build();

    println!("cargo:rerun-if-changed={}", SRC_DIR);
}
