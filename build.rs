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
    use std::ffi::OsStr;
    use std::process::Command;

    let bpf_obj_tmp = &out_path("einat.bpf.tmp.o");
    let bpf_obj = &out_path("einat.bpf.o");

    // compile BPF C code
    let mut cmd = Command::new("clang");

    cmd.args(c_args());

    if let Some(cflags) = option_env!("EINAT_BPF_CFLAGS") {
        cmd.args(cflags.split_ascii_whitespace());
    }

    // Specify environment variable LIBBPF_NO_PKG_CONFIG=1 to disable pkg-config lookup.
    // Or just disable the "pkg-config" feature.
    #[cfg(feature = "pkg-config")]
    match pkg_config::Config::new()
        .cargo_metadata(false)
        .probe("libbpf")
    {
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

    let res = cmd
        .arg("-target")
        .arg(target)
        .arg("-g")
        .arg("-O2")
        .arg("-c")
        .arg(SRC)
        .arg("-o")
        .arg(bpf_obj_tmp)
        .status()
        .expect("compile BPF object failed");
    if !res.success() {
        panic!("{}", res);
    }

    fn strip_obj<S: AsRef<OsStr>>(strip_cmd: &str, target: S, source: S) -> Result<(), String> {
        let mut args = strip_cmd.split_ascii_whitespace();
        let cmd = args.next().unwrap();
        let res = Command::new(cmd)
            .args(args)
            .arg(target)
            .arg(source)
            .status();

        match res {
            Ok(res) => {
                if res.success() {
                    return Ok(());
                }
                Err(format!("{}: {}", strip_cmd, res))
            }
            Err(err) => Err(format!("{}: {}", strip_cmd, err)),
        }
    }

    // strip the DWARF debug information
    let strip_bpf_obj = || -> Result<(), String> {
        if let Some(strip_cmd) = option_env!("EINAT_BPF_STRIP_CMD") {
            return strip_obj(strip_cmd, bpf_obj, bpf_obj_tmp);
        }

        let res = strip_obj("bpftool gen object", bpf_obj, bpf_obj_tmp);
        if res.is_ok() {
            return res;
        }
        eprintln!("strip with bpftool failed, fallback to llvm-strip");

        let res = strip_obj("llvm-strip -g -o", bpf_obj, bpf_obj_tmp);
        if res.is_ok() {
            return res;
        }
        eprintln!("strip with llvm-strip failed, skip stripping");

        std::fs::rename(bpf_obj_tmp, bpf_obj).unwrap();

        Ok(())
    };

    strip_bpf_obj().expect("strip BPF object file failed");

    println!("cargo:rerun-if-env-changed=EINAT_BPF_CFLAGS");
    println!("cargo:rerun-if-env-changed=EINAT_BPF_STRIP_CMD");
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
    println!("cargo:rerun-if-changed=build.rs");
}
