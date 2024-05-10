{ fenix, naersk }:
{ pkgs
, crossPkgs ? pkgs
, targetTriple ? crossPkgs.hostPlatform.config
, enableStatic ? false
, enableIpv6 ? false
}:
let
  inherit (pkgs) lib system;
  targetUnderscore = lib.replaceStrings [ "-" ] [ "_" ] targetTriple;
  targetUnderscoreUpper = lib.toUpper targetUnderscore;

  toolchain = with fenix.packages.${system};
    combine [
      minimal.rustc
      minimal.cargo
      # Rust target platform with support below tier 2 has no official builds
      # and requires build-std. However, fenix does not support build-std,
      # see https://github.com/nix-community/naersk/issues/146
      #complete.rust-src
      targets.${targetTriple}.latest.rust-std
    ];

  naersk' = naersk.lib.${system}.override {
    cargo = toolchain;
    rustc = toolchain;
  };

  crossCC = "${crossPkgs.stdenv.cc}/bin/${crossPkgs.stdenv.cc.targetPrefix}cc";

  buildInputs = with crossPkgs; [
    ## runtime dependencies of libbpf-sys on target platform
    stdenv.cc.libc
    # elfutils already has static library built
    elfutils
  ]
  ++ lib.optionals (!enableStatic) (with crossPkgs; [
    zlib
  ])
  ++ lib.optionals enableStatic (
    assert crossPkgs.hostPlatform.isMusl; with crossPkgs.pkgsStatic; [
      zlib
      #required by libelf
      zstd
    ]
  );

  buildInputsSearchFlags = map (dep: "-L${lib.getLib dep}/lib") buildInputs;
in
naersk'.buildPackage {
  src = ../.;
  gitSubmodules = true;
  depsBuildBuild = with pkgs; [
    # build dependencies of cargo build depenceies libbpf-cargo -> libbpf-sys
    stdenv.cc
  ];
  nativeBuildInputs = with pkgs;[
    pkg-config
    # required by `libbpf_cargo::SkeletonBuilder`
    rustfmt
    ## build dependencies of cargo build depenceies libbpf-cargo -> libbpf-sys
    stdenv.cc.libc
    zlib
    elfutils

    ## build dependencies of libbpf-sys on target platform
    # for cross linking libelf and zlib, and make libbpf
    crossPkgs.stdenv.cc
    # compile BPF C code
    clang
  ];
  inherit buildInputs;
  strictDeps = true;

  cargoBuildOptions = orig: orig ++ [
    #"-Z build-std"
  ] ++ lib.optionals enableStatic [
    "--features static"
  ] ++ lib.optionals enableIpv6 [
    "--features ipv6"
  ]
  ;

  # bindgen libbpf for build platform and target platform
  LIBCLANG_PATH = "${pkgs.clang.cc.lib}/lib";

  CARGO_BUILD_TARGET = targetTriple;

  NIX_CFLAGS_COMPILE = lib.optionals (enableStatic && crossPkgs.hostPlatform.isAarch) [ "-mno-outline-atomics" ];

  "CC_${targetUnderscore}" = crossCC;
  "CARGO_TARGET_${targetUnderscoreUpper}_LINKER" = crossCC;

  "CARGO_TARGET_${targetUnderscoreUpper}_RUSTFLAGS" = lib.concatStringsSep " "
    ([
      "-C target-feature=${if enableStatic then "+" else "-"}crt-static"
    ]
    ++ buildInputsSearchFlags
    ++ lib.optionals enableStatic [
      "-lstatic=pthread"
      "-lstatic=zstd"
    ]);

  preBuild = ''
    export BINDGEN_EXTRA_CLANG_ARGS_${targetUnderscore}="''${NIX_CFLAGS_COMPILE}";
    # Avoid adding host dependencies to CFLAGS and LDFLAGS for build platform
    if [[ ${pkgs.stdenv.cc.suffixSalt} != ${crossPkgs.stdenv.cc.suffixSalt} ]]; then
      export NIX_CC_WRAPPER_TARGET_HOST_${pkgs.stdenv.cc.suffixSalt}="";
      export NIX_BINTOOLS_WRAPPER_TARGET_HOST_${pkgs.stdenv.cc.suffixSalt}="";
    fi
  '';

  doCheck = true;
}
