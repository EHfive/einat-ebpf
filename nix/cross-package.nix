{ naersk }:
{
  pkgs,
  crossPkgs ? pkgs,
  targetTriple ? crossPkgs.hostPlatform.config,
  enableStatic ? false,
  enableIpv6 ? false,
  rustVersion ? "latest"
}:
let
  inherit (pkgs) lib system;
  targetUnderscore = lib.replaceStrings [ "-" ] [ "_" ] targetTriple;
  targetUnderscoreUpper = lib.toUpper targetUnderscore;

  toolchain = pkgs.rust-bin.stable.${rustVersion}.minimal.override {
    targets = [ targetTriple ];
  };

  naersk' = naersk.lib.${system}.override {
    cargo = toolchain;
    rustc = toolchain;
  };

  crossCC = "${crossPkgs.stdenv.cc}/bin/${crossPkgs.stdenv.cc.targetPrefix}cc";

  buildInputs = with crossPkgs; [
    ## runtime dependencies on target platform
    stdenv.cc.libc
  ];

  buildInputsSearchFlags = map (dep: "-L${lib.getLib dep}/lib") buildInputs;
in
naersk'.buildPackage {
  src = ../.;
  gitSubmodules = true;
  nativeBuildInputs = with pkgs; [
    pkg-config

    # compile BPF C code
    llvmPackages.clang-unwrapped
    bpftools
  ];
  inherit buildInputs;
  strictDeps = true;

  cargoBuildOptions =
    orig:
    orig
    ++ lib.optionals enableStatic [
      "--features static"
    ]
    ++ lib.optionals enableIpv6 [
      "--features ipv6"
    ];

  CARGO_BUILD_TARGET = targetTriple;

  NIX_CFLAGS_COMPILE = lib.optionals (enableStatic && crossPkgs.hostPlatform.isAarch) [
    "-mno-outline-atomics"
  ];

  LIBBPF_NO_PKG_CONFIG = 1;
  EINAT_BPF_CFLAGS = "-I${pkgs.libbpf}/include";

  "CC_${targetUnderscore}" = crossCC;
  "CARGO_TARGET_${targetUnderscoreUpper}_LINKER" = crossCC;

  "CARGO_TARGET_${targetUnderscoreUpper}_RUSTFLAGS" = lib.concatStringsSep " " (
    [
      "-C target-feature=${if enableStatic then "+" else "-"}crt-static"
    ]
    ++ buildInputsSearchFlags
  );

  preBuild = ''
    # Avoid adding host dependencies to CFLAGS and LDFLAGS for build platform
    if [[ ${pkgs.stdenv.cc.suffixSalt} != ${crossPkgs.stdenv.cc.suffixSalt} ]]; then
      export NIX_CC_WRAPPER_TARGET_HOST_${pkgs.stdenv.cc.suffixSalt}="";
      export NIX_BINTOOLS_WRAPPER_TARGET_HOST_${pkgs.stdenv.cc.suffixSalt}="";
    fi
  '';

  doCheck = crossPkgs.system == pkgs.system;
}
