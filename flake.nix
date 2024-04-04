{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    systems.url = "github:nix-systems/default-linux";
    flake-utils = {
      url = "github:numtide/flake-utils";
      inputs.systems.follows = "systems";
    };
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, fenix, naersk, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = (import nixpkgs) {
          inherit system;
        };
        inherit (pkgs) lib;

        crossPackage =
          { crossPkgs ? pkgs
          , targetTriple ? crossPkgs.hostPlatform.config
          , enableStatic ? false
          , features ? [ ]
          }:
          let
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

            featureFlags = map (feat: "--features ${feat}") features;
          in
          naersk'.buildPackage {
            src = ./.;
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
            ] ++ featureFlags
              ++ lib.optionals enableStatic [
              "--features static"
            ];

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
          };
      in
      {
        packages = {
          # TODO: specify all possible combinations with matrix
          default = crossPackage { };
          ipv6 = crossPackage {
            features = [ "ipv6" ];
          };
          #   x86_64-unknown-linux-gnu = crossPackage {
          #     crossPkgs = pkgs.pkgsCross.gnu64;
          #   };
          #   i686-unknown-linux-gnu = crossPackage {
          #     crossPkgs = pkgs.pkgsCross.gnu64;
          #   };
          #   aarch64-unknown-linux-gnu = crossPackage {
          #     crossPkgs = pkgs.pkgsCross.aarch64-multiplatform;
          #   };

          static-x86_64-unknown-linux-musl = crossPackage {
            crossPkgs = pkgs.pkgsCross.musl64;
            enableStatic = true;
          };
          static-i686-unknown-linux-musl = crossPackage {
            crossPkgs = pkgs.pkgsCross.musl32;
            enableStatic = true;
          };
          static-aarch64-unknown-linux-musl = crossPackage {
            crossPkgs = pkgs.pkgsCross.aarch64-multiplatform-musl;
            enableStatic = true;
          };

          ipv6-static-x86_64-unknown-linux-musl = crossPackage {
            crossPkgs = pkgs.pkgsCross.musl64;
            enableStatic = true;
            features = [ "ipv6" ];
          };
          ipv6-static-i686-unknown-linux-musl = crossPackage {
            crossPkgs = pkgs.pkgsCross.musl32;
            enableStatic = true;
            features = [ "ipv6" ];
          };
          ipv6-static-aarch64-unknown-linux-musl = crossPackage {
            crossPkgs = pkgs.pkgsCross.aarch64-multiplatform-musl;
            enableStatic = true;
            features = [ "ipv6" ];
          };
        };
      }
    );
}
