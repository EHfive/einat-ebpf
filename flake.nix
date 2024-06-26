{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    systems.url = "github:nix-systems/default-linux";
    flake-utils = {
      url = "github:numtide/flake-utils";
      inputs.systems.follows = "systems";
    };
    fenix = {
      # nightly update in https://github.com/nix-community/fenix/commit/49b387d269e31271666c01d42a2763f87bbe62b1
      # breaks native library linking to nix store,
      # see https://github.com/rust-lang/rust/issues/125321
      # use last working version
      url = "github:nix-community/fenix/a2d19ef9305841f26c8ab908b1c09a84ca307e18";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, fenix, naersk, ... }:
    let
      defaultPackage' = pkgs: pkgs.callPackage ./nix/package.nix {
        naersk = pkgs.callPackage naersk { };
      };
      crossPackage' = import ./nix/cross-package.nix { inherit fenix naersk; };

      overlay = final: prev: {
        einat = defaultPackage' {
          pkgs = (import nixpkgs) { inherit (prev) system; };
        };
      };

      module = {
        imports = [
          (import ./nix/module.nix)
          {
            nixpkgs.overlays = [ overlay ];
          }
        ];
      };
    in
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = (import nixpkgs) {
            inherit system;
          };

          defaultPackage = defaultPackage' pkgs;
          crossPackage = { ... }@args: crossPackage' ({ inherit pkgs; } // args);
        in
        {
          packages = {
            default = defaultPackage;
            ipv6 = defaultPackage;

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
              enableIpv6 = true;
            };
            ipv6-static-i686-unknown-linux-musl = crossPackage {
              crossPkgs = pkgs.pkgsCross.musl32;
              enableStatic = true;
              enableIpv6 = true;
            };
            ipv6-static-aarch64-unknown-linux-musl = crossPackage {
              crossPkgs = pkgs.pkgsCross.aarch64-multiplatform-musl;
              enableStatic = true;
              enableIpv6 = true;
            };
          };
        }
      ) // {
      overlays.default = overlay;
      nixosModules.default = module;
    };
}
