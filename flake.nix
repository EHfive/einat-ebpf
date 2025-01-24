{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    systems.url = "github:nix-systems/default-linux";
    flake-utils = {
      url = "github:numtide/flake-utils";
      inputs.systems.follows = "systems";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      rust-overlay,
      naersk,
      ...
    }:
    let
      defaultPackage' =
        pkgs:
        pkgs.callPackage ./nix/package.nix {
          naersk = pkgs.callPackage naersk { };
        };
      crossPackage' = import ./nix/cross-package.nix { inherit naersk; };

      overlay = final: prev: {
        einat = defaultPackage' prev;
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
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = (import nixpkgs) {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        defaultPackage = defaultPackage' (
          (import nixpkgs) {
            inherit system;
          }
        );
        crossPackage = { ... }@args: crossPackage' ({ inherit pkgs; } // args);
      in
      {
        legacyPackages = (import nixpkgs) {
          inherit system;
          overlays = [ overlay ];
        };

        packages = {
          default = defaultPackage;
          ipv6 = defaultPackage;

          verify_msrv_static-x86_64-unknown-linux-musl = crossPackage {
            crossPkgs = pkgs.pkgsCross.musl64;
            enableStatic = true;
            rustVersion = "1.80.0";
          };
          verify_msrv_static-aarch64-unknown-linux-musl = crossPackage {
            crossPkgs = pkgs.pkgsCross.aarch64-multiplatform-musl;
            enableStatic = true;
            rustVersion = "1.80.0";
          };

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

          ipv6_static-x86_64-unknown-linux-musl = crossPackage {
            crossPkgs = pkgs.pkgsCross.musl64;
            enableStatic = true;
            enableIpv6 = true;
          };
          ipv6_static-i686-unknown-linux-musl = crossPackage {
            crossPkgs = pkgs.pkgsCross.musl32;
            enableStatic = true;
            enableIpv6 = true;
          };
          ipv6_static-aarch64-unknown-linux-musl = crossPackage {
            crossPkgs = pkgs.pkgsCross.aarch64-multiplatform-musl;
            enableStatic = true;
            enableIpv6 = true;
          };
        };
      }
    )
    // {
      overlays.default = overlay;
      nixosModules.default = module;
    };
}
