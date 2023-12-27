{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, flake-utils, naersk, nixpkgs }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = (import nixpkgs) {
          inherit system;
        };

        naersk' = pkgs.callPackage naersk { };

        deps = with pkgs; [
          clang
          elfutils
          pkg-config
          # required by `libbpf_cargo::SkeletonBuilder`
          rustfmt
          zlib
        ];
      in
      {
        # For `nix build` & `nix run`:
        packages.default = naersk'.buildPackage {
          src = ./.;
          nativeBuildInputs = deps;
        };

        packages.static = naersk'.buildPackage {
          src = ./.;
          nativeBuildInputs = deps ++ (with pkgs.pkgsStatic; [
            elfutils # TODO: broken, build a static libelf ourself
            zlib
          ]);
          cargoBuildOptions = default: default ++ [ "--features static" ];
        };

        # For `nix develop`:
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = deps ++ (with pkgs; [ rustc cargo ]);
        };
      }
    );
}
