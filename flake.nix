{
  description = "Husk flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      utils,
    }:
    utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        version = "0.1.0";
        web = pkgs.buildNpmPackage {
          pname = "husk-web";
          inherit version;
          src = ./web;
          npmDepsFetcherVersion = 2;
          npmDepsHash = "sha256-GXrJr6m3BAnrw31QPkHsqe+EHApfjbCB6JhaIm2ctAg=";

          installPhase = ''
            mkdir -p $out
            cp -r dist $out/
          '';
        };
        package = {
          pname = "husk";
          inherit version;
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          doCheck = false;
        };
      in
      {
        packages = rec {
          husk = pkgs.rustPlatform.buildRustPackage (
            package
            // {
              postPatch = ''
                mkdir -p web/dist
                cp -r ${web}/dist/. web/dist/
              '';
            }
          );
          husk-tui = pkgs.rustPlatform.buildRustPackage (
            package
            // {
              pname = "husk-tui";
              # Drops the web UI, and with it the Node dependency.
              buildNoDefaultFeatures = true;
            }
          );
          default = husk;
        };

        apps = rec {
          husk = {
            type = "app";
            program = "${self.packages.${system}.husk}/bin/husk";
          };
          husk-tui = {
            type = "app";
            program = "${self.packages.${system}.husk-tui}/bin/husk";
          };
          default = husk;
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            clippy
            nodejs_24
            rustc
            rustfmt

            # The guide's git-client control reads the ambient git version, so
            # the shell supplies its own: a distribution git that backports
            # security fixes without moving the version number reads as
            # vulnerable.
            git

            # The hygiene tools CI runs, so a local run matches it.
            cargo-nextest
            cargo-deny
            cargo-machete
            typos
            taplo
            nixfmt
          ];

          HUSK_DEV_SHELL = "1";
        };
      }
    );
}
