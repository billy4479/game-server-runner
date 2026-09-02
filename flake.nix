{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        version = "0.1.0";

        # Svelte app built with pnpm; the dist/ output is embedded into the
        # Rust binary via the `embed-frontend` feature.
        frontend = pkgs.stdenv.mkDerivation {
          pname = "game-server-runner-frontend";
          inherit version;
          src = ./frontend;

          nativeBuildInputs = with pkgs; [
            nodejs
            pnpm_11
            pnpmConfigHook
          ];
          pnpmDeps = pkgs.fetchPnpmDeps {
            pname = "game-server-runner-frontend";
            inherit version;
            src = ./frontend;
            pnpm = pkgs.pnpm_11;
            fetcherVersion = 4;
            hash = "sha256-0MoeH5eOSn698GMP5T13aiqc8LY2rRN083R10D/jPs0=";
          };

          buildPhase = ''
            runHook preBuild
            pnpm run build
            runHook postBuild
          '';

          installPhase = ''
            runHook preInstall
            mkdir -p $out
            cp -r dist/. $out/
            runHook postInstall
          '';
        };

        app = pkgs.rustPlatform.buildRustPackage {
          pname = "game-server-runner";
          inherit version;
          src = ./.;

          cargoLock.lockFile = ./Cargo.lock;
          buildFeatures = [ "embed-frontend" ];
          env.SQLX_OFFLINE = "true";

          preBuild = ''
            mkdir -p frontend/dist
            cp -r ${frontend}/. frontend/dist
          '';
        };
      in
      {
        packages = rec {
          inherit app frontend;
          default = app;
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rust-analyzer
            rustfmt
            clippy
            rustc
            sqlx-cli
            nodejs
            pnpm
            sqlitebrowser
          ];
        };
      }
    );
}
