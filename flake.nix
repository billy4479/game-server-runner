{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        frontend = pkgs.callPackage ./frontend/package.nix {
          version = (pkgs.lib.importTOML ./Cargo.toml).package.version;
        };
        app = pkgs.callPackage ./package.nix { inherit frontend; };
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
