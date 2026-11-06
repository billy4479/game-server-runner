{
  lib,
  stdenvNoCC,
  nodejs,
  pnpm_11,
  pnpmConfigHook,
  fetchPnpmDeps,
  version,
}:

stdenvNoCC.mkDerivation (finalAttrs: {
  pname = "game-server-runner-frontend";
  inherit version;

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./src
      ./public
      ./index.html
      ./package.json
      ./pnpm-lock.yaml
      ./pnpm-workspace.yaml
      ./svelte.config.js
      ./tsconfig.json
      ./tsconfig.app.json
      ./tsconfig.node.json
      ./vite.config.ts
    ];
  };

  nativeBuildInputs = [
    nodejs
    pnpm_11
    pnpmConfigHook
  ];

  pnpmDeps = fetchPnpmDeps {
    inherit (finalAttrs) pname version src;
    pnpm = pnpm_11;
    fetcherVersion = 4;
    hash = "sha256-0MoeH5eOSn698GMP5T13aiqc8LY2rRN083R10D/jPs0=";
  };

  buildPhase = # sh
    ''
      runHook preBuild
      pnpm run build
      runHook postBuild
    '';

  installPhase = # sh
    ''
      runHook preInstall
      mkdir -p "$out"
      cp -R dist/. "$out/"
      runHook postInstall
    '';

  allowedReferences = [ ];
})
