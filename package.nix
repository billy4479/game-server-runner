{
  lib,
  rustPlatform,
  frontend,
}:

rustPlatform.buildRustPackage {
  pname = "game-server-runner";
  version = (lib.importTOML ./Cargo.toml).package.version;

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./Cargo.toml
      ./Cargo.lock
      ./src
      ./tests
      ./migrations
      ./.sqlx
    ];
  };

  cargoLock.lockFile = ./Cargo.lock;
  buildFeatures = [ "embed-frontend" ];
  env.SQLX_OFFLINE = "true";
  # Readiness checks are not latency benchmarks. Leave room for concurrent
  # Nix builds, and avoid spawning every integration-test server at once.
  env.GAME_SERVER_RUNNER_TEST_STARTUP_TIMEOUT_SECS = "120";
  dontUseCargoParallelTests = true;

  preBuild = # sh
    ''
      mkdir -p frontend/dist
      cp -R ${frontend}/. frontend/dist/
    '';

  meta = {
    description = "Game server management service with an embedded web interface";
    homepage = "https://github.com/billy4479/game-server-runner";
    mainProgram = "game-server-runner";
    platforms = lib.platforms.unix;
  };
}
