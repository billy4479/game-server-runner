# game-server-runner

Plan for the Rust rewrite of mc-runner. Everything below was decided in the
grilling session of Sep 2026; research notes with sources are at the bottom.

## Why

Learning project first, cleaner design second. mc-runner works and stays in
production until this one earns the switch, so there is no deadline and no
reason to cut corners on the foundations. Scope is full feature parity,
eventually: process lifecycle, websocket state/log feed, auto-stop, auth,
frontend, telegram notifications, restic backups.

What this program is: a small web service that runs one game server process
per instance, exposes status over HTTP and websockets, stops the server when
it has been empty for a while, and knows who is online by reading the
server's log output. Minecraft is just a config entry, not a code path.

What gets dropped from mc-runner: the java version shorthand (`java8`..
`java25` config and `getJavaExe`), the hardcoded vanilla log parser, the
`/api/hooks/mc` stub, `nix/docker.nix` and `mc-java` (deployment method has
changed), and the single-refresh-token-per-user auth wart.

## Decisions

- New repo at `/workspace/code/game-server-runner`, name `game-server-runner`.
- Rust, stable toolchain, edition 2024, Linux only.
- Single server per instance, same model as mc-runner.
- Tokio + axum, websockets from axum itself.
- SQLite through sqlx, queries written with `query!`/`query_as!` macros so the
  schema checks them at compile time. The `.sqlx` offline cache makes nix and
  CI builds work without a live database.
- TOML config, both global and per-server. serde_yaml is archived upstream,
  which forced the format question; TOML won over YAML forks and KDL.
- Svelte frontend copied from mc-runner and adjusted where the API differs.
  REST and WS message shapes stay as they are, warts included, like the
  `"start"` text message on the websocket.
- Fresh database schema, no data migration. Users get re-invited.
- Crash policy: manual restart only. The process exits, state flips to
  stopped, a human or the API starts it again.
- Single crate with modules, not a workspace.

## Runner semantics

Global `config.toml` mirrors mc-runner minus the java paths: db path, port,
connect url, server dir, minutes before stop, telegram and restic settings.

Per-server `server.toml` lives in the server dir:

```toml
server_name = "myserver"
command = "java21"
args = ["-Xmx4G", "-jar", "paper.jar", "nogui"]

[players]
# optional, these are the defaults shaped after the vanilla log format,
# to be verified against real logs during M1
join_regex  = '^(?P<player>\S+) joined the game'
leave_regex = '^(?P<player>\S+) left the game'

[stop]
mode = "signal"       # "signal" or "stdin"
payload = "SIGTERM"   # signal name, or a stdin line
grace_period = "10s"
```

Stop behavior:

- Defaults when `[stop]` is absent: signal mode, SIGTERM. Matches what
  docker stop and systemd send anyway.
- Signal payloads are parsed case-insensitively, `TERM` and `SIGTERM` both
  accepted, validated against TERM, INT, HUP, QUIT. SIGKILL and SIGSTOP are
  rejected with a clear error: they cannot be caught, so they do not belong
  in the graceful slot.
- Stdin payload gets a `\n` appended if missing.
- Escalation is uniform: graceful action, wait `grace_period`, SIGKILL.
  No intermediate SIGINT, the JVM treats INT and TERM identically, so it
  adds nothing.

Player tracking: the join and leave regexes need a `(?P<player>...)` named
group, compiled at startup with a clear error on invalid patterns. The
`regex` crate does not support lookarounds or backreferences; documented in
the README rather than pulling in fancy-regex.

Auto-stop after `minutes_before_stop` with zero players, restic backup after
a clean exit, telegram messages on start, stop, join and leave. All carried
over from mc-runner unchanged in behavior.

## Auth

The no-password invite flow stays, with sessions made less sloppy:

- `sessions` table, one row per device. The old design stored a single
  refresh token per user, so logging in on a phone signed out the desktop.
- Each authenticated request rotates the session token and slides the
  expiry forward in the same write. Expiry is 30 days of inactivity, so
  active users never see a sign-out.
- `add-device` endpoint carried over: a logged-in user mints a one-time,
  short-expiry login token for another device.
- A user stale past the expiry asks the admin for a new invite link, which
  claims onto the existing username instead of creating a new user.
- 401 responses bounce the frontend back to the login screen.

## Storage

```sql
users    (id, name)
sessions (token_hash, user_id, expires, ...)
tokens   (token_hash, kind, expires, user_id)  -- invitation, login
```

Sketch, exact shape lands in M2. Hashed tokens, indexed expiry lookups,
single writer. redb, sled, fjall and native_db were considered and rejected,
see research notes.

## Repo and nix

- flake with `rustPlatform.buildRustPackage`, frontend built with pnpm and
  embedded via rust-embed.
- direnv devshell: rust-analyzer, clippy, rustfmt, sqlx-cli, node, pnpm,
  sqlite browser.
- Tests: table-driven unit tests for the regex tracker and stop config
  parsing, plus an integration test that spawns a fake game server script
  and drives start, join, leave, autostop and stop through the real binary.

## Build order

1. M1, core: config parsing, process lifecycle, pipes and log buffer,
   websocket feed, player regexes, stop mode/payload/grace, auto-stop.
   A working headless runner.
2. M2, auth: schema, invite flow, sessions with rotation and sliding expiry,
   add-device, admin endpoints.
3. M3, frontend: copy the Svelte app, adjust the API client, rebrand.
4. M4, extras: telegram notifications, restic backup hook.

## Research notes

Signal handling, which decided the stop design:

- HotSpot installs handlers for SIGINT and SIGTERM that run shutdown hooks,
  then exit. See the OpenJ9 regression report where this broke:
  github.com/eclipse-openj9/openj9/issues/2571
- Vanilla: `DedicatedServer` registers a "Server Shutdown Thread" hook that
  calls `halt(true)`; `/stop` calls `halt(false)`. Same save path. Analysis
  of decompiled 1.17.1: blog.kuiper.dev/minecraft-server-sigterm-sigint
- Paper: signals save the world but, unlike `/stop`, do not run plugin
  `onDisable` (issue #5270). The fix attempt PR #5592 dropped its signal
  listener over `sun.misc.Signal` concerns and merged only a logging fix,
  in 1.19. Paper 1.15.2 had it worse, see issue #3062.
- Spigot: SPIGOT-5219, open since 2019, reports SIGTERM shutdown without
  chunk saving.
- Fabric: no dedicated signal handling exists; it runs the vanilla
  DedicatedServer, so it inherits the vanilla hook path. Modded servers add
  the caveat that mods may misbehave inside hooks, which is why mods like
  signal-catcher exist.
- Conclusion: SIGTERM is the default, stdin `/stop` remains the only path
  that runs plugin shutdown on Paper, and `mode = "stdin"` exists for anyone
  who cares about that.

Storage, which decided sqlx over sqlc:

- sqlc's only Rust generator, sqlc-gen-sqlx, is PostgreSQL-only. SQLite is
  listed as N/A in the official language support table and the plugin README
  confirms it: all types and executor impls are Postgres. No sqlc path to
  SQLite exists, so the compile-time-checked SQL experience comes from
  sqlx's own macros instead.
- sqlx moved from LaunchBadge to the transact-rs collective; current at 0.9.
  Behavior change to configure around: it no longer sets journal_mode by
  default, so connect options should explicitly enable WAL.
- rusqlite 0.40 remains the fallback if the macro build friction annoys.
- redb is healthy but has no expiry or secondary indexes, which token auth
  needs; sled is stalled on a 2024 alpha; fjall is an LSM engine built for
  write-heavy loads; native_db has bus-factor problems.
