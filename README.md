# game-server-runner

A small web service that runs one game server process per instance. It
exposes status and logs over HTTP and websockets, stops the server after it
has been empty for a while, and tracks online players by reading the
server's own log output. Minecraft is just a config entry, there is no
Minecraft code path.

This is a Rust rewrite of mc-runner, learning project first. See REWRITE.md
for the design decisions.

## Quick start

```console
$ nix run
```

Or build and run the binary from `result/bin`. The working directory must
contain a `config.toml` (see below), and the configured server directory
needs a `server.toml`.

On first start the runner creates its database, makes user 0 the admin, and
prints the admin invitation token to stderr:

```text
admin invitation token: AbCdEf...
```

Open the web UI, register with that token to become the admin, then use the
admin invite endpoint to invite friends. Invites are links with a token that
expires after 3 days.

## Global config

`config.toml`, in the working directory or wherever `CONFIG_PATH` points.
Every field has a default, so an empty file is valid:

```toml
db_path = "game-server-runner.db" # SQLite file, created if missing
port = 4479                       # HTTP listen port
connect_url = "localhost:25565"   # address shown to players
server_dir = "."                  # where the game server lives, holds server.toml
minutes_before_stop = 1           # stop the server after this many empty minutes
log_level = "info"                # debug, info, warn, error/err, disabled

restic_enable = false             # run a restic backup after a clean exit
restic_path = "restic"            # restic binary
restic_repo = ""                  # restic repository

[telegram]
token = ""                        # bot token; empty disables notifications
chat_ids = ""                     # semicolon separated chat ids, e.g. "1;2;3"
```

## Per-server config

`server.toml` lives in `server_dir`:

```toml
server_name = "myserver"
command = "java21"
args = ["-Xmx4G", "-jar", "paper.jar", "nogui"]

[players]
join_regex  = '^(?P<player>\S+) joined the game'
leave_regex = '^(?P<player>\S+) left the game'

[stop]
mode = "signal"       # "signal" or "stdin"
payload = "SIGTERM"   # signal name, or a stdin line
grace_period = "10s"  # accepts ns/us/ms/s, e.g. "0.5s" or "250ms"
```

Stop rules:

- With no `[stop]` table: signal mode, SIGTERM. What docker stop and systemd
  send anyway.
- Signal payloads are case-insensitive with an optional `SIG` prefix
  (`TERM`, `sigterm`, `SigTerm` all work). The whitelist is TERM, INT, HUP,
  QUIT. SIGKILL and SIGSTOP are rejected at startup because they cannot be
  caught, so they make no sense as a graceful stop.
- `stdin` mode writes `payload` to the server's stdin, appending `\n` if
  missing, so `payload = "stop"` sends the line `stop`. Stdin mode without a
  payload is a config error.
- Escalation is uniform: graceful action, wait `grace_period`, then SIGKILL.
  No intermediate SIGINT.

## Player tracking

The join and leave regexes must each contain a `(?P<player>...)` named
group; the captured value is the online player. They are compiled at
startup with a clear error for bad patterns. The defaults above are shaped
after vanilla/Paper console output like
`[12:34:56] [Server thread/INFO]: alice joined the game`.

The `regex` crate supports no lookarounds or backreferences. That is a
documented limitation, not something fancy-regex will fix.

## Auth

No passwords. The admin creates invite links that register a user (3 day
expiry). Each device gets its own session, and every authenticated request
rotates the session token and slides the 30 day expiry forward, so active
users are never signed out and losing one device does not sign out the
others. A logged-in user can mint a one-hour one-shot login token to sign in
another device. Users stale past the 30 days ask the admin for a new invite,
which claims onto their existing account. 401 responses bounce the frontend
to the login screen. The admin is user id 0.

## Crash policy

Manual restart only. When the game server process exits the state flips to
stopped, and a human or an API call starts it again. No auto-restart.

## Development

Enter the shell with `direnv allow` or `nix develop`. It contains cargo,
rustc, clippy, rustfmt, rust-analyzer, sqlx-cli, nodejs, pnpm and
sqlitebrowser.

Frontend work:

```console
$ cd frontend
$ pnpm dev
```

`pnpm dev` proxies `/api` (including websockets) to the backend at
`localhost:$PORT`, falling back to 4479.

Rust work:

- `cargo build` works without a frontend build and serves a placeholder
  page. `cargo build --features embed-frontend` needs `pnpm build` in
  `frontend/` first, because rust-embed reads `frontend/dist` at compile
  time. The nix build always does both.
- sqlx queries are compile-time checked against the committed `.sqlx`
  offline cache, so no live database is needed to build. After changing a
  query, regenerate the cache with `cargo sqlx prepare`.
- `cargo test` runs everything, including integration tests that spawn fake
  game server scripts and drive start, join, leave, auto-stop and stop
  through the real binary.
