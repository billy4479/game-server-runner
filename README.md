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

There is no bootstrap token. Log in as the admin through the OIDC provider
(tailnet only, see Auth below): the first identity whose username matches
`ADMIN_USERNAME` becomes user 0. Friends need no tailnet: they log in with
Telegram, land in the approval queue, and the admin approves them in the web
UI's admin panel.

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
token = ""                        # bot token; empty disables notifications AND telegram login
username = ""                     # bot username without @; needed for the login widget
chat_ids = ""                     # semicolon separated chat ids, e.g. "1;2;3"
```

### OIDC admin login (environment)

The admin account is a single tsidp identity, selected through the
environment (rendered from sops in deployment, same shape as ff):

```text
OIDC_ISSUER=https://idp.internal.polpetta.online
OIDC_CLIENT_ID=game-server-runner
OIDC_CLIENT_SECRET=...
ADMIN_USERNAME=jack
```

All four must be set together, or admin login stays disabled; any partial
subset refuses the startup (fail closed).

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

## Java flags

Minecraft pins the Java version: 1.12 to 1.16.5 runs on Java 8, 1.17 on
16, 1.18 to 1.20.4 on 17, 1.20.5 to 26.0 on 21, and 26.1 and newer on 25.
Whatever set you pick, give `-Xms` and `-Xmx` the same value and leave
1-1.5 GB of RAM outside the heap for the JVM itself.

- [Aikar's flags](https://docs.papermc.io/paper/aikars-flags/) with G1GC
  are still the standard recommendation and work on every Java version
  above. Use them as published: they need
  `-XX:+UnlockExperimentalVMOptions` to unlock the G1 tuning knobs. That
  flag is not needed for ZGC.
- Generational ZGC is the low-pause alternative, at the cost of more RAM
  and CPU cores, so it pays off on 6-8 GB heaps and 4+ cores. On Java 21
  and 22 enable it with `-XX:+UseZGC -XX:+ZGenerational`; plain `-XX:+UseZGC`
  there gives the old non-generational collector, which is worse than G1
  here. On Java 23 and newer `-XX:+UseZGC` alone is already generational.
  Don't mix in the Aikar/G1 flags, they do nothing for ZGC.

ZGC extras worth adding: `-XX:+AlwaysPreTouch`, `-XX:+UseStringDeduplication`
on Java 18+, `-XX:TrimNativeHeapInterval=5000` on Linux with glibc, and
`-XX:+UseCompactObjectHeaders` on Java 25+.

## Player tracking

The join and leave regexes must each contain a `(?P<player>...)` named
group; the captured value is the online player. They are compiled at
startup with a clear error for bad patterns. The defaults above are shaped
after vanilla/Paper console output like
`[12:34:56] [Server thread/INFO]: alice joined the game`.

The `regex` crate supports no lookarounds or backreferences. That is a
documented limitation, not something fancy-regex will fix.

## Auth

Two login paths, one session mechanism.

**Admin: OIDC against tsidp, ff-style.** Hand-rolled authorization code +
PKCE S256, `client_secret_post` at the token endpoint, identity claims read
from `/userinfo` with the opaque access token (the ID token is never
parsed). The only accepted identity is the one whose `username` claim equals
`ADMIN_USERNAME` — authorization is enforced by the app, not the provider.
The matching identity claims user 0; admin rights are structural (`id ==
0`), so the username check runs only at login. In-flight logins are tracked
server-side: a state token rides in a short-lived cookie, its hash in the
database next to the PKCE verifier and the in-site return path, deleted on
first use. This path only works from the tailnet, like every tsidp relying
party.

The admin surface is hidden from everyone else. The login page shows only
the Telegram widget; the admin console lives at `/admin`. An
unauthenticated browser there goes straight into the SSO flow and lands
back on `/admin` once authenticated (bookmark that address for the first
login). A browser that completed an admin login once keeps a `was_admin`
cookie: from then on the plain login page auto-redirects it into the
provider with no login screen at all. Logging out and a failed redirect
(`?sso=skip`) both clear the flow, so logout logs out. Regular users see
none of this; the console's only admin affordance for them is that an
un-invited `/admin` visit ends in the provider's consent screen or a
refusal, never in admin powers.

**Friends: Telegram login with an approval queue.** The login page embeds
the Telegram Login Widget (bot username from `[telegram] username`); the
widget hands the page a signed payload which the runner verifies against the
bot token (HMAC-SHA256 keyed with SHA-256 of the token, payload freshness
bounded to 5 minutes). Known accounts get a session. Unknown accounts are
queued as registration requests and the admin chat gets a notification; a
second request while queued is a conflict; unapproved requests are dropped
after an hour and can simply be queued again. The admin approves or denies
from the web UI. Bans are a flag plus an immediate session wipe; unbanned
accounts log back in without re-approval because the telegram binding
persists.

**Sessions**, unchanged in behavior: one row per device, every authenticated
request rotates the token and slides the 30-day expiry, so active users are
never signed out. 401 responses bounce the frontend to the login screen.
There are no passwords, no invite links, and no device tokens anywhere.

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
