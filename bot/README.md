# The helper bot

`@helper` is the account every new user starts with. It is an ordinary protocol
client — HQC auth, the v2 prekey handshake, and the KEM double ratchet — so
its replies are end-to-end encrypted exactly like anyone else's and the server
can no more read them than it can read yours.

**It is not optional decoration.** A new account with an empty friend list opens
to an empty screen, and nothing in the app explains how a conversation starts.
The bot greets each user once, moments after first login, and that greeting is
where people learn that messages are encrypted, that `/help` exists, and that
typing into the box works. A deployment without it works and feels broken.

Runs on the server (it needs the Linux HQC library), as the `bot` service in
[`docker-compose.yml`](../../../infra/deploy/docker-compose.yml), from its own
image ([`Dockerfile.bot`](../Dockerfile.bot)) — same base and native library as
the server, minus the entrypoints and packages it never imports.

## Running it

Nothing to prepare. Bring it up with the rest of the stack:

```bash
docker compose -f infra/deploy/docker-compose.yml up -d
```

On first start it generates a 32-byte seed, derives its keypair, writes its own
public key into the `admission_exempt` table, claims the reserved handle, and
connects. **Self-admission is why there is no setup step here:** the bot writes
that row itself, before authenticating, so nothing has to be copied out of a log
into a config file and nothing breaks when its identity changes. If you find an
`EXEMPT_PUBLIC_KEYS` instruction anywhere, it predates that and is wrong.

Locally, outside Docker:

```bash
cd services/server && npm run bot     # needs DATABASE_URL and a migrated database
```

## Identity, and where it lives

The seed is written to `$BOT_STATE_DIR/.bot-seed` (mode 0600) and reused on every
later start, so the bot keeps one public key across restarts and its friends keep
their channels. Per-friend keys and ratchet state sit beside it in
`.bot-state.json`. Both are secrets; both are gitignored.

In Docker `BOT_STATE_DIR` is `/app/bot-state`, a named volume, and that path is
load-bearing: it is deliberately **not** `/app/bot`. A volume mounted over the
code directory shadows `bot.ts` with whatever copy the volume was created with,
which freezes the container on old code through every subsequent upgrade — a
whole afternoon went into learning that once.

For a fixed identity across hosts, set `BOT_SEED` (hex) or `BOT_SEED_FILE`
pointing at a Docker secret; the compose file has the line commented out.

## What it does

Add `helper` (or your `BOT_USERNAME`) as a friend in the app. Once the secure
channel is up:

| Message | Reply |
|---|---|
| *(first contact)* | a one-time welcome — who it is, that the chat is end-to-end encrypted, and to try `/help` |
| `/help` | what it can do |
| `/game prc` | rock-paper-scissors |
| `/game guess <number>` | number guessing, 1 to 10 |
| `/support` | the address in `SUPPORT_EMAIL` |
| anything containing "hello" | a greeting |
| anything else | echoes it back |

The welcome is sent exactly once per user, recorded in the persisted state, and
only after the secure channel exists — there is no unencrypted path it could go
out on.

## Environment

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` / `DATABASE_URL_FILE` | — | required: self-admission writes to `admission_exempt` |
| `AUTH_BASE_URL` | `http://auth:8080` | REST, in-cluster — not through nginx |
| `API_BASE_URL` | `http://app-api:8080` | |
| `EMQX_URL` | `ws://emqx:8083/mqtt` | conversations go over MQTT |
| `BOT_USERNAME` | `helper` | the handle users add |
| `BOT_STATE_DIR` | the bot's own directory | `/app/bot-state` in Docker; see above |
| `BOT_SEED` / `BOT_SEED_FILE` | generated on first run | hex; pins the identity |
| `SUPPORT_EMAIL` | `support@example.com` | what `/support` answers |
| `FRIEND_POLL_MS` | `15000` | how often it looks for new friends |
