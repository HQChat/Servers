# hqchat server

The server half of [hqchat](https://github.com/MartinRougeron2/HQCAT), an
end-to-end encrypted messenger with a post-quantum handshake.

It is not a relay in the usual sense: **it never sees a message.** It proves that
a client holds a private key, decides who may publish to which topic, and lets
EMQX fan out ciphertext it has no key for. The interesting code is all in the
first two of those.

Licensed **AGPL-3.0** ([LICENSE](./LICENSE)).

## Services

One image, several entrypoints. All of them run on one VM today.

| Service | Entrypoint | Owns |
|---|---|---|
| **auth** | `auth/main.ts` | the HQC-KEM handshake, session + MQTT tokens, admission, and the EMQX authn hook |
| **app-api** | `api/main.ts` | directory, friend graph (which writes the broker's topic ACL), push tokens, account deletion, payments |
| **push-bridge** | `push/main.ts` | subscribes to every conversation, sends a content-free APNs wake to offline members |
| **broker-watch** | `ops/broker-watch.ts` | polls EMQX and database health, escalates transitions to Sentry; runs the expiry sweeper |
| **helper bot** | `bot/bot.ts` | the account every new user starts with, and the onboarding: it greets each one once, on an encrypted channel like any other. An ordinary MQTT client, no special privileges — see [bot/README.md](bot/README.md) |

Plus **EMQX** (messaging, per-topic ACL, offline sessions), which is a pulled
image, and **Postgres** (tokens, ACL, friend graph, directory, sessions, rate
limits) — a DigitalOcean managed cluster in production, a container on its own
droplet in pre-prod, described in [`infra/database`](../../infra/database/README.md).
Neither runs from this repo.

`legacy/` is the retired single-WebSocket monolith. It does not run; it is kept
for its end-to-end tests. See [legacy/README.md](legacy/README.md).

## Running it

```bash
npm ci
npm run typecheck && npm test

# The whole stack. The `local` overlay adds a throwaway postgres container;
# generate.sh writes the credentials for it. Production points at a managed
# cluster instead.
sh ../../infra/deploy/local-secrets/generate.sh
docker compose -f ../../infra/deploy/docker-compose.yml \
               -f ../../infra/deploy/docker-compose.local.yml up -d
```

Individual services: `npm run auth`, `npm run api`, `npm run push`,
`npm run bot`, `npm run broker-watch`. Each needs `DATABASE_URL` pointing at a
migrated database (`npm run migrate`); `auth` and the bot also need the native
HQC library (see below).

The unit suite skips its database-backed tests when there is nothing to connect
to, so `npm test` passes on a bare checkout — see `test/pg-helper.ts`.

Configuration is environment variables — see
[`.env.example`](../../infra/deploy/.env.example). There are no defaults pointing
at anyone's deployment: unset means unset, and the services say so at startup.

## The native HQC library

`lib/hqc.ts` dlopens a native shared library built from the HQC reference
implementation (`lib/libhqc_x86.so`, linux/x86_64, glibc — which is why the
Docker image is Debian-based and not Alpine). The wrapper's source lives in the
monorepo under `native/hqc/`.

## How it fits together

- [Authentication](../../docs/architecture/auth-flow.md) — the handshake, and why there are two tokens
- [Messaging](../../docs/architecture/message-flow.md) — one message end to end, and what each hop can see
- [The topic ACL](../../docs/architecture/emqx-acl.md) — the only thing between a stranger and a conversation
- [Deployment](../../docs/architecture/overview.md) — how an image reaches a host, and why nothing in CI can reach one

## Where this code lives

The server is developed in a private monorepo alongside the Apple clients, and
published — with `infra/` and the runbooks, so it can be deployed and not just
read — to [HQChat-Server](https://github.com/MartinRougeron2/HQChat-Server).

Issues and pull requests are welcome there. A PR is applied to the monorepo by
hand and returns on the next sync, so nothing is lost, but the commit that lands
publicly will not be the one you wrote.

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md), and
[the root policy](../../SECURITY.md) for scope and what counts as serious.
