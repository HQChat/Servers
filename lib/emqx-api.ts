// EMQX admin API transport, shared by lib/emqx.ts (kick / unsubscribe) and
// ops/broker-watch.ts (health checks).
//
// Two credentials, preferred in this order:
//
//   1. An API key: EMQX_API_KEY + EMQX_API_SECRET (or *_FILE, config.ts). EMQX
//      loads it from `api_key.bootstrap_file` at boot and accepts it as HTTP
//      Basic on every call, so there is no login, no token and nothing to
//      re-sync. This is the one to use when the broker lives on another host:
//      the key is a declarative file on both ends, not a dashboard password an
//      entrypoint has to push into the broker after it starts.
//
//   2. The dashboard admin: EMQX_DASHBOARD_USER + EMQX_DASHBOARD_PASSWORD, which
//      logs in once for a bearer token and logs in again once on a 401. Kept so
//      a stack that only provides the dashboard password keeps working.
//
// Env is read per call, not at import: a process started without a credential
// and given one later (a test, a reload) must not be stuck with the first read.

let token: string | null = null;

function base(): string {
  return `${process.env.EMQX_API_URL || "http://emqx:18083"}/api/v5`;
}

function apiKey(): { key: string; secret: string } | null {
  const key = process.env.EMQX_API_KEY || "";
  const secret = process.env.EMQX_API_SECRET || "";
  return key && secret ? { key, secret } : null;
}

/** True when either credential is configured. */
export function emqxApiConfigured(): boolean {
  return apiKey() !== null || (process.env.EMQX_DASHBOARD_PASSWORD || "").length > 0;
}

/** Drop the cached dashboard token. For tests: the 401 self-heal is a property
 *  of the transition from a stale token to a fresh one. */
export function resetEmqxApiToken(): void {
  token = null;
}

async function login(): Promise<string> {
  const res = await fetch(`${base()}/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      username: process.env.EMQX_DASHBOARD_USER || "admin",
      password: process.env.EMQX_DASHBOARD_PASSWORD || "",
    }),
    signal: AbortSignal.timeout(5000),
  });
  if (!res.ok) throw new Error(`login ${res.status}`);
  const body = (await res.json()) as { token?: string };
  if (!body.token) throw new Error("login returned no token");
  return body.token;
}

/**
 * One admin call. With an API key it is a single request. With the dashboard
 * credential it logs in when there is no token and re-authenticates ONCE on a
 * 401 — never in a loop, which against the broker's own dashboard would look
 * like credential stuffing.
 */
export async function emqxApi(method: string, path: string, body?: unknown, retry = true): Promise<Response> {
  const key = apiKey();
  let authorization: string;
  if (key) {
    authorization = `Basic ${Buffer.from(`${key.key}:${key.secret}`).toString("base64")}`;
  } else {
    if (!token) token = await login();
    authorization = `Bearer ${token}`;
  }
  const res = await fetch(`${base()}/${path}`, {
    method,
    headers: {
      authorization,
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(5000),
  });
  if (res.status === 401 && retry && !key) {
    token = null;
    return emqxApi(method, path, body, false);
  }
  return res;
}
