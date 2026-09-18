// MQTT 5 persistent sessions need BOTH halves.
//
// `clean: false` says "resume a session if one exists". On MQTT 3.1.1 that is
// the whole story. On MQTT 5 the session's lifetime is `sessionExpiryInterval`,
// and its default is ZERO — the session ends the instant the connection does,
// taking every queued message with it.
//
// The bot connected with `protocolVersion: 5` and `clean: false` and nothing
// else, under a comment promising "this IS the offline queue. Messages
// published to our conversations while the bot is restarting are held by the
// broker and delivered on reconnect". They were not. They were dropped, with no
// error anywhere — the shape of "the bot missed something while it was down".
//
// The apps are unaffected: they speak 3.1.1, where the original comment is true.
// That asymmetry is exactly why a source-level check earns its place — the bug
// is invisible in isolation and only shows up against a live broker, in the e2e
// suite, which is opt-in on PRs.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/** Every file in this repo that opens an MQTT connection. */
const CONNECTORS = [
  ["bot", join(__dirname, "..", "bot", "bot.ts")],
  ["e2e harness", join(__dirname, "helpers", "mqtt-client.ts")],
] as const;

test("an MQTT 5 client that asks for a persistent session sets its expiry", () => {
  for (const [name, path] of CONNECTORS) {
    const src = readFileSync(path, "utf8");
    if (!/protocolVersion:\s*5/.test(src)) continue;      // 3.1.1 needs no expiry
    if (!/clean:\s*false/.test(src)) continue;            // not asking to persist

    assert.match(
      src, /sessionExpiryInterval/,
      `${name} connects with MQTT 5 and clean:false but never sets ` +
      `sessionExpiryInterval — its session, and everything queued for it, dies ` +
      `with the socket`
    );
  }
});

test("the expiry is a real duration, not zero", () => {
  // Setting it to 0 is the same as not setting it, and would read as if the
  // question had been considered.
  for (const [name, path] of CONNECTORS) {
    const src = readFileSync(path, "utf8");
    const m = src.match(/sessionExpiryInterval:\s*([^,\n}]+)/);
    if (!m) continue;
    const expr = (m[1] ?? "").trim();
    const literal = Number(expr);
    if (Number.isFinite(literal)) {
      assert.ok(literal > 0, `${name}: sessionExpiryInterval must be > 0, got ${expr}`);
    } else {
      // An env-var expression: check the fallback it defaults to is non-zero,
      // since an unset variable is the common case.
      assert.match(expr, /\|\|\s*[1-9]/,
        `${name}: the sessionExpiryInterval fallback must be non-zero, got ${expr}`);
    }
  }
});
