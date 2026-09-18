import { describe, it } from "node:test";
import assert from "node:assert";
import { redact, scrubDeep, scrubEvent, scrubBreadcrumb } from "../lib/scrub";

describe("redact()", () => {
  it("redacts long hex public keys", () => {
    const pk = "a".repeat(64);
    assert.match(redact(`user pk ${pk} connected`), /user pk \[key\] connected/);
  });

  it("redacts base64 ciphertext blobs", () => {
    const blob = "Zm9v" + "A".repeat(60) + "==";
    const out = redact(`payload=${blob}`);
    assert.ok(!out.includes(blob), "blob should be gone");
    assert.ok(out.includes("[blob]") || out.includes("[redacted]"));
  });

  it("redacts @usernames but keeps surrounding text", () => {
    assert.strictEqual(redact("message from @alice_99 to bob"), "message from @[user] to bob");
    assert.strictEqual(redact("(@bob) hi"), "(@[user]) hi");
  });

  it("redacts IPv4 and IPv6 addresses", () => {
    assert.match(redact("client 203.0.113.7 joined"), /client \[ip\] joined/);
    assert.match(redact("from 2001:db8::ff00:42:8329 ok"), /from \[ip\] ok/);
  });

  it("redacts emails", () => {
    assert.strictEqual(redact("contact a.b+x@example.co.uk now"), "contact [email] now");
  });

  it("redacts JWTs and bearer tokens", () => {
    const jwt = "eyJhbGciOi.eyJzdWIiOiIx.SflKxwRJSM";
    assert.match(redact(`Authorization: Bearer ${jwt}`), /\[jwt\]|redacted/);
  });

  it("redacts Stripe secrets and key/value secrets", () => {
    assert.match(redact("using sk_live_abcdEFGH1234567890"), /\[stripe-key\]/);
    assert.match(redact('token=deadbeefcafebabe1234'), /token=\[redacted\]/i);
    assert.match(redact("password: hunter2secret"), /password=\[redacted\]/i);
  });

  // SYNC INVARIANT: the iOS scrubber (apple/.../Helpers/Observability.swift
  // `redactors`) must carry the same rule set. This case guards the standalone
  // Stripe webhook-signature rule that was previously missing on the iOS side.
  it("redacts a standalone Stripe webhook signature (t=…,v1=…)", () => {
    assert.strictEqual(
      redact("sig t=1700000000,v1=abcdef0123456789abcd rejected"),
      "sig [stripe-sig] rejected"
    );
  });

  it("redacts credentials embedded in a URL", () => {
    assert.strictEqual(
      redact("redis://:s3cr3tpw@cache.internal:6379 refused"),
      "redis://[redacted]@cache.internal:6379 refused"
    );
    assert.strictEqual(
      redact("connect postgres://admin:hunter2@db:5432/app"),
      "connect postgres://[redacted]@db:5432/app"
    );
    // The exact shape of DATABASE_URL in production: a pooler host, a port, a
    // database and an sslmode. This is the string most likely to end up in a
    // connection error on its way to Sentry.
    assert.strictEqual(
      redact("postgresql://app_prod:s3cr3t@private-hqcat-pg-do-user-1-0.b.db.ondigitalocean.com:25061/hqcat_prod?sslmode=verify-full"),
      "postgresql://[redacted]@private-hqcat-pg-do-user-1-0.b.db.ondigitalocean.com:25061/hqcat_prod?sslmode=verify-full"
    );
  });

  it("leaves credential-free URLs intact", () => {
    assert.strictEqual(redact("GET https://api.example.com/v1/x"), "GET https://api.example.com/v1/x");
  });

  it("is a no-op for non-strings and empty strings", () => {
    assert.strictEqual(redact(""), "");
    assert.strictEqual(redact(42 as any), 42 as any);
    assert.strictEqual(redact(null as any), null as any);
  });
});

describe("scrubDeep()", () => {
  it("redacts values of sensitive-named keys wholesale", () => {
    const out = scrubDeep({ publicKey: "not-even-hex", note: "hi @carol" }) as any;
    assert.strictEqual(out.publicKey, "[redacted]");
    assert.strictEqual(out.note, "hi @[user]");
  });

  it("matches sensitive keys by word, not substring", () => {
    const out = scrubDeep({
      tripped: ["rss high"], // contains "ip" — must NOT be redacted
      recipient: "bob", // contains "ip" — must NOT be redacted
      description: "x", // contains "sig" — must NOT be redacted
      ipAddress: "10.0.0.1", // IS sensitive
      publicKeyBytes: 32, // glued phrase "publickey" — IS sensitive
      ip: "1.2.3.4", // IS sensitive
    }) as any;
    assert.deepStrictEqual(out.tripped, ["rss high"]);
    assert.strictEqual(out.recipient, "bob");
    assert.strictEqual(out.description, "x");
    assert.strictEqual(out.ipAddress, "[redacted]");
    assert.strictEqual(out.publicKeyBytes, "[redacted]");
    assert.strictEqual(out.ip, "[redacted]");
  });

  it("walks arrays and nested objects", () => {
    const out = scrubDeep({ list: [{ ip: "10.0.0.1" }, "email me@x.com"] }) as any;
    assert.strictEqual(out.list[0].ip, "[redacted]");
    assert.strictEqual(out.list[1], "email [email]");
  });

  it("bounds recursion depth", () => {
    let deep: any = "leaf";
    for (let i = 0; i < 20; i++) deep = { n: deep };
    // Should not throw and should terminate.
    assert.doesNotThrow(() => scrubDeep(deep));
  });
});

describe("scrubEvent()", () => {
  it("drops request, hostname and user network identifiers", () => {
    const ev = scrubEvent({
      request: { headers: { authorization: "Bearer x" }, cookies: "s=1" },
      server_name: "relay-prod-3",
      user: { id: "opaque", ip_address: "203.0.113.9", email: "a@b.com", username: "alice" },
    });
    assert.strictEqual(ev.request, undefined);
    assert.strictEqual(ev.server_name, undefined);
    assert.strictEqual(ev.user.ip_address, undefined);
    assert.strictEqual(ev.user.email, undefined);
    assert.strictEqual(ev.user.username, undefined);
    assert.strictEqual(ev.user.id, "opaque", "opaque id preserved");
  });

  it("redacts exception values and message", () => {
    const ev = scrubEvent({
      message: "auth failed for @dave from 198.51.100.4",
      exception: { values: [{ value: "bad key " + "f".repeat(40) }] },
    });
    assert.ok(!ev.message.includes("@dave"));
    assert.ok(!ev.message.includes("198.51.100.4"));
    assert.match(ev.exception.values[0].value, /\[key\]/);
  });

  it("scrubs breadcrumbs and contexts", () => {
    const ev = scrubEvent({
      breadcrumbs: { values: [{ message: "sent to @erin" }] },
      contexts: { health: { note: "peer 192.0.2.1" } },
    });
    assert.strictEqual(ev.breadcrumbs.values[0].message, "sent to @[user]");
    assert.strictEqual(ev.contexts.health.note, "peer [ip]");
  });
});

describe("scrubBreadcrumb()", () => {
  it("redacts message and data", () => {
    const c = scrubBreadcrumb({ message: "peer @zoe", data: { ip: "10.1.2.3" } });
    assert.strictEqual(c.message, "peer @[user]");
    assert.strictEqual(c.data.ip, "[redacted]");
  });
});

// A fuzz finding, pinned. The compressed-IPv6 rule made the colon after each hex
// group optional (`(?:[A-Fa-f0-9]{1,4}:?)*`), so a run of hex after "::" could be
// partitioned exponentially many ways. The trailing letter is load-bearing — it
// fails the closing word boundary and forces every partition to be tried. This
// input ran for over ten minutes before being killed, on both this engine and
// ICU. redact() runs on every Sentry message, breadcrumb and exception string,
// so an attacker-influenced value reaching a log line stalls the process.
//
// Found by test/fuzz/scrub-differential.ts, which reached it while comparing
// against the Swift twin. Mirrored in apps/apple/tests/RedactionTests.swift.
describe("ReDoS", () => {
  it("does not backtrack exponentially on the compressed-IPv6 rule", () => {
    const input = "fe80::1" + "a".repeat(64) + "token";
    const started = Date.now();
    redact(input);
    assert.ok(Date.now() - started < 1000, "redact() must not blow up on this input");
  });
});
