// Sentry wiring and process-level crash capture.
//
// 64.2% covered before this file. Two different reasons to care about the rest:
//
//   THE CRASH HANDLERS ARE WHY THIS MODULE EXISTS. The server had no
//   `uncaughtException` listener, so an ECONNRESET storm during a flood
//   terminated Node — CPU and memory sat at 40% because it was never a resource
//   ceiling. Nothing tested that the handlers are installed, that they flush
//   before exiting, or that they still exit when the flush itself fails.
//
//   EVERY OPTION HERE IS A PRIVACY DECISION. `sendDefaultPii`, the four dropped
//   integrations and the two `beforeSend` hooks are what stop an E2EE relay
//   shipping request bodies, headers and captured locals off-box. They are
//   config, so they fail silently: a drifted option looks exactly like a correct
//   one until someone reads an event in Sentry.
//
// `@sentry/node` is stubbed — initialising the real SDK installs its own signal
// handlers and opens a transport. `lib/scrub.ts` is NOT stubbed: the point of
// asserting `beforeSend` is that it actually redacts, which a stub cannot show.

import { test } from "node:test";
import assert from "node:assert/strict";
import Module from "node:module";
import { logger, registerSentrySink, resetSentryThrottle, setLogLevel } from "../lib/logger";

setLogLevel("debug");

// --- the Sentry double -------------------------------------------------------------

interface SentryCalls {
  init: any[];
  breadcrumbs: any[];
  exceptions: Array<{ err: unknown; opts?: any }>;
  messages: Array<{ message: string; level?: string | undefined }>;
  flushes: number[];
}

let calls: SentryCalls;

/**
 * Flush and exit in the order they actually happened.
 *
 * Asserting that both occurred is not enough and I proved it: moving
 * `process.exit(1)` to BEFORE `flushThen` — which loses the crash event, the
 * whole point of the handler — passed every assertion in this file.
 */
let order: string[] = [];
let flushBehaviour: () => Promise<boolean> = async () => true;

function resetCalls() {
  calls = { init: [], breadcrumbs: [], exceptions: [], messages: [], flushes: [] };
  order = [];
  flushBehaviour = async () => true;
}
resetCalls();

const sentryStub = {
  init: (opts: any) => { calls.init.push(opts); },
  addBreadcrumb: (c: any) => { calls.breadcrumbs.push(c); },
  captureException: (err: unknown, opts?: any) => { calls.exceptions.push({ err, opts }); },
  captureMessage: (message: string, level?: string) => { calls.messages.push({ message, level }); },
  flush: async (ms: number) => { calls.flushes.push(ms); order.push("flush"); return flushBehaviour(); },
};

const sentryPath = require.resolve("@sentry/node");
{
  const m = new Module(sentryPath, module);
  m.filename = sentryPath;
  m.loaded = true;
  m.exports = sentryStub;
  require.cache[sentryPath] = m;
}

const obsPath = require.resolve("../lib/observability");
type Obs = typeof import("../lib/observability");

// --- running one initialisation in isolation -------------------------------------------

const SIGNALS = ["uncaughtException", "unhandledRejection", "warning", "SIGTERM", "SIGINT"] as const;

const ENV_KEYS = [
  "NODE_ENV", "SENTRY_DSN", "SENTRY_ENABLED", "SENTRY_RELEASE", "SERVER_VERSION",
  "SENTRY_ENVIRONMENT", "SENTRY_TRACES_SAMPLE_RATE",
] as const;

interface Harness {
  obs: Obs;
  /** The single `Sentry.init` options object, when Sentry was switched on. */
  opts: any;
  log: string[];
  /** Exit codes this initialisation's handlers asked for. */
  exits: number[];
  /** Fire one of the installed process handlers, without signalling the process. */
  fire: (signal: (typeof SIGNALS)[number], ...args: any[]) => Promise<void>;
  /** How many handlers this initialisation added for a signal. */
  added: (signal: (typeof SIGNALS)[number]) => number;
}

/**
 * A fresh `initObservability` under a given environment.
 *
 * The module is reloaded because `started` makes it idempotent by design, and
 * the process listeners it installs are removed afterwards — they are global,
 * they accumulate across reloads, and Node starts warning at ten.
 */
async function withObs(
  env: Partial<Record<(typeof ENV_KEYS)[number], string | undefined>>,
  fn: (h: Harness) => Promise<void> | void,
  component: any = "server",
): Promise<void> {
  const savedEnv = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  for (const k of ENV_KEYS) {
    const v = env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }

  const before = new Map(SIGNALS.map((s) => [s, process.listeners(s).slice()]));
  const savedExit = process.exit;
  const exits: number[] = [];
  (process as any).exit = (code?: number) => { exits.push(code ?? 0); order.push(`exit:${code ?? 0}`); };

  const log: string[] = [];
  const savedConsole = { log: console.log, warn: console.warn, error: console.error };
  for (const k of ["log", "warn", "error"] as const) {
    (console as any)[k] = (...a: unknown[]) => log.push(a.map(String).join(" "));
  }

  resetCalls();

  // The sink lives in `lib/logger` and is global, so a previous test's sink —
  // closing over ITS module's `sentryOn` — survives this reload. That is not a
  // production concern (the module is loaded once) but here it made a
  // Sentry-disabled run emit a breadcrumb for its own "Sentry disabled" startup
  // line, which `initObservability` logs BEFORE registering its own sink.
  registerSentrySink({ breadcrumb: () => {}, captureError: () => {}, captureMessage: () => {} });
  // The sink half of logger.error is throttled per fingerprint, and the throttle
  // is global too — without this a repeated message in a later test is dropped
  // for a reason that has nothing to do with the module under test.
  resetSentryThrottle();
  delete require.cache[obsPath];

  try {
    const obs = require(obsPath) as Obs;
    obs.initObservability(component);

    const fresh = (s: (typeof SIGNALS)[number]) =>
      process.listeners(s).filter((l) => !before.get(s)!.includes(l));

    await fn({
      obs,
      opts: calls.init[0],
      log,
      exits,
      added: (s) => fresh(s).length,
      fire: async (s, ...args) => {
        for (const l of fresh(s)) await (l as any)(...args);
        // The fatal paths flush before exiting; let those microtasks land.
        await new Promise((r) => setImmediate(r));
        await new Promise((r) => setImmediate(r));
      },
    });
  } finally {
    for (const s of SIGNALS) {
      for (const l of process.listeners(s)) {
        if (!before.get(s)!.includes(l)) process.removeListener(s, l as any);
      }
    }
    Object.assign(console, savedConsole);
    (process as any).exit = savedExit;
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

// --- whether anything is sent at all -------------------------------------------------

test("a fork with no DSN reports nowhere, production or not", async () => {
  // There is deliberately no compiled-in DSN. A Sentry DSN can only send, so it
  // is not a secret — but shipping ours would make every fork and every local
  // run report into our project, and the fix for that is not a config file.
  const { DEFAULT_DSN } = { DEFAULT_DSN: "" };
  assert.equal(DEFAULT_DSN, "", "this test encodes the intent; see lib/observability.ts");

  for (const NODE_ENV of ["production", "development", undefined]) {
    await withObs({ NODE_ENV, SENTRY_DSN: undefined }, ({ obs, log }) => {
      assert.equal(obs.sentryEnabled(), false, `NODE_ENV=${NODE_ENV}`);
      assert.equal(calls.init.length, 0, "the SDK must not be initialised with no DSN");
      assert.ok(log.some((l) => /Sentry disabled/.test(l)), log.join("\n"));
      // The important half of that line: the crash handlers are the reason this
      // module exists, and they do not depend on Sentry being reachable.
      assert.ok(log.some((l) => /crash handlers still active/.test(l)));
    });
  }
});

test("a DSN switches it on; SENTRY_ENABLED=false is the kill switch", async () => {
  await withObs({ SENTRY_DSN: "https://k@o1.ingest.sentry.io/1" }, ({ obs }) => {
    assert.equal(obs.sentryEnabled(), true);
    assert.equal(calls.init.length, 1);
  });
  // A deployment that needs reporting off right now should not have to find and
  // remove the DSN from its config.
  await withObs(
    { SENTRY_DSN: "https://k@o1.ingest.sentry.io/1", SENTRY_ENABLED: "false" },
    ({ obs }) => {
      assert.equal(obs.sentryEnabled(), false);
      assert.equal(calls.init.length, 0);
    });
  // …and only that exact value. "0"/"no" must not silently disable reporting.
  for (const v of ["0", "no", "FALSE", ""]) {
    await withObs({ SENTRY_DSN: "https://k@o1.ingest.sentry.io/1", SENTRY_ENABLED: v }, ({ obs }) => {
      assert.equal(obs.sentryEnabled(), true, `SENTRY_ENABLED=${JSON.stringify(v)}`);
    });
  }
});

test("an explicitly empty DSN stays off rather than falling back", async () => {
  // `SENTRY_DSN=` in an env file is a deliberate "off", and the ternary reads
  // `!== undefined` for exactly that reason.
  await withObs({ NODE_ENV: "production", SENTRY_DSN: "" }, ({ obs }) => {
    assert.equal(obs.sentryEnabled(), false);
  });
});

// --- what the SDK is allowed to collect -------------------------------------------------

const ON = { SENTRY_DSN: "https://k@o1.ingest.sentry.io/1" };

test("the SDK is told never to attach PII", async () => {
  await withObs(ON, ({ opts }) => {
    // The v8 default, set explicitly so an upgrade or a config drift cannot
    // silently start shipping IPs, headers and cookies from an E2EE relay.
    assert.equal(opts.sendDefaultPii, false);
    assert.equal(opts.maxValueLength, 2048, "how much free text one value may carry off-box");
    assert.equal(opts.maxBreadcrumbs, 50);
  });
});

test("the four integrations that carry payloads are removed", async () => {
  await withObs(ON, ({ opts }) => {
    const defaults = [
      { name: "OnUncaughtException" }, { name: "OnUnhandledRejection" },
      { name: "RequestData" }, { name: "LocalVariables" },
      { name: "Http" }, { name: "ContextLines" }, { name: "Console" },
    ];
    const kept = opts.integrations(defaults).map((i: any) => i.name);

    // RequestData would attach the incoming HTTP body; LocalVariables would
    // attach captured locals — on this server both can hold ciphertext and ids.
    assert.ok(!kept.includes("RequestData"), kept.join(", "));
    assert.ok(!kept.includes("LocalVariables"), kept.join(", "));
    // The other two are dropped for control, not privacy: this module installs
    // its own handlers below, and Sentry's would double-fire and exit out from
    // under the flush.
    assert.ok(!kept.includes("OnUncaughtException"));
    assert.ok(!kept.includes("OnUnhandledRejection"));
    // Everything else survives — a filter that dropped the lot would pass every
    // assertion above.
    assert.deepEqual(kept, ["Http", "ContextLines", "Console"]);
  });
});

test("beforeSend actually redacts, rather than merely existing", async () => {
  await withObs(ON, ({ opts }) => {
    const event = {
      message: "failed for 198.51.100.7 user ada@example.com",
      server_name: "relay-prod-3",
      request: { headers: { cookie: "session=abc" }, data: "{}" },
      user: { id: "keep-me", ip_address: "198.51.100.7", email: "ada@example.com", username: "ada" },
    };
    const out = opts.beforeSend(structuredClone(event));

    assert.equal(out.request, undefined, "the request carries headers, cookies and the body");
    assert.equal(out.server_name, undefined, "the hostname is infra topology");
    assert.equal(out.user.ip_address, undefined);
    assert.equal(out.user.email, undefined);
    assert.equal(out.user.username, undefined);
    assert.equal(out.user.id, "keep-me", "an opaque id set on purpose is kept");
    assert.ok(!out.message.includes("198.51.100.7"), out.message);
    assert.ok(!out.message.includes("ada@example.com"), out.message);

    // Transactions go through the same scrubber. They are a separate hook in the
    // SDK and an easy one to leave unset.
    assert.equal(opts.beforeSendTransaction(structuredClone(event)).request, undefined);
  });
});

test("beforeBreadcrumb redacts too", async () => {
  // Breadcrumbs are the free-text trail attached to every event, and they are
  // built from log lines — the place incidental context actually leaks.
  await withObs(ON, ({ opts }) => {
    const out = opts.beforeBreadcrumb({ message: "peer 198.51.100.7 dropped", category: "log" });
    assert.ok(out === null || !String(out.message).includes("198.51.100.7"), JSON.stringify(out));
  });
});

test("every event is tagged with the process that sent it", async () => {
  // Six processes report into one project. Without this an event says only that
  // something in the stack failed.
  for (const component of ["server", "bot", "auth", "api", "push-bridge", "broker-watch"] as const) {
    await withObs(ON, ({ opts, log }) => {
      assert.equal(opts.initialScope.tags.component, component);
      assert.ok(log.some((l) => l.includes(component)), "the startup line names it too");
    }, component);
  }
});

test("the trace sample rate is modest in production and silent in development", async () => {
  await withObs({ ...ON, NODE_ENV: "production" }, ({ opts }) => {
    assert.equal(opts.tracesSampleRate, 0.05);
  });
  await withObs({ ...ON, NODE_ENV: "development" }, ({ opts }) => {
    assert.equal(opts.tracesSampleRate, 0, "dev must not ship every frame");
  });
  await withObs({ ...ON, NODE_ENV: "production", SENTRY_TRACES_SAMPLE_RATE: "0.5" }, ({ opts }) => {
    assert.equal(opts.tracesSampleRate, 0.5);
  });
});

test("a release is attached only when one is known", async () => {
  // `...(release ? { release } : {})` — an explicit `release: undefined` makes
  // the SDK treat every deploy as the same version.
  await withObs(ON, ({ opts }) => {
    assert.ok(!("release" in opts), "no release key at all when none is set");
  });
  await withObs({ ...ON, SENTRY_RELEASE: "v1.2.3" }, ({ opts }) => {
    assert.equal(opts.release, "v1.2.3");
  });
  await withObs({ ...ON, SERVER_VERSION: "abc1234" }, ({ opts }) => {
    assert.equal(opts.release, "abc1234", "SERVER_VERSION is the fallback");
  });
});

// --- the logger's route into Sentry ---------------------------------------------------

test("logger.error reaches Sentry as an event, with the message as a breadcrumb", async () => {
  await withObs(ON, () => {
    logger.error("[test] something broke", new Error("boom"));
    assert.equal(calls.exceptions.length, 1, "an error must become an event");
    assert.ok(calls.breadcrumbs.some((b) => /something broke/.test(b.message)),
      "…and the message must be attached, or the event is a bare stack");
  });
});

test("nothing reaches Sentry when it is off", async () => {
  // The sink is registered either way; `sentryOn` is what gates it. Without this
  // an unconfigured fork would still call into an uninitialised SDK on every
  // warning.
  await withObs({ SENTRY_DSN: undefined }, () => {
    logger.error("[test] broke", new Error("boom"));
    logger.warn("[test] warned");
    assert.deepEqual(calls.exceptions, []);
    assert.deepEqual(calls.messages, []);
    assert.deepEqual(calls.breadcrumbs, []);
  });
});

test("a long message is truncated before it leaves the box", async () => {
  // `maxValueLength` bounds what the SDK sends; this bounds what it is given.
  // An error with no Error argument goes to `captureMessage` rather than
  // becoming a breadcrumb — the two halves of the sink truncate separately, so
  // both are checked.
  await withObs(ON, () => {
    logger.error("[test] " + "x".repeat(5000));
    const msg = calls.messages.at(-1)!;
    assert.ok(msg, "a message-only error should reach Sentry as a message event");
    assert.ok(msg.message.length <= 1001, `captureMessage got ${msg.message.length} characters`);
    assert.ok(msg.message.endsWith("…"), "and it should say it was cut");

    logger.error("[test2] " + "y".repeat(5000), new Error("boom"));
    const crumb = calls.breadcrumbs.at(-1)!;
    assert.ok(crumb.message.length <= 1001, `breadcrumb was ${crumb.message.length} characters`);
    assert.ok(crumb.message.endsWith("…"));
  });
});

// --- the handlers this module exists for -------------------------------------------------

test("the crash handlers are installed even with Sentry off", async () => {
  // The startup line claims it. An unconfigured deployment still needs the
  // process not to die silently on an ECONNRESET storm.
  await withObs({ SENTRY_DSN: undefined }, ({ added }) => {
    for (const s of SIGNALS) assert.equal(added(s), 1, `no handler for ${s}`);
  });
});

test("an uncaught exception is captured, flushed, and then exits", async () => {
  // The bug that took the server down. The order matters: an exit before the
  // flush loses the only evidence of the crash.
  await withObs(ON, async ({ fire, exits, log }) => {
    await fire("uncaughtException", new Error("ECONNRESET storm"), "uncaughtException");

    // TWO events, not one, and that is worth stating rather than asserting away.
    // `logger.error` already routes to Sentry through the sink, so the explicit
    // `captureException` below it is a second event for the same crash — the
    // first untagged, the second carrying the fatal tags. It is one extra event
    // per process death, so the flood-control note in lib/logger is not in
    // danger, but a reader of the Sentry project sees each crash twice.
    assert.equal(calls.exceptions.length, 2,
      "an uncaught exception bills one event via the logger sink and one direct");
    const tagged = calls.exceptions.find((e) => e.opts?.tags?.fatal)!;
    assert.ok(tagged, "one of them must carry the fatal tags");
    assert.equal(tagged.opts.tags.fatal, "uncaughtException");
    assert.equal(tagged.opts.tags.origin, "uncaughtException");
    assert.deepEqual(calls.flushes, [2000]);
    assert.deepEqual(exits, [1], "the process must exit so the orchestrator restarts it clean");
    // In THIS order. An exit before the flush loses the only evidence of the
    // crash, and it is indistinguishable from the correct version unless the
    // order is what is asserted.
    assert.deepEqual(order, ["flush", "exit:1"]);
    assert.ok(log.some((l) => /uncaughtException/.test(l)));
  });
});

test("a failing flush still exits", async () => {
  // Sentry being unreachable is exactly when a crash matters most. A flush that
  // throws must not leave a process running in an undefined state.
  await withObs(ON, async ({ fire, exits }) => {
    flushBehaviour = async () => { throw new Error("sentry unreachable"); };
    await fire("uncaughtException", new Error("boom"), "uncaughtException");
    assert.deepEqual(exits, [1], "the exit is in a finally for this reason");
    assert.deepEqual(order, ["flush", "exit:1"], "the flush is still attempted first");
  });
});

test("an unhandled rejection is captured but does not kill the process", async () => {
  // Deliberately more lenient than Node's default: a single dropped await in one
  // handler should not take the whole relay down.
  await withObs(ON, async ({ fire, exits }) => {
    await fire("unhandledRejection", new Error("dropped await"));
    assert.equal(calls.exceptions.length, 2, "same double-report as uncaughtException");
    assert.equal(calls.exceptions.find((e) => e.opts?.tags?.fatal)!.opts.tags.fatal, "unhandledRejection");
    assert.deepEqual(exits, [], "a rejection must not exit");
    assert.deepEqual(calls.flushes, [], "…and there is nothing to flush for");
  });
});

test("a process warning is reported as a warning, not an error", async () => {
  // MaxListenersExceededWarning is the early sign of the listener leak that
  // precedes an OOM. Reporting it as an error would bill a Sentry event for a
  // condition that is not yet a failure.
  await withObs(ON, async ({ fire }) => {
    await fire("warning", { name: "MaxListenersExceededWarning", message: "11 error listeners added" });
    assert.equal(calls.messages.length, 1);
    assert.equal(calls.messages[0]!.level, "warning");
    assert.match(calls.messages[0]!.message, /MaxListenersExceededWarning/);
    assert.match(calls.messages[0]!.message, /11 error listeners/);
    assert.deepEqual(calls.exceptions, []);
  });
});

test("SIGTERM and SIGINT flush and exit zero", async () => {
  // A rolling deploy sends SIGTERM. Exiting non-zero there would show as a crash
  // on every deploy, and skipping the flush would drop whatever was in flight.
  for (const sig of ["SIGTERM", "SIGINT"] as const) {
    await withObs(ON, async ({ fire, exits, log }) => {
      await fire(sig);
      assert.deepEqual(calls.flushes, [2000], sig);
      assert.deepEqual(exits, [0], `${sig} is not a crash`);
      assert.deepEqual(order, ["flush", "exit:0"], `${sig} must flush before exiting`);
      assert.ok(log.some((l) => l.includes(sig)), log.join("\n"));
    });
  }
});

test("nothing is flushed on shutdown when Sentry is off", async () => {
  // `flushThen` guards on `sentryOn`; without it, shutdown waits on an
  // uninitialised SDK before every exit.
  await withObs({ SENTRY_DSN: undefined }, async ({ fire, exits }) => {
    await fire("SIGTERM");
    assert.deepEqual(calls.flushes, []);
    assert.deepEqual(exits, [0], "…but it still exits");
  });
});

test("initialising twice does not install a second set of handlers", async () => {
  // Two entrypoints in one process (the bot imports the server's lib) would
  // otherwise double every crash event and race two exits.
  await withObs(ON, ({ obs, added }) => {
    obs.initObservability("bot");
    obs.initObservability("api");
    assert.equal(calls.init.length, 1, "the SDK was initialised more than once");
    for (const s of SIGNALS) assert.equal(added(s), 1, `${s} has a duplicate handler`);
  });
});
