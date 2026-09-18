// A log line is newline-delimited, and `redact` has never had an opinion about
// newlines.
//
// It removes SHAPES — tokens, keys, emails, addresses — from strings on their
// way to the console. What it does not do, and was never written to do, is stop
// one field from becoming two lines. So any attacker-influenced value that
// reaches a log line can spell:
//
//     bob\n[apns] 200 delivered to every device
//
// and Docker's json-file driver records two entries, the second one
// indistinguishable from something this process wrote. Forging an entry is the
// cheap half. The expensive half is that it makes every OTHER line untrustworthy
// — including the ones an incident gets reconstructed from afterwards.
//
// These assert what `scrubArgs` hands the console, not what the console prints:
// the console is stubbed, so the subject is the value itself, before any
// formatting can hide an escape or add one of its own.
//
// Not one control character in this file is typed literally: they are built with
// `ch()` and matched with an escape-sequence class. A test about control
// characters is the last place to put an invisible one.

import { test } from "node:test";
import assert from "node:assert/strict";
import { logger, setLogLevel, escapeControl } from "../lib/logger";

/** Anything `escapeControl` is supposed to have removed. Spelled out rather than
 *  imported: a test that reads the rule from the implementation cannot catch the
 *  rule shrinking. */
const CONTROLS = new RegExp("[\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029]");

/** One character, by code point. */
const ch = (code: number): string => String.fromCharCode(code);

const NUL = 0x00, TAB = 0x09, LF = 0x0a, CR = 0x0d, DEL = 0x7f, CSI = 0x9b;
const LINE_SEP = 0x2028, PARA_SEP = 0x2029;

/** Run `fn` with the console captured, and return every argument it was given. */
function captured(fn: () => void): unknown[] {
  const real = { log: console.log, warn: console.warn, error: console.error };
  const seen: unknown[] = [];
  const grab = (...a: unknown[]) => { seen.push(...a); };
  console.log = grab; console.warn = grab; console.error = grab;
  try { fn(); } finally { Object.assign(console, real); }
  return seen;
}

setLogLevel("debug");   // every level must reach the stubbed console

test("a newline in a logged string cannot start a second line", () => {
  const handle = `bob${ch(LF)}[apns] 200 delivered to every device`;
  const [arg] = captured(() => { logger.info("new profile:", handle); }).slice(1);
  assert.equal(typeof arg, "string");
  assert.ok(!CONTROLS.test(arg as string), `a raw newline survived: ${JSON.stringify(arg)}`);
  assert.match(arg as string, /\\n/, "…and it is escaped rather than dropped");
  assert.match(arg as string, /delivered to every device/,
    "the content is preserved — this is about line structure, not censorship");
});

test("CR, NUL, tab, DEL, C1 and the line separators are all escaped", () => {
  // CR alone re-homes the cursor on a terminal and is a line break to plenty of
  // log readers. U+2028/U+2029 are line breaks to a JSON consumer and invisible
  // in a terminal, which is the worse pair of those two properties to combine.
  const cases: Array<[number, RegExp]> = [
    [CR, /\\r/],
    [NUL, /\\x00/],
    [TAB, /\\t/],
    [DEL, /\\x7f/],
    [CSI, /\\x9b/],
    [LINE_SEP, /\\u2028/],
    [PARA_SEP, /\\u2029/],
  ];
  for (const [code, shown] of cases) {
    const out = escapeControl(`a${ch(code)}b`);
    assert.match(out, shown, `U+${code.toString(16)} was not escaped`);
    assert.ok(!CONTROLS.test(out), `U+${code.toString(16)} still holds a control character`);
  }
});

test("ordinary text is untouched, escapes and all", () => {
  // The check that this is not simply mangling every line it sees. A literal
  // backslash-n a developer typed is two ordinary characters and stays two.
  assert.equal(escapeControl("APNs ready (production; topic=x)"),
    "APNs ready (production; topic=x)");
  assert.equal(escapeControl("already \\n escaped"), "already \\n escaped");
  assert.equal(escapeControl(""), "");
});

test("a nested object cannot smuggle one in, by value or by key", () => {
  // scrubDeep walked objects for SHAPES; nothing walked them for structure. Both
  // halves matter, because console.log prints the key as well as the value.
  const [arg] = captured(() => {
    logger.info({ [`peer${ch(LF)}fake: line`]: `value${ch(LF)}also fake` });
  }).slice(1);
  assert.ok(!CONTROLS.test(JSON.stringify(arg) ?? ""),
    `a raw control character survived: ${JSON.stringify(arg)}`);
});

test("an Error's message is escaped and its real frames survive", () => {
  // Errors passed through untouched, to keep the stack readable. The stack IS
  // worth keeping — but it begins with the message, so an Error built around an
  // attacker's input carries the injection inside the multi-line string being
  // printed. Rebuilt, not flattened.
  const e = new Error(`parse failed near: }${ch(LF)}    at Object.forged (/etc/passwd:1:1)`);
  const [arg] = captured(() => { logger.error(e); });
  assert.ok(arg instanceof Error);
  const err = arg as Error;
  assert.ok(!CONTROLS.test(err.message), `the message kept a newline: ${err.message}`);
  assert.match(err.message, /\\n/);
  assert.match(err.stack!, /parse failed near/);
  const frames = err.stack!.split(ch(LF)).slice(1);
  assert.ok(frames.length > 0, "the real frames were thrown away");
  assert.ok(frames.every((l) => /^\s+at\s/.test(l)),
    `a forged frame survived as a line of its own: ${JSON.stringify(err.stack)}`);
  assert.ok(!frames.some((l) => l.includes("Object.forged")),
    "the fake frame was inside the message and must not become a frame");
});

test("an Error with nothing to escape is the same object", () => {
  // Every Error this process raises itself. Returning a copy unconditionally
  // would lose whatever subclass, `cause` or custom property a call site put on
  // it, for no benefit at all.
  const e = new Error("the broker is unreachable");
  const [arg] = captured(() => { logger.error(e); });
  assert.equal(arg, e, "an ordinary Error must pass through untouched");
});

test("redaction still happens, and happens before the escaping", () => {
  // The two are composed, not alternatives: a secret that arrives with a newline
  // attached must be both redacted and unable to break the line.
  const [arg] = captured(() => {
    logger.warn("db said:", `postgresql://u:hunter2@host/db${ch(LF)}FATAL: forged`);
  }).slice(1);
  const s = arg as string;
  assert.ok(!s.includes("hunter2"), `the password survived: ${s}`);
  assert.ok(!CONTROLS.test(s), `the newline survived: ${s}`);
});
