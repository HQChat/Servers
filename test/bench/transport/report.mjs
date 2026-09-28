// report.mjs — turn a results JSONL into the tables you can argue from.
//
//   node report.mjs results/<stamp>.jsonl [--md]
//
// The comparison that answers the question is `mqtts` vs `wss-nginx`: the
// proposal against production as deployed. The other three arms exist to
// attribute any difference rather than guess at it —
//
//   wss-direct vs mqtts        the WebSocket layer's own cost (same TLS, no nginx)
//   wss-nginx  vs wss-direct   what the nginx hop costs
//   ws-plain   vs tcp-plain    framing with TLS taken out of the picture
import { readFileSync } from "node:fs";

const file = process.argv[2];
if (!file) { console.error("usage: node report.mjs <results.jsonl>"); process.exit(2); }

const rows = readFileSync(file, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
const PROFILES = [...new Set(rows.map((r) => r.profile))];
const ALL_ARMS = ["tcp-plain", "ws-plain", "mqtts", "wss-direct", "wss-nginx", "wss-edge-warm", "wss-edge-cold"];
// Only show arms this results file actually contains, so a subset run
// (ARMS="mqtts wss-nginx" bash run.sh) prints a narrow table instead of one
// padded with dashes.
const present = new Set(rows.filter((r) => r.arm).map((r) => r.arm));
const ARMS = ALL_ARMS.filter((a) => present.has(a));

const cal = {};
for (const r of rows.filter((r) => r.kind === "calibration")) cal[r.profile] = r;
const wire = {};
for (const r of rows.filter((r) => r.kind === "wire")) wire[`${r.profile}|${r.arm}`] = r;
const main = {};
for (const r of rows.filter((r) => !r.kind && r.connect)) main[`${r.profile}|${r.arm}`] = r;

const n = (v, d = 1) => (v === null || v === undefined || Number.isNaN(v) ? "–" : Number(v).toFixed(d));
const pad = (s, w) => String(s).padEnd(w);
const lpad = (s, w) => String(s).padStart(w);

function table(title, headers, lines) {
  const widths = headers.map((h, i) => Math.max(h.length, ...lines.map((l) => String(l[i]).length)));
  const out = [];
  out.push("");
  out.push(title);
  out.push("| " + headers.map((h, i) => pad(h, widths[i])).join(" | ") + " |");
  out.push("|" + widths.map((w, i) => (i === 0 ? ":" + "-".repeat(w + 1) : "-".repeat(w + 1) + ":")).join("|") + "|");
  for (const l of lines) out.push("| " + l.map((c, i) => (i === 0 ? pad(c, widths[i]) : lpad(c, widths[i]))).join(" | ") + " |");
  return out.join("\n");
}

// --- the network the arms actually saw --------------------------------------
console.log(table(
  "### Measured link conditions (ICMP, through the same impaired path)",
  ["profile", "RTT avg", "RTT min", "RTT max", "ICMP loss"],
  PROFILES.filter((p) => cal[p]).map((p) => [
    p, `${n(cal[p].rtt_avg)} ms`, `${n(cal[p].rtt_min)} ms`, `${n(cal[p].rtt_max)} ms`, `${n(cal[p].icmp_loss_pct)} %`,
  ]),
));

// --- connect ---------------------------------------------------------------
for (const metric of [
  { key: "connect", label: "Cold connect → CONNACK", pick: (r) => r.connect },
  { key: "rtt256", label: "Message latency, 256 B payload (publish → delivered)", pick: (r) => r.messages?.[256]?.rtt },
  { key: "rtt16k", label: "Message latency, 16 KB payload (publish → delivered)", pick: (r) => r.messages?.[16384]?.rtt },
  { key: "recover", label: "Recovery after an abrupt socket kill → message round-trips again", pick: (r) => r.recover },
]) {
  const lines = [];
  for (const p of PROFILES) {
    if (!PROFILES.includes(p) || !ARMS.some((a) => main[`${p}|${a}`])) continue;
    for (const half of ["p50", "p95"]) {
      const row = [`${p} ${half}`];
      for (const a of ARMS) {
        const s = main[`${p}|${a}`] && metric.pick(main[`${p}|${a}`]);
        row.push(s ? n(s[half]) : "–");
      }
      lines.push(row);
    }
    const fr = [`${p} fail`];
    for (const a of ARMS) {
      const s = main[`${p}|${a}`] && metric.pick(main[`${p}|${a}`]);
      fr.push(s ? `${s.failures}/${s.n + s.failures}` : "–");
    }
    lines.push(fr);
  }
  console.log(table(`### ${metric.label} (ms)`, ["profile", ...ARMS], lines));
}

// --- wire bytes ------------------------------------------------------------
{
  const lines = [];
  for (const p of PROFILES) {
    const row = [p];
    for (const a of ARMS) {
      const w = wire[`${p}|${a}`];
      row.push(w ? `${(w.tx_bytes / 1024).toFixed(1)}k↑ ${(w.rx_bytes / 1024).toFixed(1)}k↓` : "–");
    }
    lines.push(row);
  }
  console.log(table(
    "### Bytes on the wire for a fixed workload (1 connect + 100 × QoS-1 publish of 256 B, incl. IP/TCP headers and retransmits)",
    ["profile", ...ARMS], lines,
  ));
}

// --- the headline deltas ---------------------------------------------------
// Everything is stated against `mqtts`, the proposal, so a positive number means
// "this WSS topology is that many ms slower than going raw" and a negative number
// means the WebSocket arrangement wins.
{
  const delta = (x, y) => (x == null || y == null ? "–" : `${y - x > 0 ? "+" : ""}${n(y - x)}`);
  const lines = [];
  for (const p of PROFILES) {
    const m = main[`${p}|mqtts`];
    if (!m) continue;
    const row = [p];
    for (const a of ["wss-nginx", "wss-direct", "wss-edge-warm", "wss-edge-cold"]) {
      const x = main[`${p}|${a}`];
      row.push(x ? delta(m.connect.p50, x.connect.p50) : "–");
    }
    const w = main[`${p}|wss-nginx`];
    row.push(w ? delta(m.messages?.[256]?.rtt.p50, w.messages?.[256]?.rtt.p50) : "–");
    lines.push(row);
  }
  console.log(table(
    "### Headline: every WSS topology's cold-connect cost relative to raw mqtts (ms; + means WSS is slower, − means WSS wins)",
    ["profile", "wss-nginx", "wss-direct", "edge (warm)", "edge (cold)", "msg p50 (wss-nginx)"],
    lines,
  ));
}
console.log("");
