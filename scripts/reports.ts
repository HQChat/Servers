// The moderation queue, and the one lever an operator has.
//
//   docker compose exec api node --import tsx scripts/reports.ts
//   docker compose exec api node --import tsx scripts/reports.ts <report-id> <disposition>
//
// App Store Guideline 1.2 asks a user-generated-content app to act on reported
// content within 24 hours, and /eula says we do. A commitment with no procedure
// behind it is the same acceptable-use clause this whole phase exists to replace,
// so: docs/runbooks/moderation.md is the procedure, and this is the tool it names.
//
// There is no mail path in this stack (docs/product/publishing.md records
// resend_api_key as no longer used), so a report announces itself through
// `logger.event` — a Sentry message, deliberately unthrottled — and is worked
// through here.
//
// ⚠️ READING THE QUEUE DELETES LAPSED ROWS. `DB.listOpenReports` sweeps
// `expires_at` before it selects, because the 90-day deletion is a published
// promise rather than a space optimisation: an operator must not be shown a
// report that should no longer exist, whether or not the ops sweep is running.
//
// ⚠️ AN EXCERPT IS NOT EVIDENCE. It is the reporter's own plaintext copy of a
// message, uploaded by consent, and nothing here can tell a genuine one from an
// invented one — the AEAD tag on an attached frame is computed under a ratchet
// key the REPORTER holds. Read it as what somebody handed in. The output says so
// on every row rather than trusting whoever runs this to remember.

import "../lib/config";
import { DB } from "../services/db/api";
import { disconnect } from "../services/db/pg";

/** What an operator may record. Mirrors the CHECK in 006_reports.sql — a value
 *  this list invents fails at the constraint, after the operator was told it
 *  worked. */
export const DISPOSITIONS = ["no-action", "warned", "ejected", "banned"] as const;

const short = (id: string | null) => (id ? `${id.slice(0, 12)}…` : "(deleted account)");

/** Print the open queue. Exported so its formatting can be asserted without a
 *  process, the way check-push separates `report` from argv. */
export async function queue(limit = 100): Promise<number> {
  const rows = await DB.listOpenReports(limit);
  console.log("");
  if (!rows.length) {
    console.log("no open reports.");
    console.log("");
    return 0;
  }
  console.log(`${rows.length} open report(s), oldest first:`);
  console.log("");
  for (const r of rows) {
    // The count is the only question these rows answer that a single report
    // cannot, and it is the one that decides between a word and an ejection.
    const repeat = r.againstSubject > 1 ? `  ⚠️ ${r.againstSubject} reports against this account` : "";
    console.log(`  ${r.id}`);
    console.log(`    ${r.createdAt}  ${r.category}`);
    console.log(`    against ${short(r.reportedId)}   by ${short(r.reporterId)}${repeat}`);
    console.log(`    conversation ${r.conversationHash.slice(0, 16)}…`
      + (r.messageId ? `  message ${r.messageId.slice(0, 16)}…` : "")
      + (r.hasFrame ? "  [frame attached]" : ""));
    if (r.note) console.log(`    they said: ${r.note}`);
    if (r.excerpt) {
      console.log(`    handed in (UNVERIFIED — the reporter's own copy, not proof of what was said):`);
      for (const line of r.excerpt.split("\n")) console.log(`      | ${line}`);
    }
    console.log("");
  }
  console.log("to record a decision:");
  console.log(`  node --import tsx scripts/reports.ts <report-id> <${DISPOSITIONS.join("|")}>`);
  console.log("");
  console.log("the levers, in docs/runbooks/moderation.md:");
  console.log("  ejected — POST /friends/remove on their behalf is NOT it; use the admission");
  console.log("            policy + EMQX kick described in the runbook.");
  console.log("  banned  — ADMISSION_POLICY, and read the runbook's note on what a ban");
  console.log("            cannot do: an id is sha256(public key), so a reinstall is a new");
  console.log("            person and no ban follows a human across it.");
  console.log("");
  return rows.length;
}

/** Record what was done. Refuses to overwrite a decision somebody already made. */
export async function resolve(id: string, disposition: string): Promise<boolean> {
  if (!(DISPOSITIONS as readonly string[]).includes(disposition)) {
    console.error(`unknown disposition "${disposition}" — one of: ${DISPOSITIONS.join(", ")}`);
    return false;
  }
  const ok = await DB.resolveReport(id, disposition);
  console.log(ok
    ? `✅ ${id} → ${disposition}`
    : `⛔️ ${id} is not an open report — unknown id, or somebody has already handled it`);
  return ok;
}

async function main(): Promise<void> {
  const [id, disposition] = process.argv.slice(2);
  if (id && disposition) {
    const ok = await resolve(id, disposition);
    await disconnect();
    process.exit(ok ? 0 : 1);
  }
  if (id) {
    console.error("usage: reports.ts [<report-id> <disposition>]");
    await disconnect();
    process.exit(1);
  }
  await queue();
  await disconnect();
}

if (require.main === module) {
  main().catch(async (e) => {
    console.error(`[reports] ${(e as Error).message}`);
    await disconnect();
    process.exit(1);
  });
}
