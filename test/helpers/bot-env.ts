// MUST be imported before `bot/bot`. The bot derives its identity from a seed
// file and reads its state file at import — both cheap, both contained by
// BOT_STATE_DIR, and both done before any test body runs, because `import` is
// hoisted. Without this it would write into services/server/bot/.
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

export const BOT_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "hqchat-bot-test-"));
process.env.BOT_STATE_DIR = BOT_DIR;
process.env.BOT_USERNAME = "helper-test";
