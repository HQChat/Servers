// What the helper bot says back.
//
// EXTRACTED FROM bot.ts so it can be tested. bot.ts loads a seed from disk,
// derives a keypair and reads persisted state at module scope, so importing it
// has side effects on the filesystem — nothing could hold it, and the reply
// logic went untested along with the other 1,600 lines.
//
// Pure: the support address and the source of randomness are arguments rather
// than module state, so a test can pin both. `gameReply` used `Math.random()`
// directly, which made the guessing game's output unassertable.

export interface ReplyDeps {
  supportEmail: string;
  /** Inclusive 1..max. Injected so the guessing game is testable. */
  randomInt?: (max: number) => number;
}

const HELP =
  "I can play simple games or answer basic questions. " +
  "Try '/game prc' for rock-paper-scissors or '/game guess <number>' to guess a number between 1 and 10.";

const GAME_HELP =
  "I only play rock-paper-scissors or number guessing. Try '/game prc' or '/game guess <number>'.";

const GUESS_HELP = "I only play number guessing with '/game guess <number>'.";

export function gameReply(text: string, deps: ReplyDeps): string {
  const randomInt = deps.randomInt ?? ((max: number) => Math.floor(Math.random() * max) + 1);
  const lower = text.toLowerCase();

  if (lower.startsWith("/game prc")) {
    // Always beats the player — this is a toy, and saying so is better than
    // pretending the outcome is fair.
    if (lower.includes("rock")) return "Paper! I win!";
    if (lower.includes("paper")) return "Scissors! I win!";
    if (lower.includes("scissors")) return "Rock! I win!";
    return "I only play rock-paper-scissors. Try sending 'rock', 'paper', or 'scissors'.";
  }

  if (lower.startsWith("/game guess")) {
    const parts = lower.split(" ");
    if (parts.length < 3) return GUESS_HELP;
    const raw = parts[2];
    if (raw === undefined) return GUESS_HELP;
    // `parseInt` stops at the first character it cannot use, so it accepts a
    // PREFIX: parseInt("1.5e400") is 1, and so is parseInt("1abc"). The guess
    // then silently becomes a number the player did not type. Harmless in a toy
    // game and not harmless as a habit, so the whole token has to be digits.
    const number = /^\d+$/.test(raw) ? Number(raw) : NaN;
    if (isNaN(number) || number < 1 || number > 10) return "Guess a number between 1 and 10.";
    const botNumber = randomInt(10);
    if (number === botNumber) return `You guessed ${number} and I guessed ${botNumber}. You win!`;
    return `You guessed ${number} and I guessed ${botNumber}. I win!`;
  }

  return GAME_HELP;
}

export function reply(text: string, deps: ReplyDeps): string {
  const lower = text.toLowerCase();
  if (lower.includes("hello")) return "Hello! I'm a bot. How can I help you?";
  if (lower.startsWith("/support")) return `For support, please email ${deps.supportEmail}`;
  if (lower.startsWith("/game")) return gameReply(text, deps);
  if (lower.startsWith("/help")) return HELP;
  // Default: echo back what was said.
  return `You said: "${text}"`;
}
