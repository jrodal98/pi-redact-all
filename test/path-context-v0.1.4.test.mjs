// Regression tests for v0.1.4 — filename / path-context preservation
//
// Bug: pi-redact-all v0.1.3 redacted legitimate file paths in Obsidian
// playbooks and tool output. The reported offender was
// `zed-task-handle.md` becoming
// `zed-task-h***************[REDACTED:OpenAI/Anthropic API Key].md`.
//
// Cause: Layer 1 (vendor prefix `sk-[a-zA-Z0-9._\-]{20,}`) and
// Layer 4 (entropy) matched on a long alphanumeric token that was part of
// a filename. The new `isInsidePathContext()` heuristic in shared.ts
// suppresses all layer matches when the [start, end) span sits inside a
// path-like context — modeled after gitleaks' `paths` allowlist and
// detect-secrets' `--exclude-files` flag.
//
// Conventions: every test asserts what the text *is* after redaction,
// rather than asserting it equals a magic marker string, so failures
// remain readable in CI logs.

import assert from "node:assert/strict";
import { redactText } from "../dist/layers/index.js";
import { loadConfig } from "../dist/config.js";

const ctx = { config: loadConfig(), partialPrivateKeyPaths: new Set() };
let pass = 0, fail = 0;
function test(name, fn) {
  try { fn(); console.log(`\u2705 ${name}`); pass++; }
  catch (e) { console.log(`\u274c ${name}: ${e.message}`); fail++; }
}

// A long alphanumeric blob that satisfies the OpenAI vendor pattern
// (`sk-` + 20+ chars of `[a-zA-Z0-9._\-]`). When written plainly it
// would always trigger the rule.
const KEY_LIKE_BLOB = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdEFGH";

// --- The reported bug --------------------------------------------------

test("Reported bug: zed-task-handle.md style filename survives", () => {
  const input = "Please save this as zed-task-handle.md under " +
    "/home/steimer/Dokumente/OBSIDIAN/Bs-digitaler-Garten/AGENT/OKF/" +
    "playbooks/zed-task-handle.md";
  const { text } = redactText(input, ctx);
  assert.match(text, /zed-task-handle\.md/, "filename must survive intact");
  assert.doesNotMatch(text, /\[REDACTED:OpenAI.*API Key\]/,
    "no OpenAI marker should appear in the filename path");
  assert.doesNotMatch(text, /\[REDACTED:High Entropy Token\]/,
    "no entropy marker should appear in the filename path");
});

test("Filename with random alphanumeric tail: NOT flagged as entropy key", () => {
  const input = "Write the file to ./" + KEY_LIKE_BLOB + ".md";
  const { text } = redactText(input, ctx);
  assert.match(text, new RegExp(KEY_LIKE_BLOB.replace(/\./g, "\\.") + "\\.md"),
    "filename must survive intact");
  assert.doesNotMatch(text, /\[REDACTED/);
});

// --- Path-context signals ----------------------------------------------

test("File extension immediately after token: protects from Layer 1", () => {
  const input = "see file sk-" + KEY_LIKE_BLOB + ".json for details";
  const { text } = redactText(input, ctx);
  assert.match(text, /sk-AbCd/);
  assert.match(text, /\.json/);
  assert.doesNotMatch(text, /\[REDACTED:OpenAI/);
});

test("Path separator before token: protects", () => {
  const input = "spec at /home/foo/sk-" + KEY_LIKE_BLOB + "/notes.md";
  const { text } = redactText(input, ctx);
  assert.match(text, /\/sk-AbCd/);
  assert.match(text, /\/notes\.md/);
  assert.doesNotMatch(text, /\[REDACTED:OpenAI/);
});

test("Path-prefix cue 'path:' before token: protects", () => {
  const input = "path: sk-" + KEY_LIKE_BLOB;
  const { text } = redactText(input, ctx);
  assert.match(text, /sk-AbCd/);
  assert.doesNotMatch(text, /\[REDACTED:OpenAI/);
});

test("Path-prefix cue 'save' before token: protects", () => {
  const input = "save sk-" + KEY_LIKE_BLOB + " as the next key";
  const { text } = redactText(input, ctx);
  assert.match(text, /sk-AbCd/);
  assert.doesNotMatch(text, /\[REDACTED:OpenAI/);
});

test("Path-prefix cue 'from' before token: protects", () => {
  const input = "loaded from sk-" + KEY_LIKE_BLOB;
  const { text } = redactText(input, ctx);
  assert.match(text, /sk-AbCd/);
  assert.doesNotMatch(text, /\[REDACTED:OpenAI/);
});

test("<path> tag-style cursor: protects", () => {
  const input = "<path>sk-" + KEY_LIKE_BLOB + "</path>";
  const { text } = redactText(input, ctx);
  assert.match(text, /sk-AbCd/);
  assert.doesNotMatch(text, /\[REDACTED:OpenAI/);
});

// --- Negatives: real secrets in normal context ARE still redacted -------

test("Stand-alone sk-* in a sentence IS redacted (still works)", () => {
  const input = "Your API key is sk-" + KEY_LIKE_BLOB + " and it works.";
  const { text } = redactText(input, ctx);
  assert.match(text, /\[REDACTED:OpenAI\/Anthropic API Key\]/,
    "real OpenAI key in prose must still be redacted");
});

test("Stand-alone ghp_ token IS redacted (still works)", () => {
  // 36 alnum chars after ghp_ — matches the GitHub token regex.
  const input = "My GitHub token: ghp_" + KEY_LIKE_BLOB;
  const { text } = redactText(input, ctx);
  assert.match(text, /\[REDACTED:GitHub Token\]/);
});

test("Stand-alone high-entropy token IS redacted", () => {
  // 36 chars of high-entropy content. We avoid word-boundary trigger
  // words like "key" / "secret" / "token" in the cue prefix.
  const input = "the blob is " + KEY_LIKE_BLOB + " and should be redacted";
  const { text } = redactText(input, ctx);
  assert.match(text, /\[REDACTED/);
});

test("AWS access key in a config-snippet IS redacted", () => {
  // AKIA + exactly 16 uppercase alnum chars.
  const input = "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP and other settings";
  const { text } = redactText(input, ctx);
  assert.match(text, /\[REDACTED:AWS Access Key\]/);
});

console.log(`\n${pass}/${pass + fail} tests passed`);
process.exit(fail > 0 ? 1 : 0);
