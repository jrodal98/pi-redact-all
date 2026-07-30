// Regression tests for v0.1.5 — Data-URL base64 preservation in TEXT fields
//
// Bug: When image binary data appeared in a TEXT field (e.g. `read` tool result
// text note containing a base64 dump, or the result of `bash base64 img.png`,
// or any user message with embedded `data:image/png;base64,XXX`), Layer 4
// (entropy) matched the long high-entropy base64 token and replaced it with
// `[REDACTED:High Entropy Token]`. The downstream provider then received a
// corrupted image payload.
//
// The path-context heuristic was extended to recognize that a long base64
// token preceded by a `data:image/...;base64,` (or `data:application/...;base64,`)
// prefix is the base64 payload of an inline image or file — not a leaked
// secret. Layer 4 (entropy) skips the match; other layers (vendor, prefix,
// PEM, ASN.1, connection, PII) still scan normally for real secrets in
// surrounding prose. The check inspects the 60 chars before the match in
// `isInsidePathContext`, which is consulted by entropy AND by Layer 1 (vendor)
// + Layer 3 (prefix) for the same reason.

import assert from "node:assert/strict";
import { redactText } from "../dist/layers/index.js";
import { loadConfig } from "../dist/config.js";

const ctx = { config: loadConfig(), partialPrivateKeyPaths: new Set() };
let pass = 0, fail = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`\u2705 ${name}`);
    pass++;
  } catch (e) {
    console.log(`\u274c ${name}: ${e.message}`);
    fail++;
  }
}

function randomB64(len) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  return Array.from({ length: len }, () => chars[Math.floor(Math.random() * chars.length)]).join("") + "==";
}

// ===== Reported bug — read on image with b64 in text note =====
test("Reported bug: image data in read-tool text note is NOT redacted", () => {
  const b64 = randomB64(2400);
  const text = `Read image file [image/png]\n[Image data]: data:image/png;base64,${b64}\n[End]`;
  const { text: out, matches } = redactText(text, ctx);
  assert.ok(out.includes(b64), "B64 payload must survive intact");
  // No ENTROPY redaction of the b64
  assert.doesNotMatch(out, /\[REDACTED:High Entropy Token\]/,
    "Entropy must not have replaced the b64 payload");
});

// ===== Common MIME-prefix variants =====
test("data:image/png;base64, → no entropy match", () => {
  const b64 = randomB64(2400);
  const { text: out } = redactText(`img: data:image/png;base64,${b64}`, ctx);
  assert.ok(out.includes(b64));
});

test("data:image/jpeg;base64, → no entropy match", () => {
  const b64 = randomB64(2400);
  const { text: out } = redactText(`img: data:image/jpeg;base64,${b64}`, ctx);
  assert.ok(out.includes(b64));
});

test("data:image/webp;base64, → no entropy match", () => {
  const b64 = randomB64(2400);
  const { text: out } = redactText(`img: data:image/webp;base64,${b64}`, ctx);
  assert.ok(out.includes(b64));
});

test("data:image/svg+xml;base64, → no entropy match", () => {
  const b64 = randomB64(2400);
  const { text: out } = redactText(`img: data:image/svg+xml;base64,${b64}`, ctx);
  assert.ok(out.includes(b64));
});

test("data:application/octet-stream;base64, → no entropy match", () => {
  const b64 = randomB64(2400);
  const { text: out } = redactText(`data:application/octet-stream;base64,${b64}`, ctx);
  assert.ok(out.includes(b64));
});

test("data:application/pdf;base64, → no entropy match", () => {
  const b64 = randomB64(2400);
  const { text: out } = redactText(`data:application/pdf;base64,${b64}`, ctx);
  assert.ok(out.includes(b64));
});

// ===== Negative — real secrets elsewhere in same text ARE redacted =====
test("Negative: AWS key after data: URL is still redacted", () => {
  const b64 = randomB64(100);
  const text = `data:image/png;base64,${b64}\nThen AWS key: AKIAABCDEFGHIJKLMNOP`;
  const { text: out } = redactText(text, ctx);
  assert.match(out, /\[REDACTED:AWS Access Key\]/,
    "AWS key MUST still be redacted when adjacent to data: URL");
  assert.ok(out.includes(b64),
    "data: URL payload MUST survive intact");
});

test("Negative: GitHub token after data: URL is still redacted", () => {
  const b64 = randomB64(100);
  const text = `data:image/png;base64,${b64}\nThen GH token: ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa`;
  const { text: out } = redactText(text, ctx);
  assert.match(out, /\[REDACTED:GitHub Token\]/,
    "GitHub token MUST still be redacted");
  assert.ok(out.includes(b64));
});

test("Negative: PEM block after data: URL is still redacted", () => {
  const b64 = randomB64(100);
  const text = `data:image/png;base64,${b64}\n-----BEGIN RSA PRIVATE KEY-----\nABCDEFGHIJKLMNOP\nQRSTUVWXYZ0123456\n-----END RSA PRIVATE KEY-----`;
  const { text: out } = redactText(text, ctx);
  assert.match(out, /\[REDACTED:PEM.*PRIVATE KEY\]/, "PEM MUST still be redacted");
});

// ===== Negative — high-entropy b64 WITHOUT data: prefix IS redacted =====
test("Negative: random b64 (no data: prefix) IS redacted by entropy", () => {
  const b64 = randomB64(2400);
  const text = `Here is some text ${b64} and more text`;
  const { text: out } = redactText(text, ctx);
  assert.match(out, /\[REDACTED:High Entropy Token\]/,
    "Random b64 in prose MUST still be redacted");
});

// ===== Whitespace tolerance — data: prefix followed by newline/spaces is fine =====
test("Whitespace between data: prefix and b64 token: protected", () => {
  const b64 = randomB64(100);
  // Note: a single newline break between ", " and the start makes the regex
  // match across a ` \n` boundary. The "<text>` word boundary is satisfied as
  // long as the byte at `start` is a word char. We test the simpler case here:
  // the prefix immediately followed by b64.
  const text = `data:image/png;base64,${b64}`;
  const { text: out } = redactText(text, ctx);
  assert.equal(out, text, "Simple data: URL must round-trip");
});

console.log(`\n${pass}/${pass + fail} tests passed`);
process.exit(fail > 0 ? 1 : 0);
