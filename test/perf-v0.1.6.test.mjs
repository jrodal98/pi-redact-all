// Performance regression tests for v0.1.6 — a soft suite that catches
// "we accidentally made the filters 10× slower again". Each test has a
// generous upper bound so this passes consistently on CI machines but
// still catches large regressions.
//
// Run with: node test/perf-v0.1.6.test.mjs

import { redactText } from "../dist/layers/index.js";
import { applyRedaction } from "../dist/hooks/tool-result.js";
import { loadConfig } from "../dist/config.js";

const ctx = { config: loadConfig(), partialPrivateKeyPaths: new Set() };

function genB64Chars(len) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  return Array.from({ length: len }, () => chars[Math.floor(Math.random() * chars.length)]).join("") + "==";
}

function time(fn, iters = 100) {
  // Warmup
  fn();
  const t0 = performance.now();
  for (let i = 0; i < iters; i++) fn();
  return (performance.now() - t0) / iters;
}

let pass = 0, fail = 0;
function assertUnder(name, fn, maxMs, iters = 100) {
  const ms = time(fn, iters);
  if (ms <= maxMs) {
    console.log(`\u2705 ${name}: ${ms.toFixed(2)}ms (limit ${maxMs}ms)`);
    pass++;
  } else {
    console.log(`\u274c ${name}: ${ms.toFixed(2)}ms EXCEEDS limit ${maxMs}ms`);
    fail++;
  }
}

// ===== Layer 1–8 hotspots (single layer) =====
// No-secret benchmarks: ensure that the regex engine isn't being run
// pointlessly on texts that contain no vendor tokens.

// 1K text, no secrets
const text1k = "Lorem ipsum ".repeat(50) + genB64Chars(1000);
assertUnder("1K text, no secrets (redactText)", () => redactText(text1k, ctx), 1);

// 10K text, no secrets
const text10k = "Lorem ipsum ".repeat(500) + genB64Chars(2000);
assertUnder("10K text, no secrets (redactText)", () => redactText(text10k, ctx), 3);

// 100K text, no secrets
const text100k = "Lorem ipsum dolor sit amet. ".repeat(4000);
assertUnder("100K text, no secrets (redactText)", () => redactText(text100k, ctx), 15);

// 100K text with one long base64 (real-world: read of an image)
const text100k_b64 = "Lorem ipsum ".repeat(10000) + genB64Chars(2000);
assertUnder("100K + 1 token (redactText)", () => redactText(text100k_b64, ctx), 25);

// 100K text with many base64 tokens (real-world: lots of small files
// in a workspace)
const text100k_many = ("Lorem ipsum " + genB64Chars(800) + " ").repeat(1000);
assertUnder("100K + many tokens (~1000 x b64, redactText)", () => redactText(text100k_many, ctx), 200);

// ===== Hook overhead =====
// End-to-end tool_result pipeline.
assertUnder("applyRedaction on 100K + many b64 tool result", () => applyRedaction({
  type: "tool_result",
  toolName: "bash",
  toolCallId: "x",
  input: { command: "echo" },
  content: [{ type: "text", text: text100k_many }],
  isError: false,
  details: {},
}, ctx), 250);

// ===== Worst-case MUST stay sub-linear =====
assertUnder("applyRedaction 100k prose + 1 b64 token", () => applyRedaction({
  type: "tool_result",
  toolName: "bash",
  toolCallId: "x",
  input: { command: "echo" },
  content: [{ type: "text", text: text100k_b64 }],
  isError: false,
  details: {},
}, ctx), 50);

console.log(`\n${pass}/${pass + fail} perf tests passed`);
process.exit(fail > 0 ? 1 : 0);
