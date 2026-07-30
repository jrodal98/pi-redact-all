// Regression tests for v0.1.6 — Real image data preservation
//
// Bug: image base64 inside Anthropic image.source.data was being corrupted
// because the Anthropic source object itself has `type: "base64"` and
// `data: "<...>"` fields. When redactInPlace descended into the source
// object, the `isProtectedImageKey` checks failed:
//
//   - check 1 looked for `parent.source` — but parent IS the source object
//   - check 2 looked for `parent.type === "image"` — but parent.type is
//     "base64", not "image"
//
// Net effect: the entropy layer matched the long base64 token, found
// vendor prefixes (AKIA, ghp_, etc.) embedded in random image bytes, and
// replaced them with `[REDACTED:...]` markers. Anthropic then rejected
// the request with HTTP 400:
//
//   invalid_request_error: invalid param: decode base64 data url:
//   illegal base64 data at input byte 4 (2013)
//
// v0.1.6 adds a recognition check for being INSIDE the Anthropic source
// object: when `parent.type === "base64"` AND `parent.media_type` is a
// string, the `data` field is protected.
//
// These tests use deterministic base64 tokens (built from repeating chars)
// that *would* trigger entropy, vendor and PEM layers if the protection
// is removed. They verify the protection is in place across all three
// hook paths: tool_result, message_end, and before_provider_request.

import assert from "node:assert/strict";
import { applyRedaction } from "../dist/hooks/tool-result.js";
import { filterProviderPayload } from "../dist/hooks/before-provider.js";
import { filterMessage } from "../dist/hooks/message-end.js";
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

// Build deterministic base64-like payloads that *should* trigger every
// layer if the protection is removed:
//
//   "iVBOR..."  — real PNG header (every layer is fine with this)
//   "AKIA****" — would be flagged by Layer 1 vendor as AWS Access Key
//   "-----BEGIN...PRIVATE KEY-----" — Layer 2 PEM
//   "xoxb-..."  — Layer 1 vendor Slack Bot Token
//   "ghp_..."   — Layer 1 vendor GitHub Token
//
// These are exactly the patterns the v0.1.4 protection handled, but in a
// way that only worked when the data was at the TOP level (Pi internal
// `{type:"image", data:"<b64>"}` form). The v0.1.6 fix extends the same
// protection to nested Anthropic format AND adds the real-world byte-4
// reproducer.
const realB64 = "iVBORw0KGgoAAAANSUhEUgAAB4AAAAQICAYAAADsqcbuAAAAAXNSR0IArs4c";
const trap = "AKIAIOSFODNN7EXAMPLE" + // Layer 1 vendor — would be redacted
             "xoxb-1234567890123456789012" + // Layer 1 vendor
             "ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa" + // Layer 1 vendor
             "-----BEGIN RSA PRIVATE KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END RSA PRIVATE KEY-----" + // Layer 2 PEM
             "B".repeat(3000); // Padding to make it a long token
const evilB64 = realB64 + trap;
const evilB64Len = evilB64.length;

// ===== Reported bug — Anthropic image.source.data MUST NOT be modified =====
test("Reported bug: Anthropic image.source.data preserved bytewise", () => {
  const payload = {
    model: "claude-sonnet-4-5",
    messages: [
      { role: "user", content: [
        { type: "tool_use", id: "tu-1", name: "read", input: { path: "/tmp/img.png" } },
      ]},
      { role: "user", content: [
        { type: "tool_result", tool_use_id: "tu-1", content: [
          { type: "image", source: { type: "base64", media_type: "image/png", data: evilB64 } },
        ]}
      ]}
    ],
  };
  filterProviderPayload({ type: "before_provider_request", payload }, ctx);
  const actual = payload.messages[1].content[0].content[0].source.data;
  assert.equal(actual, evilB64,
    `Anthropic image.source.data must be unchanged bytewise (was ${actual.length}, expected ${evilB64Len})`);
});

// ===== Pi internal format =====
test("Pi internal: {type:'image', data, mimeType} preserved", () => {
  const payload = {
    messages: [
      { role: "user", content: [{ type: "image", data: evilB64, mimeType: "image/png" }] }
    ]
  };
  filterProviderPayload({ type: "before_provider_request", payload }, ctx);
  const actual = payload.messages[0].content[0].data;
  assert.equal(actual, evilB64);
});

// ===== Same structure as Anthropic conversion output (tool result content) =====
test("Tool result content with Anthropic-format image: data preserved", () => {
  const event = {
    type: "tool_result",
    toolName: "read",
    toolCallId: "tc-1",
    input: { path: "/tmp/img.png" },
    content: [
      { type: "text", text: "Read image file [image/png]" },
      {
        type: "image",
        source: { type: "base64", media_type: "image/png", data: evilB64 }
      },
    ],
    isError: false,
  };
  const result = applyRedaction(event, ctx);
  const items = result.content || event.content;
  // applyRedaction only processes text items — image items pass through.
  // So the data should be unchanged at this layer. (verify it's still
  // unchanged after the tool_result hook.)
  const imgItem = items.find((i) => i.type === "image");
  assert.equal(imgItem.source.data, evilB64, "tool_result hook must not modify image data");
});

// ===== message_end on toolResult role =====
test("message_end toolResult role: image data preserved through schema pass-through", () => {
  const event = {
    type: "message_end",
    message: {
      role: "toolResult",
      toolCallId: "tc-1",
      toolName: "read",
      content: [
        {
          type: "image",
          source: { type: "base64", media_type: "image/png", data: evilB64 }
        }
      ],
      isError: false,
      timestamp: 1234567890,
    },
  };
  filterMessage(event, ctx);
  // toolResult passes through (returns {}). The data must still be intact.
  assert.equal(event.message.content[0].source.data, evilB64);
});

// ===== End-to-end Anthropic chain through message_end + provider payload =====
test("End-to-end: toolResult -> message_end -> before_provider_request preserves data", () => {
  // Simulate pi's runtime path:
  // 1. tool_result hook fires with image content
  // 2. message_end fires with the resulting toolResult message
  // 3. before_provider_request fires with the provider-format payload
  const tr = {
    type: "tool_result",
    toolName: "read",
    toolCallId: "tc-e2e",
    input: { path: "/tmp/img.png" },
    content: [
      { type: "image", source: { type: "base64", media_type: "image/png", data: evilB64 } }
    ],
    isError: false,
  };
  const trResult = applyRedaction(tr, ctx);
  // The tool_result hook doesn't touch image items, so the content is
  // preserved. Simulate the rest of the pipeline:
  const meEvent = {
    type: "message_end",
    message: {
      role: "toolResult",
      toolCallId: tr.toolCallId,
      toolName: tr.toolName,
      content: (trResult.content || tr.content),
      isError: false,
      timestamp: 1234567890,
    },
  };
  filterMessage(meEvent, ctx);
  const bprPayload = {
    messages: [
      { role: "toolResult", toolCallId: "tc-e2e", toolName: "read",
        content: meEvent.message.content,
        isError: false, timestamp: 1234567890 }
    ]
  };
  filterProviderPayload({ type: "before_provider_request", payload: bprPayload }, ctx);
  const finalData = bprPayload.messages[0].content[0].source.data;
  assert.equal(finalData, evilB64,
    `End-to-end chain must preserve data bytewise (got len ${finalData.length}, expected ${evilB64Len})`);
});

// (Negative tests for plain `data` fields without image envelope live in
// test/image-payload-v0.1.4.test.mjs already; not duplicated here.)
console.log(`\n${pass}/${pass + fail} tests passed`);
process.exit(fail > 0 ? 1 : 0);