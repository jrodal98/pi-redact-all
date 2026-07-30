// Regression tests for v0.1.4 — image payload preservation
//
// Bug: redactInPlace() in before-provider.ts naively descended into
// `image.source.data` (long base64 string). Layer 4 entropy + Layer 2 PEM
// regexes matched on the encoded bytes and replaced them with a redacted
// marker. The provider then rejected the request with HTTP 400
// "invalid image content: decode image config: image: unknown format (2013)".
//
// These tests verify that v0.1.4+ preserves multimodal payloads across every
// provider shape we know about, while still redacting ordinary `data`-like
// fields on unrelated payloads.

import assert from "node:assert/strict";
import { filterProviderPayload } from "../dist/hooks/before-provider.js";
import { loadConfig } from "../dist/config.js";

const ctx = { config: loadConfig(), partialPrivateKeyPaths: new Set() };
let pass = 0, fail = 0;
function test(name, fn) {
  try { fn(); console.log(`✅ ${name}`); pass++; }
  catch (e) { console.log(`❌ ${name}: ${e.message}`); fail++; }
}

// --- Realistic provider payload shapes ---------------------------------

// Minimal but valid base64-ish string — long enough to trigger entropy and
// PEM-style regexes; we don't care if it actually decodes because the bug
// happened BEFORE decoding reached the server.
const bigB64 = "A".repeat(800) + "ABCD" + "B".repeat(800) + "==";

// Anthropic Messages: image in a user message content block.
test("Anthropic: image.source.data preserved (base64 bytes intact)", () => {
  const payload = {
    model: "MiniMax-M3",
    messages: [
      {
        role: "user",
        content: [
          {
            type: "image",
            source: { type: "base64", media_type: "image/png", data: bigB64 },
          },
          { type: "text", text: "describe the image" },
        ],
      },
    ],
  };
  filterProviderPayload({ type: "before_provider_request", payload }, ctx);
  const actual = payload.messages[0].content[0].source.data;
  assert.equal(actual, bigB64, "base64 bytes must be unchanged");
});

// Pi internal: image ContentItem with data + mimeType fields.
test("Pi internal: image.data preserved", () => {
  const payload = {
    messages: [
      {
        role: "user",
        content: [{ type: "image", data: bigB64, mimeType: "image/png" }],
      },
    ],
  };
  filterProviderPayload({ type: "before_provider_request", payload }, ctx);
  const actual = payload.messages[0].content[0].data;
  assert.equal(actual, bigB64, "Pi image.data must be unchanged");
});

// OpenAI Chat Completions: image_url with a data: URI inside.
test("OpenAI Chat: image_url object preserved", () => {
  const url = `data:image/png;base64,${bigB64}`;
  const payload = {
    messages: [
      {
        role: "user",
        content: [{ type: "image_url", image_url: { url } }],
      },
    ],
  };
  filterProviderPayload({ type: "before_provider_request", payload }, ctx);
  const actual = payload.messages[0].content[0].image_url.url;
  assert.equal(actual, url, "image_url.url must be unchanged");
});

// OpenAI Responses: input_image with a URL field (data URI).
test("OpenAI Responses: input_image preserved", () => {
  const url = `data:image/jpeg;base64,${bigB64}`;
  const payload = {
    input: [{ role: "user", content: [{ type: "input_image", image_url: url }] }],
  };
  filterProviderPayload({ type: "before_provider_request", payload }, ctx);
  const actual = payload.input[0].content[0].image_url;
  assert.equal(actual, url, "input_image.image_url must be unchanged");
});

// Google: inline_data wrapper.
test("Google: inlineData.data preserved", () => {
  const payload = {
    contents: [
      {
        role: "user",
        parts: [{ inlineData: { mimeType: "image/png", data: bigB64 } }],
      },
    ],
  };
  filterProviderPayload({ type: "before_provider_request", payload }, ctx);
  const actual = payload.contents[0].parts[0].inlineData.data;
  assert.equal(actual, bigB64, "Google inlineData.data must be unchanged");
});

// OpenAI generated-image response: b64_json field.
test("OpenAI image-generation: b64_json preserved", () => {
  const payload = { data: [{ b64_json: bigB64 }] };
  filterProviderPayload({ type: "before_provider_request", payload }, ctx);
  const actual = payload.data[0].b64_json;
  assert.equal(actual, bigB64, "b64_json must be unchanged");
});

// --- Negative: ordinary data fields on non-multimodal objects STILL get redacted.

test("Plain `data` field at arbitrary depth is still redacted", () => {
  const payload = {
    someRandomApiObject: { data: "ghp_FAKE-TOKEN-FOR-TEST-ONLY-NOT-REAL-aaaaaaaaaaaa" },
  };
  filterProviderPayload({ type: "before_provider_request", payload }, ctx);
  const actual = payload.someRandomApiObject.data;
  assert.notEqual(actual, "ghp_FAKE-TOKEN-FOR-TEST-ONLY-NOT-REAL-aaaaaaaaaaaa");
  assert.match(actual, /\[REDACTED/);
});

// Data URI URL strings anywhere in the payload are preserved as a unit.
test("Stand-alone data: URL string is preserved (not redacted character-by-character)", () => {
  const payload = {
    references: [`data:image/png;base64,${bigB64}`],
  };
  filterProviderPayload({ type: "before_provider_request", payload }, ctx);
  const actual = payload.references[0];
  assert.equal(actual, `data:image/png;base64,${bigB64}`);
});

// Deeply nested multimodal content blocks survive the recursion.
test("Deeply nested image blocks survive", () => {
  const payload = {
    messages: [
      {
        role: "user",
        content: [
          {
            type: "tool_result",
            tool_use_id: "tc1",
            content: [
              { type: "text", text: "Read image file [image/png]" },
              { type: "image", data: bigB64, mimeType: "image/png" },
            ],
          },
        ],
      },
    ],
  };
  filterProviderPayload({ type: "before_provider_request", payload }, ctx);
  const inner = payload.messages[0].content[0].content[1];
  assert.equal(inner.data, bigB64, "nested image.data must be unchanged");
});

// The text/plain sibling of an image block IS still redacted (text fields are
// not in the protected set).
test("Text siblings of images are still redacted", () => {
  const payload = {
    messages: [
      {
        role: "user",
        content: [
          { type: "image", source: { type: "base64", media_type: "image/png", data: bigB64 } },
          { type: "text", text: "my token is ghp_FAKE-TOKEN-FOR-TEST-ONLY-NOT-REAL-aaaaaaaaaaaa" },
        ],
      },
    ],
  };
  filterProviderPayload({ type: "before_provider_request", payload }, ctx);
  const text = payload.messages[0].content[1].text;
  assert.match(text, /\[REDACTED/, "text siblings must still be redacted");
});

console.log(`\n${pass}/${pass + fail} tests passed`);
process.exit(fail > 0 ? 1 : 0);
