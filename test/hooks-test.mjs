// Schema-aware hook tests — verify that message_end and before_provider_request
// preserve the original message/payload shape and only mutate text where appropriate.

import { filterMessage } from "../dist/hooks/message-end.js";
import { filterProviderPayload } from "../dist/hooks/before-provider.js";
import { DEFAULT_CONFIG } from "../dist/config.js";

const ctx = {
  config: { ...DEFAULT_CONFIG, pii: true },
  partialPrivateKeyPaths: new Set(),
};

let pass = 0;
let fail = 0;

function assert(name, condition, detail) {
  if (condition) {
    pass++;
    console.log(`✅ ${name}`);
  } else {
    fail++;
    console.log(`❌ ${name}`);
    if (detail) console.log(`   ${detail}`);
  }
}

// ─────────────────────────────────────────────────────────────
// message_end tests
// ─────────────────────────────────────────────────────────────

// Test 1: user message with text content → redacted, schema preserved
{
  const event = {
    type: "message_end",
    message: {
      role: "user",
      content: "Token: ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa",
      timestamp: 1234567890,
    },
  };
  const result = filterMessage(event, ctx);
  assert(
    "user message: text redacted",
    String(result.message?.content || "").includes("[REDACTED"),
    `Got: ${JSON.stringify(result)}`
  );
  assert(
    "user message: timestamp preserved",
    result.message?.timestamp === 1234567890,
    `Got: ${JSON.stringify(result.message)}`
  );
  assert(
    "user message: role preserved",
    result.message?.role === "user"
  );
}

// Test 2: custom message with customType/display/details/timestamp → preserved
{
  const event = {
    type: "message_end",
    message: {
      role: "custom",
      customType: "bashExecution",
      content: "Token: ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa",
      display: true,
      details: { exitCode: 0 },
      timestamp: 9876543210,
    },
  };
  const result = filterMessage(event, ctx);
  assert(
    "custom message: customType preserved",
    result.message?.customType === "bashExecution",
    `Got message keys: ${Object.keys(result.message || {}).join(", ")}`
  );
  assert(
    "custom message: display preserved",
    result.message?.display === true
  );
  assert(
    "custom message: details preserved",
    JSON.stringify(result.message?.details) === '{"exitCode":0}'
  );
  assert(
    "custom message: timestamp preserved",
    result.message?.timestamp === 9876543210
  );
  assert(
    "custom message: content redacted",
    String(result.message?.content || "").includes("[REDACTED")
  );
}

// Test 3: bashExecution message → pass through (no redaction, no schema change)
{
  const event = {
    type: "message_end",
    message: {
      role: "bashExecution",
      command: "cat secret",
      output: "ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa",
      exitCode: 0,
      cancelled: false,
      truncated: false,
      timestamp: 5555555555,
    },
  };
  const result = filterMessage(event, ctx);
  assert(
    "bashExecution: not modified (passes through)",
    result.message === undefined || JSON.stringify(result.message) === JSON.stringify(event.message)
  );
}

// Test 4: branchSummary → pass through
{
  const event = {
    type: "message_end",
    message: {
      role: "branchSummary",
      summary: "Branch summary with token ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa",
      fromId: "abc-123",
      timestamp: 1111111111,
    },
  };
  const result = filterMessage(event, ctx);
  assert(
    "branchSummary: not modified",
    result.message === undefined,
    `Got: ${JSON.stringify(result)}`
  );
}

// Test 5: compactionSummary → pass through
{
  const event = {
    type: "message_end",
    message: {
      role: "compactionSummary",
      summary: "ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa",
      tokensBefore: 50000,
      timestamp: 2222222222,
    },
  };
  const result = filterMessage(event, ctx);
  assert(
    "compactionSummary: not modified",
    result.message === undefined
  );
}

// Test 6: assistant message with content array → redacted, schema preserved
{
  const event = {
    type: "message_end",
    message: {
      role: "assistant",
      content: [
        { type: "text", text: "I see your API key ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa" },
        { type: "text", text: "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END CERTIFICATE-----" },
      ],
      timestamp: 3333333333,
      model: "test-model",
      usage: { inputTokens: 10, outputTokens: 5 },
    },
  };
  const result = filterMessage(event, ctx);
  assert(
    "assistant: content array redacted",
    Array.isArray(result.message?.content) &&
      String(result.message.content[0].text || "").includes("[REDACTED")
  );
  assert(
    "assistant: model preserved",
    result.message?.model === "test-model",
    `Got message keys: ${Object.keys(result.message || {}).join(", ")}`
  );
  assert(
    "assistant: usage preserved",
    JSON.stringify(result.message?.usage) === '{"inputTokens":10,"outputTokens":5}'
  );
}

// ─────────────────────────────────────────────────────────────
// before_provider_request tests
// ─────────────────────────────────────────────────────────────

// Test 7: in-place mutation of nested message
{
  const payload = {
    messages: [
      {
        role: "user",
        content: [
          { type: "text", text: "Token: ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa" },
        ],
      },
    ],
    model: "test-model",
    max_tokens: 100,
  };
  const originalRef = payload.messages[0].content[0].text;
  filterProviderPayload({ type: "before_provider_request", payload }, ctx);
  assert(
    "before_provider: text redacted in-place",
    String(payload.messages[0].content[0].text || "").includes("[REDACTED"),
    `Got: ${payload.messages[0].content[0].text}`
  );
  assert(
    "before_provider: model preserved",
    payload.model === "test-model"
  );
  assert(
    "before_provider: max_tokens preserved (not a string)",
    payload.max_tokens === 100
  );
  assert(
    "before_provider: object identity preserved (no return value)",
    payload.messages[0].content[0].text !== originalRef || String(originalRef).includes("[REDACTED")
  );
}

// Test 8: preserves class instances / functions
{
  class CustomProvider {
    methodName() { return "test"; }
  }
  const payload = {
    provider: new CustomProvider(),
    config: { apiKey: "test" },
    data: "ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa",
  };
  const providerInstance = payload.provider;
  filterProviderPayload({ type: "before_provider_request", payload }, ctx);
  assert(
    "before_provider: class instance preserved",
    payload.provider === providerInstance
  );
  assert(
    "before_provider: data string redacted",
    String(payload.data || "").includes("[REDACTED")
  );
}

// Test 9: no return value (relies on in-place mutation)
{
  const payload = { messages: [] };
  const result = filterProviderPayload({ type: "before_provider_request", payload }, ctx);
  assert(
    "before_provider: returns void/undefined",
    result === undefined
  );
}

console.log(`\n${pass}/${pass + fail} tests passed`);
process.exit(fail > 0 ? 1 : 0);