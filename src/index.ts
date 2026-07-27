// pi-redact-all — Extension entry point
// Hooks: tool_result (PostToolUse), tool_call (PreToolUse Block),
//        before_agent_start (User-Input Filter), message_end (Last Line),
//        before_provider_request (Final Defense)

import { loadConfig } from "./config.js";
import { createSessionStats, recordMatches, recordBlock, formatStats } from "./stats.js";
import { applyRedaction, type ToolResultLike } from "./hooks/tool-result.js";
import { shouldBlock, inputContainsSensitiveSecrets } from "./hooks/tool-call.js";
import { filterUserPrompt, filterProviderPayload, type BeforeAgentStartLike, type BeforeProviderRequestLike } from "./hooks/before-provider.js";
import { filterMessage, type MessageEndLike } from "./hooks/message-end.js";
import { redactText } from "./layers/index.js";
import type { RedactionContext } from "./types.js";

/**
 * Minimal Pi Extension API contract that we depend on.
 * The real Pi runtime provides this — we just use the parts we need.
 */
interface ExtensionAPI {
  on(event: string, handler: (...args: unknown[]) => unknown): void;
  registerCommand(name: string, config: { description: string; handler: (args: string, ctx: unknown) => Promise<string> | string }): void;
}

/**
 * Default export — Pi calls this with the ExtensionAPI.
 */
export default function (pi: ExtensionAPI) {
  const config = loadConfig();
  const stats = createSessionStats();
  const partialPrivateKeyPaths = new Set<string>();

  const makeContext = (toolName?: string, input?: Record<string, unknown>): RedactionContext => ({
    config,
    partialPrivateKeyPaths,
    toolName,
    inputPath: input ? (input.path as string) : undefined,
    command: input ? (input.command as string) : undefined,
  });

  // ──────────────────────────────────────────────────────────────
  // POST-TOOL HOOK: Redact tool output before it reaches the LLM
  // ──────────────────────────────────────────────────────────────
  pi.on("tool_result", async (event: unknown) => {
    const e = event as ToolResultLike;
    const ctx = makeContext(e.toolName, e.input);
    const result = applyRedaction(e, ctx);

    // Track partial private key paths
    if (e.toolName === "read" && ctx.inputPath) {
      const textItem = e.content.find((c) => c.type === "text");
      if (textItem && textItem.type === "text") {
        if (/-----BEGIN[ \t]+[\w -]*PRIVATE[ \t]+KEY-----/.test(textItem.text) &&
            !/-----END[ \t]+[\w -]*PRIVATE[ \t]+KEY-----/.test(textItem.text)) {
          partialPrivateKeyPaths.add(ctx.inputPath);
        } else if (/-----END[ \t]+[\w -]*PRIVATE[ \t]+KEY-----/.test(textItem.text)) {
          partialPrivateKeyPaths.delete(ctx.inputPath);
        }
      }
    }

    // Stats: count via length delta as approximation
    if (result.content) {
      let totalMatches = 0;
      for (let i = 0; i < e.content.length; i++) {
        const orig = e.content[i];
        const mod = result.content[i];
        if (orig.type === "text" && mod.type === "text" && orig.text !== mod.text) {
          const scanResult = redactText(orig.text, ctx);
          totalMatches += scanResult.matches.length;
        }
      }
      if (totalMatches > 0) {
        recordMatches(
          stats,
          Array(totalMatches).fill({ start: 0, end: 0, type: "unknown", replacement: "" }),
          e.toolName
        );
      }
    }

    return result;
  });

  // ──────────────────────────────────────────────────────────────
  // PRE-TOOL HOOK: Block sensitive tool calls
  // ──────────────────────────────────────────────────────────────
  pi.on("tool_call", async (event: unknown) => {
    const e = event as ToolResultLike;
    const blockResult = shouldBlock({ toolName: e.toolName, input: e.input }, config);
    if (blockResult) {
      recordBlock(stats);
      return blockResult;
    }
    const inputBlock = inputContainsSensitiveSecrets({ toolName: e.toolName, input: e.input }, config);
    if (inputBlock) {
      recordBlock(stats);
      return inputBlock;
    }
    return undefined;
  });

  // ──────────────────────────────────────────────────────────────
  // USER-INPUT HOOK: Filter user prompt before agent loop starts
  // ──────────────────────────────────────────────────────────────
  pi.on("before_agent_start", async (event: unknown) => {
    const e = event as BeforeAgentStartLike;
    const ctx = makeContext("user_input");
    const result = filterUserPrompt(e, ctx);
    if (result.prompt && result.prompt !== e.prompt) {
      const scanResult = redactText(e.prompt, ctx);
      if (scanResult.matches.length > 0) {
        recordMatches(
          stats,
          scanResult.matches,
          "user_input"
        );
      }
    }
    return result;
  });

  // ──────────────────────────────────────────────────────────────
  // ASSISTANT-MESSAGE HOOK: Last-line filter for assistant output
  // DISABLED BY DEFAULT: AgentMessage is a union-type (custom/bashExecution/
  // branchSummary/compactionSummary + user/assistant/toolResult). Returning
  // {role, content} breaks the schema for custom message types and causes
  // provider 400 errors. Enable only via config after schema-aware re-implementation.
  // ──────────────────────────────────────────────────────────────
  // pi.on("message_end", async (event: unknown) => { ... });

  // ──────────────────────────────────────────────────────────────
  // PROVIDER-PAYLOAD HOOK: Final defense before HTTP call to LLM
  // DISABLED BY DEFAULT: payload is `unknown` and providers reject 400 if
  // schema is violated. Re-enable only with proper schema-aware mutation
  // (in-place, not return-value).
  // ──────────────────────────────────────────────────────────────
  // pi.on("before_provider_request", async (event: unknown) => { ... });

  // ──────────────────────────────────────────────────────────────
  // COMMANDS
  // ──────────────────────────────────────────────────────────────
  pi.registerCommand("redact-all-stats", {
    description: "Show pi-redact-all session statistics",
    handler: () => formatStats(stats),
  });

  pi.registerCommand("redact-all-config", {
    description: "Show current pi-redact-all configuration",
    handler: () => JSON.stringify(config, null, 2),
  });
}