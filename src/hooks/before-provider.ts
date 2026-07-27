// before_agent_start + before_provider_request hooks — User-Input filtering

import { redactText } from "../layers/index.js";
import type { RedactionContext } from "../types.js";

export interface BeforeAgentStartLike {
  type: "before_agent_start";
  prompt: string;
  images?: unknown;
}

export interface BeforeAgentStartResult {
  prompt?: string;
}

export interface BeforeProviderRequestLike {
  type: "before_provider_request";
  payload: unknown;
}

/**
 * Filter the user prompt before the agent loop starts.
 * This catches User-Input before it enters the conversation.
 */
export function filterUserPrompt(
  event: BeforeAgentStartLike,
  ctx: RedactionContext
): BeforeAgentStartResult {
  if (ctx.config.mode === "off") return {};
  if (ctx.config.toolPolicy.whitelist.includes("user_input")) return {};

  const result = redactText(event.prompt, { ...ctx, toolName: "user_input" });
  if (result.matches.length === 0) return {};

  return { prompt: result.text };
}

/**
 * Filter the full provider request payload before sending to LLM.
 * This is the LAST line of defense — catches everything that reached
 * the provider payload (user input + tool results + system prompt).
 */
export function filterProviderPayload(
  event: BeforeProviderRequestLike,
  ctx: RedactionContext
): BeforeProviderRequestLike {
  if (ctx.config.mode === "off") return event;
  if (!event.payload) return event;

  // Walk the payload and redact string values
  const redacted = redactJsonValue(event.payload, ctx);
  return { ...event, payload: redacted };
}

/**
 * Recursively redact all string values in a JSON-like object.
 */
function redactJsonValue(value: unknown, ctx: RedactionContext, depth = 0): unknown {
  // Prevent infinite recursion
  if (depth > 20) return value;

  if (typeof value === "string") {
    const result = redactText(value, ctx);
    return result.matches.length > 0 ? result.text : value;
  }

  if (Array.isArray(value)) {
    return value.map((v) => redactJsonValue(v, ctx, depth + 1));
  }

  if (value && typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      result[k] = redactJsonValue(v, ctx, depth + 1);
    }
    return result;
  }

  return value;
}