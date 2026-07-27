// before_agent_start + before_provider_request hooks
//
// Two responsibilities:
//   1. filterUserPrompt: Filter user prompt before agent loop (before_agent_start)
//   2. filterProviderPayload: Final defense before HTTP call to LLM (before_provider_request)
//
// For before_provider_request: payload structure is provider-specific and opaque.
// We CANNOT safely return a modified payload object — it may have:
//   - Class instances with methods
//   - Streams/Buffers
//   - Strict schema validation
//   - Provider-specific structure (OpenAI, Anthropic, etc. differ)
//
// Strategy: Detect the messages-array location and mutate strings IN-PLACE.
// If we can't safely identify the structure, we pass through untouched.

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
 * Best-effort final defense: mutate text strings in-place within the payload.
 * Returns nothing — relies on mutation (similar to before_provider_headers).
 */
export function filterProviderPayload(
  event: BeforeProviderRequestLike,
  ctx: RedactionContext
): void {
  if (ctx.config.mode === "off") return;
  if (!event.payload) return;

  // Recursively walk and mutate string values in place
  redactInPlace(event.payload, ctx, 0);
}

/**
 * Recursively walk an object/array and mutate string values in place.
 * Stops at depth > 20 to prevent runaway traversal.
 */
function redactInPlace(value: unknown, ctx: RedactionContext, depth: number): void {
  if (depth > 20) return;

  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const item = value[i];
      if (typeof item === "string") {
        const result = redactText(item, ctx);
        if (result.matches.length > 0) {
          value[i] = result.text;
        }
      } else if (item && typeof item === "object") {
        redactInPlace(item, ctx, depth + 1);
      }
    }
    return;
  }

  if (value && typeof value === "object") {
    // Walk own enumerable properties (skip prototype chain, methods, etc.)
    const obj = value as Record<string, unknown>;
    for (const key of Object.keys(obj)) {
      // Skip non-data properties (functions, getters, symbols)
      const descriptor = Object.getOwnPropertyDescriptor(obj, key);
      if (!descriptor || typeof descriptor.value === "function") continue;

      const v = obj[key];
      if (typeof v === "string") {
        const result = redactText(v, ctx);
        if (result.matches.length > 0) {
          obj[key] = result.text;
        }
      } else if (v && (Array.isArray(v) || typeof v === "object")) {
        redactInPlace(v, ctx, depth + 1);
      }
    }
  }
}