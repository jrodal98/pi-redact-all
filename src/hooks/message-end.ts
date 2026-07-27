// message_end hook — Last-line defense for Assistant-Messages

import { redactText } from "../layers/index.js";
import type { RedactionContext } from "../types.js";

export interface MessageEndLike {
  type: "message_end";
  message: {
    role: string;
    content: unknown;
  };
}

export interface MessageEndResult {
  message?: {
    role: string;
    content: unknown;
  };
}

/**
 * Filter assistant message content before it's added to context.
 * Catches any leaks that slipped past tool_result hooks.
 */
export function filterMessage(
  event: MessageEndLike,
  ctx: RedactionContext
): MessageEndResult {
  if (ctx.config.mode === "off") return {};
  if (ctx.config.toolPolicy.whitelist.includes(event.message.role)) return {};

  // Only filter assistant messages — user input is filtered separately
  if (event.message.role !== "assistant") return {};

  const result = redactMessageContent(event.message.content, ctx);
  if (!result.changed) return {};

  return {
    message: {
      role: event.message.role,
      content: result.content,
    },
  };
}

function redactMessageContent(
  content: unknown,
  ctx: RedactionContext,
  depth = 0
): { content: unknown; changed: boolean } {
  if (depth > 20) return { content, changed: false };

  if (typeof content === "string") {
    const result = redactText(content, ctx);
    return {
      content: result.matches.length > 0 ? result.text : content,
      changed: result.matches.length > 0,
    };
  }

  if (Array.isArray(content)) {
    let changed = false;
    const newContent = content.map((item) => {
      const r = redactMessageContent(item, ctx, depth + 1);
      if (r.changed) changed = true;
      return r.content;
    });
    return { content: newContent, changed };
  }

  if (content && typeof content === "object") {
    const result: Record<string, unknown> = {};
    let changed = false;
    for (const [k, v] of Object.entries(content)) {
      const r = redactMessageContent(v, ctx, depth + 1);
      if (r.changed) changed = true;
      result[k] = r.content;
    }
    return { content: result, changed };
  }

  return { content, changed: false };
}