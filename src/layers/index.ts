// Layer Registry — orchestriert alle Layer

import type { RedactionContext, LayerResult, Match } from "../types.js";
import * as layer1 from "./layer-1-vendor.js";
import * as layer2 from "./layer-2-pem.js";
import * as layer3 from "./layer-3-prefix.js";
import * as layer4 from "./layer-4-entropy.js";
import * as layer5 from "./layer-5-asn1.js";
import * as layer6 from "./layer-6-context.js";
import * as layer7 from "./layer-7-path.js";
import * as layer8 from "./layer-8-pii.js";
import * as layer9 from "./layer-9-10-connection.js";
import { applyMatches } from "./shared.js";

interface Layer {
  id: keyof RedactionContext["config"]["layers"];
  apply: (text: string, ctx: RedactionContext) => LayerResult;
}

const ALL_LAYERS: Layer[] = [
  { id: "vendor", apply: layer1.apply },
  { id: "prefix", apply: layer3.apply },
  { id: "pem", apply: layer2.apply },
  { id: "asn1", apply: layer5.apply },
  { id: "context", apply: layer6.apply },
  { id: "connection", apply: layer9.apply },
  { id: "path", apply: layer7.apply },
  { id: "pii", apply: layer8.apply },
  { id: "entropy", apply: layer4.apply },
];

export function redactText(text: string, ctx: RedactionContext): { text: string; matches: Match[] } {
  let current = text;
  const allMatches: Match[] = [];

  for (const layer of ALL_LAYERS) {
    if (!ctx.config.layers[layer.id]) continue;

    const result = layer.apply(current, ctx);
    if (result.matches.length === 0) continue;

    // Apply this layer's matches to current
    current = applyMatches(current, result.matches);
    allMatches.push(...result.matches);
  }

  return { text: current, matches: allMatches };
}