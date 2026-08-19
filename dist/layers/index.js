// Layer Registry — orchestriert alle Layer
import * as layer1 from "./layer-1-vendor.js";
import * as layer2 from "./layer-2-pem.js";
import * as layer3 from "./layer-3-prefix.js";
import * as layer4 from "./layer-4-entropy.js";
import * as layer5 from "./layer-5-asn1.js";
import * as layer6 from "./layer-6-context.js";
import * as layer7 from "./layer-7-path.js";
import * as layer8 from "./layer-8-pii.js";
import * as layer9 from "./layer-9-10-connection.js";
import * as layerCustom from "./layer-custom.js";
import { applyMatches, isAllowlistedLiteralOrEnv } from "./shared.js";
const ALL_LAYERS = [
    { id: "path", apply: layer7.apply },
    { id: "custom", apply: layerCustom.apply },
    { id: "vendor", apply: layer1.apply },
    { id: "prefix", apply: layer3.apply },
    { id: "pem", apply: layer2.apply },
    { id: "asn1", apply: layer5.apply },
    { id: "context", apply: layer6.apply },
    { id: "connection", apply: layer9.apply },
    { id: "pii", apply: layer8.apply },
    { id: "entropy", apply: layer4.apply },
];
export function redactText(text, ctx) {
    // Graceful handling of null/undefined/empty
    if (!text || typeof text !== "string") {
        return { text: "", matches: [] };
    }
    // Hot-path fast-exit: skip obviously-too-short texts. The smallest vendor
    // token in the registry is ~11 chars (e.g. npm_ + 8, BSA + 20, fc- + 32,
    // tk_ + 20). A threshold of 16 preserves the win on tiny tool outputs
    // ("ok", "success", short file listings) while ensuring vendor/ntfy
    // tokens of 20-31 chars are still scanned — the previous guard used
    // `minLength` (32 by default) which incorrectly blocked standalone tk_
    // / AKIA / sk- tokens that are shorter than the entropy layer's threshold.
    // Per-layer length checks (entropy's minLength, pii regexes, etc.) still
    // gate the expensive paths; this is just the cheap global short-circuit.
    const hasCustom = ctx.config.layers.custom && ((ctx.config.blocklistRegex?.length ?? 0) > 0 ||
        (ctx.config.blocklistLiteral?.length ?? 0) > 0 ||
        (ctx.config.blocklistEnv?.length ?? 0) > 0 ||
        (ctx.config.customRegex?.length ?? 0) > 0 ||
        (ctx.config.customLiterals?.length ?? 0) > 0 ||
        (ctx.config.envVars?.length ?? 0) > 0);
    const threshold = hasCustom ? 2 : 16;
    if (text.length < threshold) {
        return { text, matches: [] };
    }
    let current = text;
    const allMatches = [];
    for (const layer of ALL_LAYERS) {
        if (!ctx.config.layers[layer.id])
            continue;
        const result = layer.apply(current, ctx);
        if (result.matches.length === 0)
            continue;
        let matches = result.matches;
        if (ctx.config.allowlistLiteral?.length || ctx.config.allowlistEnv?.length) {
            matches = matches.filter((m) => {
                const val = current.slice(m.start, m.end);
                return !isAllowlistedLiteralOrEnv(val, ctx);
            });
            if (matches.length === 0)
                continue;
        }
        current = applyMatches(current, matches);
        allMatches.push(...matches);
    }
    return { text: current, matches: allMatches };
}
//# sourceMappingURL=index.js.map