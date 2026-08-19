// Config loader for pi-redact-all
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
export const DEFAULT_CONFIG = {
    mode: "mask",
    blockMode: false,
    streamingRedaction: false,
    toolPolicy: {
        whitelist: [],
        blacklist: [],
    },
    layers: {
        vendor: true,
        pem: true,
        prefix: true,
        entropy: true,
        asn1: true,
        context: true,
        path: true,
        pii: false,
        connection: true,
        custom: true,
    },
    allowlistRegex: [
        "\\b[a-f0-9]{40}\\b",
        "\\b[0-9a-f]{7,40}\\b",
    ],
    allowlistLiteral: [],
    allowlistEnv: [],
    blocklistRegex: [],
    blocklistLiteral: [],
    blocklistEnv: [],
    customRegex: [],
    customLiterals: [],
    envVars: [],
    minEntropy: 4.5,
    minLength: 32,
    preservePrefixChars: 4,
    asterisksMax: 20,
};
export function loadConfig() {
    const configPath = join(homedir(), ".pi", "agent", "pi-redact-all.json");
    if (!existsSync(configPath))
        return { ...DEFAULT_CONFIG };
    try {
        const raw = readFileSync(configPath, "utf-8");
        const user = JSON.parse(raw);
        return mergeConfig(DEFAULT_CONFIG, user);
    }
    catch (err) {
        console.error(`[pi-redact-all] Failed to load config at ${configPath}:`, err);
        return { ...DEFAULT_CONFIG };
    }
}
function mergeConfig(base, user) {
    return {
        mode: user.mode ?? base.mode,
        blockMode: user.blockMode ?? base.blockMode,
        streamingRedaction: user.streamingRedaction ?? base.streamingRedaction,
        toolPolicy: {
            whitelist: user.toolPolicy?.whitelist ?? base.toolPolicy.whitelist,
            blacklist: user.toolPolicy?.blacklist ?? base.toolPolicy.blacklist,
        },
        layers: {
            vendor: user.layers?.vendor ?? base.layers.vendor,
            pem: user.layers?.pem ?? base.layers.pem,
            prefix: user.layers?.prefix ?? base.layers.prefix,
            entropy: user.layers?.entropy ?? base.layers.entropy,
            asn1: user.layers?.asn1 ?? base.layers.asn1,
            context: user.layers?.context ?? base.layers.context,
            path: user.layers?.path ?? base.layers.path,
            pii: user.layers?.pii ?? base.layers.pii,
            connection: user.layers?.connection ?? base.layers.connection,
            custom: user.layers?.custom !== undefined ? user.layers.custom : base.layers.custom,
        },
        allowlistRegex: collectStringArrays(user, ["allowlistRegex", "allowListRegex"]) ?? base.allowlistRegex,
        allowlistLiteral: collectStringArrays(user, ["allowlistLiteral", "allowListLiteral", "allowlistLiterals", "allowListLiterals"]) ?? base.allowlistLiteral,
        allowlistEnv: collectStringArrays(user, ["allowlistEnv", "allowListEnv", "allowlistEnvs", "allowListEnvs", "allowlistEnvVars", "allowListEnvVars"]) ?? base.allowlistEnv,
        blocklistRegex: collectStringArrays(user, ["blocklistRegex", "blockListRegex", "customRegex", "customPatterns"]) ?? base.blocklistRegex,
        blocklistLiteral: collectStringArrays(user, ["blocklistLiteral", "blockListLiteral", "blocklistLiterals", "blockListLiterals", "customLiterals", "customLiteral", "customExact", "customExactMatches", "exactMatches"]) ?? base.blocklistLiteral,
        blocklistEnv: collectStringArrays(user, ["blocklistEnv", "blockListEnv", "blocklistEnvs", "blockListEnvs", "blocklistEnvVars", "envVars", "redactEnvVars", "envVarNames"]) ?? base.blocklistEnv,
        customRegex: collectStringArrays(user, ["customRegex", "customPatterns", "blocklistRegex", "blockListRegex"]) ?? base.customRegex,
        customLiterals: collectStringArrays(user, ["customLiterals", "customLiteral", "customExact", "customExactMatches", "exactMatches", "blocklistLiteral", "blockListLiteral", "blocklistLiterals"]) ?? base.customLiterals,
        envVars: collectStringArrays(user, ["envVars", "redactEnvVars", "envVarNames", "blocklistEnv", "blockListEnv", "blocklistEnvs"]) ?? base.envVars,
        minEntropy: user.minEntropy ?? base.minEntropy,
        minLength: user.minLength ?? base.minLength,
        preservePrefixChars: user.preservePrefixChars ?? base.preservePrefixChars,
        asterisksMax: user.asterisksMax ?? base.asterisksMax,
    };
}
function collectStringArrays(user, keys) {
    const out = [];
    let found = false;
    for (const k of keys) {
        const v = user[k];
        if (Array.isArray(v) && v.every((x) => typeof x === "string")) {
            found = true;
            out.push(...v);
        }
    }
    if (!found)
        return undefined;
    return [...new Set(out)];
}
function pickStringArray(user, keys) {
    return collectStringArrays(user, keys);
}
//# sourceMappingURL=config.js.map