import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, resolve, basename, dirname, isAbsolute } from "node:path";
import { homedir } from "node:os";
import { execSync } from "node:child_process";
import type { Config } from "./types.js";

export const DEFAULT_CONFIG: Config = {
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
  blocklistDotenv: [],
  blocklistDotenvDiscover: [],
  blocklistDotenvExcludeKeys: [],
  customRegex: [],
  customLiterals: [],
  envVars: [],
  minEntropy: 4.5,
  minLength: 32,
  preservePrefixChars: 4,
  asterisksMax: 20,
};

let lastDotenvDebug: DotenvDebug | null = null;
let lastConfigPaths: { global: string | null; project: string | null; usedProject: string | null } = { global: null, project: null, usedProject: null };

export interface DotenvDebug {
  manualPatterns: string[];
  discoverStrategies: string[];
  discoveredFiles: string[];
  expandedManualFiles: string[];
  loadedFiles: { path: string; keys: string[]; valuesCount: number; skippedKeys: string[] }[];
  skippedExampleFiles: string[];
  excludedKeys: string[];
  totalValues: number;
  placeholderSkipped: number;
  shortSkipped: number;
}

export function getDotenvDebug(): DotenvDebug | null {
  return lastDotenvDebug;
}

export function getConfigPaths(): { global: string | null; project: string | null; usedProject: string | null } {
  return lastConfigPaths;
}

export function loadConfig(): Config {
  const globalPath = join(homedir(), ".pi", "agent", "pi-redact-all.json");
  lastConfigPaths.global = globalPath;
  let config: Config = { ...DEFAULT_CONFIG };
  let hasGlobal = false;
  if (existsSync(globalPath)) {
    try {
      const raw = readFileSync(globalPath, "utf-8");
      const user = JSON.parse(raw);
      config = mergeConfig(config, user);
      hasGlobal = true;
    } catch (err) {
      console.error(`[pi-redact-all] Failed to load global config at ${globalPath}:`, err);
    }
  }
  const projectPath = findProjectConfigPath();
  lastConfigPaths.project = projectPath;
  lastConfigPaths.usedProject = projectPath;
  if (projectPath && projectPath !== globalPath) {
    try {
      const raw = readFileSync(projectPath, "utf-8");
      const user = JSON.parse(raw);
      config = mergeConfig(config, user);
    } catch (err) {
      console.error(`[pi-redact-all] Failed to load project config at ${projectPath}:`, err);
    }
  } else if (!hasGlobal && !projectPath) {
    lastConfigPaths.usedProject = null;
  }
  if (!hasGlobal && !projectPath) {
    return applyDotenvBlocklist({ ...DEFAULT_CONFIG });
  }
  return applyDotenvBlocklist(config);
}

function findProjectConfigPath(): string | null {
  const candidates: string[] = [];
  const cwd = process.cwd();
  candidates.push(join(cwd, ".pi-redact-all.json"));
  candidates.push(join(cwd, ".pi", "agent", "pi-redact-all.json"));
  candidates.push(join(cwd, "pi-redact-all.json"));
  const gitRoot = getGitRoot();
  if (gitRoot && gitRoot !== cwd) {
    candidates.push(join(gitRoot, ".pi-redact-all.json"));
    candidates.push(join(gitRoot, ".pi", "agent", "pi-redact-all.json"));
    candidates.push(join(gitRoot, "pi-redact-all.json"));
  }
  for (const p of candidates) {
    if (existsSync(p)) return p;
  }
  return null;
}

function getGitRoot(): string | null {
  try {
    const out = execSync("git rev-parse --show-toplevel", { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"], timeout: 2000 });
    const trimmed = out.trim();
    if (trimmed) return resolve(trimmed);
  } catch {}
  return null;
}

function mergeConfig(base: Config, user: Partial<Config>): Config {
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
      custom: (user.layers as Record<string, unknown>)?.custom !== undefined ? (user.layers as { custom?: boolean }).custom! : base.layers.custom,
    },
    allowlistRegex: mergeArrays(base.allowlistRegex, collectStringArrays(user, ["allowlistRegex", "allowListRegex"])),
    allowlistLiteral: mergeArrays(base.allowlistLiteral, collectStringArrays(user, ["allowlistLiteral", "allowListLiteral", "allowlistLiterals", "allowListLiterals"])),
    allowlistEnv: mergeArrays(base.allowlistEnv, collectStringArrays(user, ["allowlistEnv", "allowListEnv", "allowlistEnvs", "allowListEnvs", "allowlistEnvVars", "allowListEnvVars"])),
    blocklistRegex: mergeArrays(base.blocklistRegex, collectStringArrays(user, ["blocklistRegex", "blockListRegex", "customRegex", "customPatterns"])),
    blocklistLiteral: mergeArrays(base.blocklistLiteral, collectStringArrays(user, ["blocklistLiteral", "blockListLiteral", "blocklistLiterals", "blockListLiterals", "customLiterals", "customLiteral", "customExact", "customExactMatches", "exactMatches"])),
    blocklistEnv: mergeArrays(base.blocklistEnv, collectStringArrays(user, ["blocklistEnv", "blockListEnv", "blocklistEnvs", "blockListEnvs", "blocklistEnvVars", "envVars", "redactEnvVars", "envVarNames"])),
    blocklistDotenv: mergeArrays(base.blocklistDotenv, collectStringArrays(user, ["blocklistDotenv", "blockListDotenv", "dotenv", "dotenvFiles", "dotenvPath", "dotenvPaths"])),
    blocklistDotenvDiscover: mergeArrays(base.blocklistDotenvDiscover, collectStringArrays(user, ["blocklistDotenvDiscover", "blockListDotenvDiscover", "dotenvDiscover", "dotenvDiscovery", "dotenvAutoDiscover"])),
    blocklistDotenvExcludeKeys: mergeArrays(base.blocklistDotenvExcludeKeys, collectStringArrays(user, ["blocklistDotenvExcludeKeys", "blockListDotenvExcludeKeys", "dotenvExcludeKeys", "dotenvExclude", "dotenvIgnoreKeys"])),
    customRegex: mergeArrays(base.customRegex, collectStringArrays(user, ["customRegex", "customPatterns", "blocklistRegex", "blockListRegex"])),
    customLiterals: mergeArrays(base.customLiterals, collectStringArrays(user, ["customLiterals", "customLiteral", "customExact", "customExactMatches", "exactMatches", "blocklistLiteral", "blockListLiteral", "blocklistLiterals"])),
    envVars: mergeArrays(base.envVars, collectStringArrays(user, ["envVars", "redactEnvVars", "envVarNames", "blocklistEnv", "blockListEnv", "blocklistEnvs"])),
    minEntropy: user.minEntropy ?? base.minEntropy,
    minLength: user.minLength ?? base.minLength,
    preservePrefixChars: user.preservePrefixChars ?? base.preservePrefixChars,
    asterisksMax: user.asterisksMax ?? base.asterisksMax,
  };
}

function mergeArrays(base: string[], user: string[] | undefined): string[] {
  if (!user) return base;
  if (!base.length) return user;
  return [...new Set([...base, ...user])];
}

function collectStringArrays(user: Record<string, unknown>, keys: string[]): string[] | undefined {
  const out: string[] = [];
  let found = false;
  for (const k of keys) {
    const v = user[k];
    if (Array.isArray(v) && v.every((x) => typeof x === "string")) {
      found = true;
      out.push(...(v as string[]));
    }
  }
  if (!found) return undefined;
  return [...new Set(out)];
}

function pickStringArray(user: Record<string, unknown>, keys: string[]): string[] | undefined {
  return collectStringArrays(user, keys);
}

function applyDotenvBlocklist(config: Config): Config {
  const manual = config.blocklistDotenv ?? [];
  const discover = config.blocklistDotenvDiscover ?? [];
  const hasManual = manual.length > 0;
  const hasDiscover = discover.length > 0;
  if (!hasManual && !hasDiscover) {
    lastDotenvDebug = {
      manualPatterns: [],
      discoverStrategies: [],
      discoveredFiles: [],
      expandedManualFiles: [],
      loadedFiles: [],
      skippedExampleFiles: [],
      excludedKeys: [...(config.blocklistDotenvExcludeKeys ?? [])],
      totalValues: 0,
      placeholderSkipped: 0,
      shortSkipped: 0,
    };
    return config;
  }
  const excludeSet = new Set((config.blocklistDotenvExcludeKeys ?? []).map((k) => k.toLowerCase()));
  const discovered = hasDiscover ? discoverDotenvFiles(discover) : [];
  const allPatterns = [...manual, ...discovered];
  const expandedManual = manual.flatMap((p) => expandDotenvPattern(p));
  const debug: DotenvDebug = {
    manualPatterns: [...manual],
    discoverStrategies: [...discover],
    discoveredFiles: [...discovered],
    expandedManualFiles: [...new Set(expandedManual.map((p) => resolve(p)))],
    loadedFiles: [],
    skippedExampleFiles: [],
    excludedKeys: [...(config.blocklistDotenvExcludeKeys ?? [])],
    totalValues: 0,
    placeholderSkipped: 0,
    shortSkipped: 0,
  };
  const { values, loadedFiles, skippedExamples, placeholderSkipped, shortSkipped } = loadDotenvValuesWithDebug(allPatterns, excludeSet);
  debug.loadedFiles = loadedFiles;
  debug.skippedExampleFiles = skippedExamples;
  debug.totalValues = values.length;
  debug.placeholderSkipped = placeholderSkipped;
  debug.shortSkipped = shortSkipped;
  lastDotenvDebug = debug;
  if (values.length === 0) return config;
  const mergedLiteral = [...new Set([...(config.blocklistLiteral ?? []), ...values])];
  const mergedCustomLiteral = [...new Set([...(config.customLiterals ?? []), ...values])];
  return {
    ...config,
    blocklistLiteral: mergedLiteral,
    customLiterals: mergedCustomLiteral,
  };
}

function discoverDotenvFiles(strategies: string[]): string[] {
  const out: string[] = [];
  const normalized = strategies.map((s) => s.toLowerCase().trim());
  for (const strat of normalized) {
    if (strat === "gitroot" || strat === "git_root" || strat === "git-root") {
      const root = getGitRoot();
      if (root) {
        const candidates = [join(root, ".env"), join(root, ".env.local")];
        for (const c of candidates) if (existsSync(c)) out.push(c);
        const globs = discoverViaGitLsFiles(root);
        out.push(...globs);
      }
    } else if (strat === "cwd" || strat === "current") {
      const cwd = process.cwd();
      const candidates = [join(cwd, ".env"), join(cwd, ".env.local")];
      for (const c of candidates) if (existsSync(c)) out.push(c);
    } else if (strat === "nexttoexample" || strat === "next_to_example" || strat === "next-to-example" || strat === "example" || strat === "tracked") {
      const root = getGitRoot() || process.cwd();
      const examples = findTrackedEnvExampleFiles(root);
      for (const ex of examples) {
        const dir = dirname(ex);
        const base = basename(ex);
        let envName = base;
        if (base.endsWith(".example")) envName = base.slice(0, -8);
        else if (base.endsWith(".sample")) envName = base.slice(0, -7);
        else if (base.endsWith(".template")) envName = base.slice(0, -9);
        const envPath = join(dir, envName);
        if (existsSync(envPath)) out.push(envPath);
      }
    }
  }
  return [...new Set(out.map((p) => resolve(p)))];
}

function discoverViaGitLsFiles(root: string): string[] {
  try {
    const out = execSync("git ls-files -z --cached --others --exclude-standard", { encoding: "buffer", cwd: root, timeout: 2000 });
    const files = out.toString("utf-8").split("\0").filter(Boolean);
    const envFiles = files.filter((f) => {
      const lower = f.toLowerCase();
      if (lower.endsWith(".example") || lower.endsWith(".sample") || lower.endsWith(".template")) return false;
      const base = basename(f);
      return base === ".env" || base.startsWith(".env.");
    });
    return envFiles.map((f) => join(root, f));
  } catch {
    return [];
  }
}

function findTrackedEnvExampleFiles(root: string): string[] {
  try {
    const out = execSync("git ls-files -z --cached --others --exclude-standard", { encoding: "buffer", cwd: root, timeout: 2000 });
    const files = out.toString("utf-8").split("\0").filter(Boolean);
    return files
      .filter((f) => {
        const lower = f.toLowerCase();
        return lower.endsWith(".env.example") || lower.endsWith(".env.sample") || f.endsWith(".env.template");
      })
      .map((f) => join(root, f));
  } catch {
    try {
      const entries = readdirSync(root, { withFileTypes: true });
      const res: string[] = [];
      function walk(dir: string) {
        let ents;
        try { ents = readdirSync(dir, { withFileTypes: true }); } catch { return; }
        for (const ent of ents) {
          if (ent.name.startsWith(".git") || ent.name === "node_modules") continue;
          const full = join(dir, ent.name);
          if (ent.isDirectory()) walk(full);
          else if (ent.name.endsWith(".env.example") || ent.name.endsWith(".env.sample")) res.push(full);
        }
      }
      walk(root);
      return res;
    } catch { return []; }
  }
}

function loadDotenvValues(patterns: string[], excludeKeys: Set<string>): string[] {
  const { values } = loadDotenvValuesWithDebug(patterns, excludeKeys);
  return values;
}

function loadDotenvValuesWithDebug(patterns: string[], excludeKeys: Set<string>): { values: string[]; loadedFiles: { path: string; keys: string[]; valuesCount: number; skippedKeys: string[] }[]; skippedExamples: string[]; placeholderSkipped: number; shortSkipped: number } {
  const out: string[] = [];
  const seenFiles = new Set<string>();
  const loadedFiles: { path: string; keys: string[]; valuesCount: number; skippedKeys: string[] }[] = [];
  const skippedExamples: string[] = [];
  let placeholderSkipped = 0;
  let shortSkipped = 0;
  for (const pat of patterns) {
    const files = expandDotenvPattern(pat);
    for (const file of files) {
      if (seenFiles.has(file)) continue;
      seenFiles.add(file);
      if (isDotenvExampleFile(file)) {
        skippedExamples.push(file);
        continue;
      }
      if (!existsSync(file)) continue;
      try {
        const stat = statSync(file);
        if (!stat.isFile()) continue;
      } catch { continue; }
      const parsed = parseDotenvFile(file);
      const keys: string[] = [];
      const skippedKeys: string[] = [];
      let added = 0;
      for (const [k, v] of parsed) {
        if (excludeKeys.has(k.toLowerCase())) {
          skippedKeys.push(k);
          continue;
        }
        const trimmed = v.trim();
        if (trimmed.length < 2) {
          shortSkipped++;
          continue;
        }
        if (isDotenvPlaceholderValue(trimmed)) {
          placeholderSkipped++;
          continue;
        }
        out.push(v);
        keys.push(k);
        added++;
      }
      loadedFiles.push({ path: file, keys, valuesCount: added, skippedKeys });
    }
  }
  return { values: [...new Set(out)], loadedFiles, skippedExamples, placeholderSkipped, shortSkipped };
}

function isDotenvExampleFile(file: string): boolean {
  const base = basename(file).toLowerCase();
  return base.endsWith(".example") || base.endsWith(".sample") || base.endsWith(".template") || base === ".env.example" || base === ".env.sample";
}

function isDotenvPlaceholderValue(val: string): boolean {
  const lower = val.toLowerCase();
  if (["", "example", "placeholder", "changeme", "your_value_here", "xxx", "***"].includes(lower)) return true;
  if (/^\$\{.*\}$/.test(val)) return true;
  return false;
}

function parseDotenvFile(file: string): Map<string, string> {
  const map = new Map<string, string>();
  let raw: string;
  try { raw = readFileSync(file, "utf-8"); } catch { return map; }
  const lines = raw.split(/\r?\n/);
  for (let line of lines) {
    line = line.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    if (line.startsWith("export ")) line = line.slice(7).trim();
    const eq = line.indexOf("=");
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'")) || (val.startsWith("`") && val.endsWith("`"))) {
      val = val.slice(1, -1);
    }
    val = val.replace(/\\n/g, "\n").replace(/\\r/g, "\r");
    if (val.includes("#") && !line.includes('"') && !line.includes("'")) {
      const hashIdx = val.indexOf(" #");
      if (hashIdx !== -1) val = val.slice(0, hashIdx).trim();
    }
    map.set(key, val);
  }
  return map;
}

function expandDotenvPattern(pattern: string): string[] {
  const hasGlob = pattern.includes("*") || pattern.includes("?") || pattern.includes("[");
  if (!hasGlob) {
    const abs = isAbsolute(pattern) ? pattern : resolve(process.cwd(), pattern);
    return [abs];
  }
  try {
    const fs = require("node:fs") as { globSync?: (pat: string) => string[] };
    if (typeof fs.globSync === "function") {
      const absPat = isAbsolute(pattern) ? pattern : join(process.cwd(), pattern);
      return (fs as any).globSync(absPat).map((p: string) => resolve(p));
    }
  } catch {}
  const absPat = isAbsolute(pattern) ? pattern : join(process.cwd(), pattern);
  return expandGlobFallback(absPat);
}

function expandGlobFallback(pattern: string): string[] {
  const starIdx = pattern.indexOf("*");
  if (starIdx === -1) return [pattern];
  const slashBefore = pattern.lastIndexOf("/", starIdx);
  const baseDir = slashBefore === -1 ? "." : pattern.slice(0, slashBefore) || "/";
  const afterBase = pattern.slice(slashBefore + 1);
  const results: string[] = [];
  try {
    const entries = readdirSync(baseDir, { withFileTypes: true });
    for (const ent of entries) {
      const candidate = join(baseDir, ent.name);
      if (matchGlob(afterBase, ent.name)) {
        if (ent.isFile()) results.push(resolve(candidate));
        else if (ent.isDirectory() && pattern.includes("**")) {
          const subPattern = pattern.slice(pattern.indexOf("**") + 3).replace(/^\//, "");
          const deep = expandGlobFallback(join(candidate, subPattern || "*"));
          results.push(...deep);
          const directFiles = expandGlobFallback(join(candidate, "*"));
          results.push(...directFiles);
        }
      } else if (ent.isDirectory()) {
        if (afterBase.startsWith("*") || pattern.includes("**")) {
          const remaining = pattern.slice(baseDir.length + 1);
          const subResults = expandGlobFallback(join(candidate, remaining));
          results.push(...subResults);
        }
      }
    }
  } catch {}
  if (results.length === 0) return [resolve(pattern.replace(/\*/g, ""))];
  return results;
}

function matchGlob(pattern: string, str: string): boolean {
  const esc = (s: string) => s.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  let reStr = "^";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === "*") {
      if (pattern[i + 1] === "*") { reStr += ".*"; i++; if (pattern[i + 1] === "/") i++; }
      else reStr += "[^/]*";
    } else if (c === "?") reStr += "[^/]";
    else if (c === "[") {
      const close = pattern.indexOf("]", i);
      if (close !== -1) { reStr += pattern.slice(i, close + 1); i = close; }
      else reStr += "\\[";
    } else reStr += esc(c);
  }
  reStr += "$";
  try { return new RegExp(reStr).test(str); } catch { return str === pattern; }
}
