import type { Match, RedactionContext, LayerResult } from "../types.js";

const DOTENV_EXAMPLE_RE = /\.env\.(example|sample|template)$/i;

function isDotenvExample(path: string): boolean {
  const lower = path.toLowerCase();
  return lower.endsWith(".env.example") || lower.endsWith(".env.sample") || lower.endsWith(".env.template");
}

const SENSITIVE_PATH_PATTERNS: { pattern: RegExp; type: string }[] = [
  { pattern: /\.pem$/i, type: "PEM File" },
  { pattern: /\.crt$/i, type: "Certificate File" },
  { pattern: /\.cer$/i, type: "Certificate File" },
  { pattern: /\.der$/i, type: "DER File" },
  { pattern: /\.p7b$/i, type: "PKCS7 File" },
  { pattern: /\.p7c$/i, type: "PKCS7 File" },
  { pattern: /\.p12$/i, type: "PKCS12 File" },
  { pattern: /\.pfx$/i, type: "PKCS12 File" },
  { pattern: /(^|\/)\.ssh\/id_(rsa|ed25519|ecdsa|dsa)(\.pub)?$/i, type: "SSH Key" },
  { pattern: /\.ssh\/config$/i, type: "SSH Config" },
  { pattern: /\.ssh\/known_hosts$/i, type: "SSH Known Hosts" },
  { pattern: /\.ssh\/authorized_keys$/i, type: "SSH Authorized Keys" },
  { pattern: /(^|\/)\.env(\.\w+)?$/i, type: "Env File" },
  { pattern: /\.aws\/credentials$/i, type: "AWS Credentials" },
  { pattern: /\.aws\/config$/i, type: "AWS Config" },
  { pattern: /\.npmrc$/i, type: "npm Config" },
  { pattern: /\.pypirc$/i, type: "PyPI Config" },
  { pattern: /\.netrc$/i, type: "Netrc File" },
  { pattern: /\.docker\/config\.json$/i, type: "Docker Config" },
  { pattern: /\.gitconfig-credentials$/i, type: "Git Credentials" },
  { pattern: /(^|\/)credentials(\.\w+)?$/i, type: "Credentials File" },
  { pattern: /(^|\/)secrets?\.(ya?ml|json|env)$/i, type: "Secrets File" },
  { pattern: /\.kube\/config$/i, type: "Kube Config" },
  { pattern: /\.kube\/.*\.crt$/i, type: "Kube Cert" },
];

export function apply(text: string, ctx: RedactionContext): LayerResult {
  const matches: Match[] = [];
  if (ctx.toolName !== "read") return { matches };
  if (!ctx.inputPath) return { matches };
  if (isDotenvExample(ctx.inputPath)) return { matches };
  for (const { pattern, type } of SENSITIVE_PATH_PATTERNS) {
    if (type === "Env File" && DOTENV_EXAMPLE_RE.test(ctx.inputPath)) continue;
    if (pattern.test(ctx.inputPath)) {
      matches.push({
        start: 0,
        end: text.length,
        type: `Protected File (${type})`,
        replacement: `[REDACTED:Protected File (${type})]`,
      });
      return { matches };
    }
  }
  return { matches };
}

export function shouldBlockPath(path: string): boolean {
  if (isDotenvExample(path)) return false;
  for (const { pattern, type } of SENSITIVE_PATH_PATTERNS) {
    if (type === "Env File" && DOTENV_EXAMPLE_RE.test(path)) continue;
    if (pattern.test(path)) return true;
  }
  return false;
}

export function commandReadsSensitive(command: string): boolean {
  if (/\.env\.(example|sample|template)\b/i.test(command)) return false;
  const sensitiveNames = [
    ".env",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "credentials",
    ".aws/credentials",
    ".npmrc",
    ".netrc",
    ".pypirc",
    ".gitconfig-credentials",
  ];
  for (const name of sensitiveNames) {
    const re = new RegExp(`\\b(?:cat|cp|mv|grep|less|more|head|tail|vi[m]?|nano|less)\\b\\s+[^|;&]*${name.replace(/\./g, "\\.")}`, "i");
    if (re.test(command)) {
      if (name === ".env" && DOTENV_EXAMPLE_RE.test(command)) continue;
      return true;
    }
    const envRe = new RegExp(`\\bprintenv\\b.*${name}`, "i");
    if (envRe.test(command)) return true;
  }
  return false;
}
