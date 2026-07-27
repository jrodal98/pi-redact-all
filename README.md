# pi-redact-all

[![npm version](https://img.shields.io/npm/v/pi-redact-all.svg)](https://www.npmjs.com/package/pi-redact-all)
[![license: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/steimbyte/pi-redact-all/actions/workflows/ci.yml/badge.svg)](https://github.com/steimbyte/pi-redact-all/actions/workflows/ci.yml)

Global tool-output redaction for Pi — redacts secrets, certificates, PII, and connection strings across **all** tool outputs (bash, read, write, edit, MCP, etc.) and **user input** before they reach the model.

## Features

### Multi-Layer Detection (10 layers)
- **L1**: Vendor API-Key Patterns (AWS, GitHub, Stripe, Google, OpenAI, Slack, etc.)
- **L2**: PEM/X.509/PGP-Blocks (`CERTIFICATE`, `X509 CRL`, `PKCS7`, `CSR`, `PRIVATE KEY`, etc.)
- **L3**: Vendor-Prefix Recognition (fast pre-check)
- **L4**: Shannon-Entropy Heuristics (high-entropy tokens, allowlist-aware)
- **L5**: ASN.1 SEQUENCE Detection (`MII…` DER blocks, even without PEM wrapper)
- **L6**: Context-Anchored (`subject=`, `issuer=`, `SECRET=`, JSON/INI/YAML secret fields)
- **L7**: File-Path Based (read-tool on `*.pem`, `id_rsa`, `.env`, `.aws/credentials`, etc.)
- **L8**: PII (Email, Phone, IPv4, Credit Card with Luhn, SSN, IBAN) — opt-in
- **L9+10**: Connection Strings & URL-Embedded Credentials

### Hook Coverage
| Hook | Purpose |
|------|---------|
| `tool_result` | Redact tool output before it reaches the LLM |
| `tool_call` | Pre-block sensitive tool calls (e.g., `cat .env`, `cat id_rsa`) |
| `before_agent_start` | **Filter user input before it enters the conversation** |
| `message_end` | Filter assistant messages (last line of defense) |
| `before_provider_request` | Filter the final provider payload before HTTP call |

### Visual Identity
- Whitespace, linebreaks, and structure stay **1:1** — only matched spans are replaced
- Tools continue to function normally (they're already finished when we redact)
- TUI shows the redacted output, indistinguishable from "normal" output

## Installation

```bash
# From npm (recommended)
pi install npm:pi-redact-all

# From source (development)
git clone https://github.com/steimbyte/pi-redact-all.git
cd pi-redact-all
npm install
npm run build
ln -s "$(pwd)" ~/.pi/agent/extensions/pi-redact-all
```

Or symlink from anywhere:

```bash
ln -s /path/to/pi-redact-all ~/.pi/agent/extensions/pi-redact-all
```

## Configuration

`~/.pi/agent/pi-redact-all.json`:

```json
{
  "mode": "mask",
  "blockMode": false,
  "streamingRedaction": false,
  "toolPolicy": {
    "whitelist": [],
    "blacklist": []
  },
  "layers": {
    "vendor": true,
    "pem": true,
    "prefix": true,
    "entropy": true,
    "asn1": true,
    "context": true,
    "path": true,
    "pii": false,
    "connection": true
  },
  "allowlistRegex": ["\\b[a-f0-9]{40}\\b"],
  "minEntropy": 4.5,
  "minLength": 32
}
```

## Commands

- `/redact-all-stats` — Show session statistics
- `/redact-all-config` — Show current configuration

## Compatibility

- Co-exists with `@spences10/pi-redact` (boundary check prevents double-redaction)
- Marker format: `[REDACTED:TYPE]` (compatible with pi-redact's format)
- PEM-blocks use specific marker: `[REDACTED:PEM CERTIFICATE]`

## Development

```bash
npm install
npm run build        # Compile TS to dist/
npm test             # Run smoke tests
```

## License

MIT