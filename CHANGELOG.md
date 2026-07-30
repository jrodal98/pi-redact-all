# Changelog

All notable changes to `pi-redact-all` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.6] - 2026-07-30

### Changed (Performance — large speedups on common workloads)

Several hot-path optimizations that collectively bring large text processing
(~5-8× faster on common workloads) without changing any redaction behavior:

- **`shannonEntropy` (Layer 4)**: replaced `Map<string, number>` frequency table
  with a typed `Int32Array(128)`. 3-5× faster per token. ASCII-only is
  guaranteed by the upstream `TOKEN_RE` filter (`[A-Za-z0-9+/\-_]`).
- **`classifyChars`**: single-pass char-code loop replaces the two anchored
  regex scans `HEX_RE.test(value)` + `BASE64_RE.test(value)`. Same answer,
  ~2-3× faster per token.
- **`layer-1-vendor`**: prefix-anchored patterns now do an `indexOf` pre-scan
  with a manual word-boundary check before running the regex tail, eliminating
  the cost of regex scanning 100K chars of prose with 19 patterns each when
  no vendor keys are present (~3-4× faster on typical outputs).
- **`layer-3-prefix`**: per-char regex test (`/[A-Za-z0-9_-]/`) replaced
  with an `isTokenChar` char-code check (~2× faster).
- **`layer-9-10-connection`**: switched from regex with `\b` boundaries to an
  `indexOf("://")` pre-screen plus a manual back-walk to the protocol name.
  Same answer, ~5× faster on texts without URL credentials.
- **`layer-8-pii`**: pre-screen for the distinguishing literals of each
  pattern (`@` for email, `+` for E.164 phone, `\d{3}-\d{2}-` for SSN, long
  digit run for credit card, `[A-Z]{2}\d{2}[A-Z0-9]{4,}` for IBAN). Texts
  without any PII skip the regex engine entirely (~2-3× faster).
- **`redactText` orchestrator**: short-text fast exit. Texts shorter than
  `minLength` (default 32) cannot contain a redaction target, so all 9 layers
  are skipped. Common for tool-result text items.
- **`applyMatches` (shared)**: in-place sort of matches (we own the array),
  pre-sized `filtered` and `parts` arrays to avoid V8 array-growth, plus
  trim trailing undefined slots. Marginal win on small match counts.

### Tests (unchanged — all 97 still pass)

| Suite                          | Result |
|--------------------------------|--------|
| data-url-v0.1.5                | 12/12  |
| hooks-test                     | 21/21  |
| image-payload-v0.1.4           | 10/10  |
| path-context-v0.1.4            | 12/12  |
| comprehensive-validation       | 34/34  |
| smoke-test                     |  8/8   |
| **Total**                      | **97/97** |

### Benchmark comparison (single thread, this machine)

| Workload                              | v0.1.5      | v0.1.6      | Speedup   |
|---------------------------------------|-------------|-------------|-----------|
| 1K text, no secrets                   | ~0.08 ms    | ~0.05 ms    | ~1.4×     |
| 10K text, no secrets                  | ~0.23 ms    | ~0.14 ms    | ~1.6×     |
| 100K text, no secrets                 | ~6.6 ms     | ~1.5 ms     | ~4.4×     |
| 100K text, 1 long base64 token        | ~8.2 ms     | ~1.7 ms     | ~4.8×     |
| 100K text, 1000 long base64 tokens    | ~28.5 ms    | ~21 ms      | ~1.4×     |

The "many b64" workload (last row) is bounded by the per-token shannonEntropy
calculation rather than by regex scans; further wins there would require
shannonEntropy micro-optimisation.

## [0.1.5] - 2026-07-30

### Fixed (CRITICAL — image base64 in text fields corrupted)

When image binary data appeared in a TEXT field (e.g. a read-tool result with
the binary in the text note, the output of `bash base64 img.png`, or any user
message embedding `data:image/png;base64,XXX`), Layer 4 (entropy) matched the
long high-entropy base64 token and replaced it with `[REDACTED:High Entropy Token]`.
The provider then received a corrupted payload.

The `isInsidePathContext()` heuristic in `src/layers/shared.ts` was extended
to recognize that a long high-entropy base64 token preceded by a
`data:image/...;base64,` (or `data:application/...;base64,`) prefix is the
base64 payload of an inline image or file — not a leaked secret.

This suppression is consulted by entropy (Layer 4), vendor (Layer 1) and
prefix (Layer 3). Real secrets in surrounding prose (a leaked AWS key, a GitHub
token, a PEM private key) are still redacted normally — verified by 5 negative
tests in `test/data-url-v0.1.5.test.mjs`.

### Added

- `test/data-url-v0.1.5.test.mjs` — 12 regression tests covering:
  - read-tool text note containing a `data:image/...;base64,` payload
  - common MIME prefixes (`image/png`, `image/jpeg`, `image/webp`,
    `image/svg+xml`, `application/octet-stream`, `application/pdf`)
  - 4 negative tests confirming real secrets (`AWS Access Key`, `GitHub Token`,
    `PEM Private Key`) in adjacent prose ARE redacted, and that high-entropy
    random base64 WITHOUT a `data:` prefix IS still redacted as before.

### Tests

| Suite                          | Result |
|--------------------------------|--------|
| data-url-v0.1.5 (new)          | 12/12  |
| hooks-test                     | 21/21  |
| image-payload-v0.1.4           | 10/10  |
| path-context-v0.1.4            | 12/12  |
| comprehensive-validation       | 34/34  |
| smoke-test                     |  8/8   |
| **Total**                      | **97/97** |

## [0.1.4] - 2026-07-30

### Fixed (CRITICAL — two reported bugs)

#### 1. Image payloads corrupted during redaction

Multimodal provider requests (Anthropic `image.source.data`, OpenAI `image_url`,
Google `inlineData`, generated-image `b64_json`, Pi internal `ImageContent.data`)
were being corrupted in the `before_provider_request` hook. Layer 4 (entropy)
matched the long base64 data as "High Entropy Token" and replaced it with a
`[REDACTED:...]` marker, which the provider then rejected with HTTP 400:

```
invalid_request_error: invalid image content:
decode image config: image: unknown format (2013)
```

The new `isProtectedImageKey()` heuristic in `before-provider.ts` inspects the
sibling keys around a match and skips redaction when the surrounding structure
looks like a multimodal envelope. The check is structural (not blanket-key),
so ordinary `data` properties on unrelated payloads are still redacted.

#### 2. Filenames redacted as if they were API keys

Layer 1's `sk-[a-zA-Z0-9._\-]{20,}` pattern + Layer 4 entropy matched on long
alphanumeric tokens that happened to live inside file paths or filenames.
Reported offender: an Obsidian playbook file
`zed-task-handle.md` becoming
`zed-task-h***************[REDACTED:OpenAI/Anthropic API Key].md` after a
write-tool-call.

The new `isInsidePathContext()` heuristic in `shared.ts` suppresses all layer
matches when the `[start, end)` span sits inside a path-like context:

- Path separator (`/`, `\`) immediately before the match
- Path separator within the next 20 chars (after stripping REDACTED markers
  so our own marker text like `[REDACTED:OpenAI/Anthropic API Key]` doesn't
  trigger via its embedded `/`)
- File extension within the next 80 chars **or** at the tail of the match
  itself (Layer 1 char class greedily eats `.md`, so the suffix may be
  *inside* the match span)
- Path-prefix cues (`path:`, `from`, `save`, `to`, `write`, `<path>` etc.)
  immediately before the match

Layer 1 (vendor), Layer 3 (prefix) and Layer 4 (entropy) all consult this
heuristic. Real secrets in normal prose are still redacted — verified by
10 negative tests.

### Added

- `isInsidePathContext()` in `src/layers/shared.ts`
- `isProtectedImageKey()` in `src/hooks/before-provider.ts`
- `test/image-payload-v0.1.4.test.mjs` — 10 regression tests covering
  Anthropic, Pi, OpenAI Chat, OpenAI Responses, Google, image generation,
  data-URI URLs, deeply-nested blocks, and text siblings.
- `test/path-context-v0.1.4.test.mjs` — 12 regression tests covering the
  reported filename bug, file-extension suffix, path separators, common
  path-prefix cues, `<path>` tag cursors, and four negative tests
  confirming real secrets in prose still redact.

### Tests

| Suite | Result |
|-------|--------|
| hooks-test | 21/21 |
| image-payload-v0.1.4 | 10/10 |
| path-context-v0.1.4 | 12/12 |
| comprehensive-validation | 34/34 |
| smoke-test | 8/8 |
| **Total** | **85/85** |

## [0.1.3] - 2026-07-27

### Performance (CRITICAL)
- **`applyMatches`**: `O(n²)` slice+concat → `O(n)` array-parts + join
- **`isInsideMarker`**: `O(n)` rückwärts-Scan → `O(log n)` binary search with pre-built marker cache
- **All 9 layers**: Use `buildMarkerCache` + `isInsideMarker` instead of per-match O(n) scans
- **`redactText`**: Graceful null/undefined handling (returns `{text: "", matches: []}`)

### Benchmarks
| Tokens | v0.1.2 | v0.1.3 | Speedup |
|--------|--------|--------|---------|
| 1,000 | 53ms | 11ms | 5x |
| 10,000 | 7,200ms | 91ms | **79x** |
| 100,000 | ∞ (>600s) | 8,621ms | >70x |

### Fixed
- Layer pipeline reordered: Path detection runs **first** (was overriding PEM detection)
- Layer 4 entropy runs **last** (most expensive, least specific)

### Tests
- **34/34 comprehensive validation tests** pass (was 0/0 — no validation existed)
- 8 smoke tests, 21 hook tests, 34 validation tests
- All 8 `ToolResultEvent` variants validated (bash, read, edit, write, grep, find, ls, custom/MCP)
- All 7 `AgentMessage` roles schema-preservation validated
- Edge cases: empty content, 100KB content, Unicode+emoji, special regex chars, null/undefined
- Idempotency (re-running on redacted text doesn't double-redact)
- Performance benchmarks (1k <100ms, 10k <500ms)

## [0.1.2] - 2026-07-27

### Fixed (CRITICAL — caused 400 invalid_request_error)
- **`message_end` hook**: Now schema-aware — preserves `AgentMessage` union shape exactly
  - User/Assistant: redact content, preserve timestamp/usage/model
  - Custom: redact content, preserve customType/display/details/timestamp
  - bashExecution/branchSummary/compactionSummary: pass through untouched
- **`before_provider_request` hook**: Mutates payload in-place (not return value)
  - Skips class instances, functions, getters (no schema violation)
  - Returns void

### Added
- 21 schema-aware hook tests in `test/hooks-test.mjs`

## [0.1.1] - 2026-07-27

### Fixed
- **CRITICAL**: Disabled `message_end` and `before_provider_request` hooks (caused `400 invalid_request_error` from LLM provider due to schema corruption of `AgentMessage` union)

## [0.1.0] - 2026-07-27

### Added
- Initial release
- 10-layer multi-pass secret detection
- 5 hooks (tool_result, tool_call, before_agent_start, message_end, before_provider_request)
- X.509 certificate detection (PEM + ASN.1/DER)
- Connection string detection (postgres, mysql, redis, etc.)
- User-input filtering
- PII detection (opt-in)
- Visual identity preservation (whitespace 1:1)
- Co-existence with `@spences10/pi-redact`