# Changelog

All notable changes to `pi-redact-all` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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