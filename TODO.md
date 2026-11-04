# Hunter OS V5 Build Plan

## M1: Parser foundation + file dispositions + hardened extraction (DONE)

- [x] M1: Parser foundation + file dispositions + hardened extraction (DONE)
  - **Goal:** Establish bounded PHP subset parsing, visible source-file dispositions, and safe isolated archive extraction.
  - **Files to touch:** `analyzer/php_parser.py`, `analyzer/wordpress.py`, `tools/download.py`, `main.py`, `tests/test_scanner.py`, `tests/fixtures/php/`, `BOOK.md`, `README.md`.
  - **Tests to add:** Parser structure/location and malformed/unsupported syntax fixtures; file disposition tests; archive limits, path/symlink, and extraction isolation tests.
  - **Done criteria:** Existing V4 tests pass; parser is explicit about unsupported syntax; extraction and scan work are bounded; no scanned code is executed.
  - **Risks:** The parser is a documented subset, not a complete PHP AST or syntax validator. Existing V4 behavior and reports must remain compatible.

## M2: Taint engine on top of php_parser.py

- [x] M2: Taint engine on top of php_parser.py - sources, sinks, sanitizers, propagators. Must handle variable refs, assignments, calls, branches. Must NOT claim protection from nearby auth token.
  - **Goal:** Add a bounded, independently callable taint engine over the PHP parser IR. Track configurable source provenance through assignments, calls, branches, function arguments, and returns to configured sinks. Keep sanitizer evidence context-specific; never treat nearby authorization tokens as protection.
  - **Files to touch:** `analyzer/taint.py` (new), `analyzer/php_parser.py`, `tests/test_scanner.py`, `BOOK.md`, `TODO.md`.
  - **Tests to add:** Positive/negative source-to-sink cases; assignment and propagator cases; branch merge cases; inter-procedural parameter/return cases; context-appropriate and mismatched sanitizer cases; malformed/incomplete parser input; bounded recursion/step exhaustion; an auth-token-nearby non-protection regression.
  - **Done criteria:** The engine reports source-to-sink flows with source, sink, trace, context, and sanitizer evidence; preserves context-mitigated flows instead of silently dropping them; refuses to claim complete analysis for incomplete parser input or exhausted limits; does not execute source or change V4 scanner/report behavior.
  - **Risks:** The parser is incomplete and expressions are partly opaque. Unknown calls, aliases, path-sensitive branch conditions, and complex PHP features can only be handled conservatively or surfaced as limitations.

## M3: Wire parser + taint into scanner as opt-in parallel mode

- [ ] M3: Wire parser + taint into scanner as opt-in parallel mode, compare vs regex, keep V4 output identical when flag off
  - **Goal:** Add an explicit opt-in mode that runs parser/taint alongside existing regex checks while leaving flag-off V4 behavior byte-for-byte compatible for generated outputs.
  - **Files to touch:** `main.py`, `analyzer/wordpress.py`, `reporter/json_report.py`, focused CLI/report tests, `BOOK.md`, `README.md`.
  - **Tests to add:** Flag-off golden compatibility tests for exit codes, JSON shape/content, report paths, and duplicate history; opt-in mode/parser failure isolation and comparison output tests.
  - **Done criteria:** Default behavior remains V4-identical; only explicit opt-in invokes the new analysis; unsupported framework handling remains honest.
  - **Risks:** Report/history side effects, duplicate handling, and output ordering can accidentally change existing behavior.

## M4: New detectors using taint

- [ ] M4: New detectors using taint: SQLi, XSS (echo/print), RCE / command injection, LFI / path traversal, SSRF, unauthenticated sensitive actions
  - **Goal:** Add separately tested detector rules on top of reliable taint paths and sink contexts.
  - **Files to touch:** `analyzer/detectors/` (new), parser only for required syntax extensions, `tests/fixtures/`, `tests/test_scanner.py`, `BOOK.md`.
  - **Tests to add:** Positive, negative, sanitizer, authorization, malformed-source, and false-positive regression fixtures per detector; cross-function/file coverage where supported.
  - **Done criteria:** Each detector has explicit source/sink/context rules, test evidence, and truthful limitations; no detector treats a keyword-only match as proof.
  - **Risks:** Context confusion, incomplete language modeling, unsupported output/control syntax, and false-positive/false-negative tradeoffs.

## M5: Framework analysis

- [ ] M5: Framework analysis: WordPress hooks/actions, Laravel, Django, Node - identify entry points, routes, controllers
  - **Goal:** Add adapters for framework-specific entry points, routes/controllers, source/sink/sanitizer/authorization definitions, and only claim tested support.
  - **Files to touch:** `analyzer/frameworks/` (new), framework fixtures/tests, `analyzer/platform.py`, `main.py`, docs.
  - **Tests to add:** Per-framework detection, route/hook recognition, authorization, sanitization, cross-function flow, malformed input, and unsupported-framework regressions.
  - **Done criteria:** A framework is marked supported only when its parser/analysis route and security checks are implemented and tested.
  - **Risks:** Framework conventions vary by version and project structure; marker detection alone is insufficient support.

## M6: Report V5

- [ ] M6: Report V5: add taint trace (source -> propagations -> sink with lines), confidence, fix suggestion, keep V4 fields for backwards compat
  - **Goal:** Add structured V5 evidence and remediation while preserving every V4 JSON field and report path.
  - **Files to touch:** `reporter/json_report.py`, `reporter/patchstack.py`, `main.py`, report fixtures/tests, docs.
  - **Tests to add:** Backward-compatible V4 schema tests; V5 trace, confidence, remediation, sanitizer and authorization evidence serialization; safe Markdown/JSON escaping tests.
  - **Done criteria:** Reports distinguish observed evidence from inference, expose source-to-sink locations, include a fix suggestion, and preserve legacy fields.
  - **Risks:** Schema drift, escaped/untrusted source snippets, unsupported claims of severity, or unexpected report-history changes.

## M7: Full regression + docs update

- [ ] M7: Full regression + docs update in BOOK.md + README.md
  - **Goal:** Validate the implemented V5 scope end to end and make supported/unsupported behavior clear to users.
  - **Files to touch:** `tests/`, `BOOK.md`, `README.md`, and only implementation files required by discovered regressions.
  - **Tests to add:** Clean and synthetic fixtures, end-to-end compatibility checks, malformed source, bounded analysis, and any missing per-category/framework regressions.
  - **Done criteria:** Full unit suite, compile check, and diff checks pass; docs match actual implementation; no unsupported stage is claimed as implemented.
  - **Risks:** Broad regression surface, stale reports/history assumptions, and overclaiming capabilities not covered by tests.
