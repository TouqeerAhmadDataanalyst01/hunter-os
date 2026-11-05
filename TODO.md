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

- [x] M3: Wire parser + taint into scanner as opt-in parallel mode, compare vs regex, keep V4 output identical when flag off
  - **Goal:** Add an explicit opt-in mode that runs parser/taint alongside existing regex checks while leaving flag-off V4 behavior byte-for-byte compatible for generated outputs.
  - **Files to touch:** `main.py`, `analyzer/wordpress.py`, `reporter/json_report.py`, `tests/test_v4_multi.py`, `BOOK.md`, `README.md`.
  - **Tests to add:** Flag-off/default byte-compatibility tests for output, exit codes, JSON, Markdown, and duplicate history; opt-in V4+taint, sanitizer/auth downgrade, incomplete parser, cross-function, and branch-merge tests.
  - **Done criteria:** Default and `--engine=regex` retain V4 output and artifacts; only `--engine=taint` adds V5 JSON fields; downgraded and incomplete findings remain visible.
  - **Risks:** Report/history side effects, duplicate handling, and output ordering can accidentally change existing behavior. The judge authorization check is only a same-function-before-sink stub, not full control-flow proof.

## M4: New detectors using taint

- [x] M4: New detectors using taint: SQLi, XSS (echo/print), RCE / command injection, LFI / path traversal, SSRF, unauthenticated sensitive actions
  - **Goal:** Add source-to-sink XSS, SQLi, command injection, SSRF, upload, and path findings; check public WordPress AJAX callbacks and high-confidence hardcoded secrets without treating keyword-only matches as taint proof.
  - **Files touched:** `analyzer/php_parser.py`, `analyzer/taint.py`, `analyzer/detectors.py`, `analyzer/wordpress.py`, `main.py`, `tests/test_scanner.py`, `tests/test_v4_multi.py`, `BOOK.md`, `README.md`.
  - **Tests added:** Real-file end-to-end inputs for XSS, SQLi, AJAX auth, upload, traversal, secrets, command injection, and SSRF; sanitizer downgrade/audit, nonce-not-auth, guarded AJAX, upload-reference-only, unrelated file path, placeholder/comment-secret false positives, and echo/print parser location/malformed-input regressions.
  - **Done criteria:** All listed detector paths have explicit source/sink behavior and expected-output regressions; downgraded results remain in `v5_audit`; regex-mode V4 output remains compatible; limitations are documented.
  - **Risks:** The parser is still a PHP subset; AJAX callback support is literal/direct only, file boundaries and upload policies are not fully proven, and secret patterns are intentionally narrow.

## M5: Framework analysis

- [ ] M5: Framework analysis: WordPress hooks/actions, Laravel, Django, Node - identify entry points, routes, controllers
  - **Goal:** Add adapters for framework-specific entry points, routes/controllers, source/sink/sanitizer/authorization definitions, and only claim tested support.
  - **Implemented in this slice:** `analyzer/frameworks/wordpress.py` recognizes tested literal WordPress AJAX hooks, shortcode callbacks, and REST route callbacks. V4 mode is unchanged. Laravel, Django, and Node.js are still detected from markers only and receive no source-analysis claim.
  - **Files touched:** `analyzer/frameworks/__init__.py`, `analyzer/frameworks/wordpress.py`, `analyzer/taint.py`, `analyzer/wordpress.py`, `tests/test_v4_multi.py`, `BOOK.md`, `README.md`.
  - **Tests added:** Real-file CLI regression for `wp_ajax_nopriv_*`, privileged `wp_ajax_*` with capability proof, nonce-only AJAX handling, shortcode-to-XSS entry-point linking, REST routes with missing/`__return_true` permission callbacks, and a direct capability-check permission callback.
  - **Remaining for M5 completion:** Laravel route/controller analysis, Django URL/view analysis, Node.js/Express route/controller analysis, and their source/sink/auth tests.
  - **Risks:** WordPress dynamic callbacks, closures, callback arrays, complex permission functions, and cross-file registration/handlers are not resolved. Marker detection alone is insufficient support for the other frameworks.

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
