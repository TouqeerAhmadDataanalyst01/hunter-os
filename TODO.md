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

## M6: Mass scanner + parallel polish

- [x] M6: Mass scanner + parallel polish - scan folder/ZIP, preserve V4 history dedupe and regex output, add taint-mode V5 fields, and bound analysis.
  - **Goal:** Scan local WordPress source directories and ZIPs without changing V4 regex behavior; run taint analysis alongside existing checks in opt-in mode.
  - **Files touched:** `main.py`, `analyzer/wordpress.py`, `tests/test_v4_multi.py`, `TODO.md`, `BOOK.md`.
  - **Tests added:** Folder taint report and duplicate-history preservation; ZIP regex report shape and temporary extraction cleanup; malformed, empty, oversized PHP; timeout and file-count limit visibility.
  - **Done criteria:** Folder/ZIP scans create reports, regex retains the V4 JSON-list shape and dedupe, taint adds only V5 JSON fields, scan bounds are visible, malformed input does not crash.
  - **Risks:** The timeout is cooperative between bounded file analyses, not a way to terminate Python work mid-file. The mass path is capped at 10,000 PHP files; it is not a benchmarked overnight-scale scanner.

## M7: Reporting + docs

- [ ] M7: Reporting + docs - render taint traces, confidence, sanitizer/auth evidence, and audit results in Markdown; update BOOK.md and README.md.
  - **Goal:** Make V5 evidence and remediation visible while preserving V4 report content when V5 data is absent.
  - **Files to touch:** `reporter/patchstack.py`, report tests, `BOOK.md`, `README.md`.
  - **Tests to add:** V4 Markdown byte-compatibility; V5 trace, confidence, remediation, sanitizer/auth evidence, and `v5_audit` sections; safe Markdown escaping.
  - **Done criteria:** V5 Markdown shows source-to-sink evidence and judge downgrades; docs describe current flags, folder/ZIP input, actual WordPress-only scope, parser and time/file limits.
  - **Risks:** Schema/report drift, unsafe rendering of source-controlled text, or claiming unsupported framework and PHP syntax coverage.
