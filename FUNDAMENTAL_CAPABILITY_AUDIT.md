# Hunter OS V5 — Fundamental Capability Audit

**Audit date:** 2026-11-06
**Scope:** Read-only architecture and test review of the current repository. No scanned plugin code was executed.

## Executive assessment

Hunter OS is more than a pattern matcher, but it is not a general-purpose static application security analyzer. In `--engine=taint` mode, it parses a bounded subset of PHP into a lightweight representation, follows selected tainted values through assignments and some same-file calls, and matches them to configured sinks. This is meaningful data-flow analysis within a narrow subset.

Important limitations are foundational: expressions are mostly opaque text spans rather than a full AST, control flow is approximated, call resolution is limited, framework entry points are recognized from literal patterns, and security decisions rely on narrow syntactic proofs. A file can be marked syntactically complete without its full PHP semantics being modeled.

The test suite run during this audit reported **118 passing tests**. This establishes behavior for the tested fixtures, not detection accuracy.

## Architecture

```text
Directory / ZIP / PHP file
  ↓
PHP-file inventory and path-based exclusions
  ↓
Bounded lexer and partial PHP parser
  ↓
Lightweight Program / statement representation
  ↓
Selected sources → bounded taint propagation
  ↓
Configured sinks and parsed echo/print output
  ↓
WordPress literal-hook / route checks
  ↓
Syntactic sanitizer and authorization evidence
  ↓
Judge marks some findings DOWNGRADED; evidence retained in audit
  ↓
JSON / Markdown reports and coverage statuses
```

This is not a full AST-to-CFG pipeline. Expression structure, call resolution, control flow, authorization, and framework behavior are approximated or rule-based.

## 1. Source-code coverage

PHP discovery is implemented in `analyzer/wordpress.py` by `_discover_php_files()` and `_coverage_report()`. It inventories `.php` files recursively. Path components named `vendor`, `node_modules`, `dist`, `.git`, `__pycache__`, `tests`, and `test` are intentionally excluded and recorded with classifications. Symlinks and enumeration errors are recorded as skipped; source-size, read, parser, file-count, and timeout limitations are represented in coverage data.

Coverage can demonstrate that discovered files were assigned a status. It cannot prove that all *relevant code* was analyzed:

- Non-PHP sources and PHP code loaded from unmodeled paths are outside the inventory.
- Excluded files are not checked for whether in-scope code calls or includes them.
- `coverage.complete` means no known inventory/parser/analysis gap was recorded. It does not mean all PHP syntax or all relevant execution paths were understood.
- Unsupported syntax that the shallow parser fails to diagnose can still lead to an apparently complete analysis.

## 2. PHP understanding

`analyzer/php_parser.py` contains a standard-library lexer and bounded parser. It records source locations and represents named functions, classes/interfaces/traits, methods, simple properties, assignments, calls, output, returns, `if`, `switch`, common loop forms, and `try/catch/finally`. Limits include 2 MB, 2,000 lines, 200,000 tokens, and nesting caps.

The parser does not build a complete expression tree or model full PHP semantics. Ternary, null-coalescing, arrays, interpolation, and many calls are extracted from token spans. Namespaces/imports are retained but aliases, inheritance, trait composition, dynamic dispatch, and callback arrays are not generally resolved. Loop iterations, switch fall-through, and exception paths are approximated.

Closures and arrow functions are **not analyzed as bodies**. They trigger an incomplete-analysis diagnostic, which prevents a clean result for a diagnosed closure, but also stops taint analysis for the entire file. The test `test_closures_and_arrow_functions_are_supported` verifies incomplete diagnostics—not closure flow analysis.

### Confirmed syntax-shaped gaps

An in-memory, non-executing probe found:

- `include $path;` parsed as complete but produced no taint flow. `include($path);` was recognized.
- A sensitive `wp_delete_post()` inside a `switch` was not found by WordPress AJAX call collection, despite the file being parsed complete. The framework collector traverses `if` branches but not `ControlStatement` bodies.
- An escaped short echo within a `<script>` context was classified as HTML and treated as mitigated, because output context is determined from the individual PHP expression rather than the enclosing document.

These probes are architecture checks, not added tests or claims about a specific plugin.

## 3. Detector-by-detector capability matrix

| Category | Implemented behavior | Principal limitations and risks |
|---|---|---|
| **SQL injection** | Taints selected request sources and reports flows to selected `$wpdb` query methods. Includes narrow `$wpdb->prepare` and query-builder/allowlist patterns. | No SQL parser, identifier/value distinction, or general query-builder semantics. Prepared-query proofs are pattern-based. A capability check can downgrade SQL findings even though authorization does not sanitize SQL. |
| **XSS** | Tracks taint to parsed `echo`, `print`, and inline output; recognizes selected escaping functions and estimates contexts with string patterns. | Context detection is not aware of surrounding HTML across PHP boundaries. The script-context probe above was considered mitigated. `printf`, many rendering APIs, and template behavior are not modeled. |
| **Authorization bypass** | V4 has a weak cookie/boolean text pattern. V5 models selected sensitive-action flows and some same-function capability guards. | No general authorization analysis, role/capability sufficiency model, or proof of path dominance. A recognized capability check may not protect the operation. |
| **CSRF** | Nonce calls may be recorded as evidence; nonce is not treated as authorization. | No genuine CSRF detector: no model of browser-originated state changes, cookies, forms, or whether request verification is required and validated on all relevant paths. |
| **WordPress AJAX authorization** | Recognizes literal `wp_ajax_*` registrations and selected sensitive calls; checks capability guards and keeps nonce evidence separate. | Literal callbacks only; no closure/array/dynamic callback resolution. Framework call collection misses calls under `switch`, loops, and `try`. Sensitive operation list is finite. |
| **WordPress REST authorization** | Recognizes literal `register_rest_route` options and direct string callbacks. A permission callback directly returning a recognized capability call is accepted as proof. | Does not resolve common callback arrays, closures, aliases, dynamic options, or cross-file registrations. It does not establish that the capability is sufficient. `__return_false` is not recognized as a safe deny-all callback. |
| **File upload** | Reports selected upload API calls when tainted file data reaches a modeled argument; improves on V4’s `$_FILES`-alone heuristic. | Does not prove MIME/extension/destination safety, executable-file risk, or authorization. Safe fixed-destination uploads may be reported; V4 may flag harmless `$_FILES` references. |
| **Path traversal / file include** | Tracks taint to selected filesystem calls and parenthesized `include`/`require` calls. | No general canonicalization or directory-boundary proof. Safe `realpath`/allowlist logic is not generally understood. Bare `include $path;` can be silently missed. |
| **Command injection** | Selected shell APIs are sinks for tainted arguments. | No shell grammar, argument-position, command-construction, or escaping proof. Safe escaping may be flagged; unsupported APIs may be missed. |
| **SSRF** | Selected outbound APIs (`wp_remote_get`, `wp_remote_post`, `curl_init`) are sinks for tainted arguments. | No URL parser, scheme/host policy, DNS/rebinding, redirect, or allowlist analysis. Safe fixed-host validation may still be flagged; other clients may be missed. |
| **Hardcoded secrets** | Regex/entropy checks for private-key headers, AWS-style access-key strings, and high-entropy values assigned to credential-like names. | Lexical detection, not credential verification. Other formats can be missed; placeholder filtering can suppress values that happen to contain placeholder terms. |

Registry entries in `analyzer/taint.py` are definitions, not proof of comprehensive category coverage.

## 4. Data flow, sanitization, and authorization

`analyzer/taint.py` tracks configured sources through variable assignments, selected array/interpolated values, nested call arguments, direct uniquely resolved same-file calls and returns, and simple branch merges. Call depth defaults to three. Unknown calls propagate tainted arguments conservatively.

It does not provide a complete call graph, include graph, global-state model, object heap, or cross-file data flow. Same-file object support is narrow; general object property state and method side effects are not modeled. Functions are also analyzed independently with empty arguments, regardless of whether they are reachable, which can create findings in dead or unregistered code.

Sanitizer evidence is tied to selected calls and contexts, but it does not amount to a general semantic proof. The judge in `analyzer/wordpress.py` downgrades findings when it sees effective sanitizer evidence **or same-function authorization evidence**, without limiting authorization-based downgrades to authorization-sensitive categories. Consequently, authorization can downgrade SQL, XSS, command, path, or URL findings without making those values safe for their sink.

The same-function guard check is syntactic. It checks selected `if` forms and statement ordering, but not general CFG dominance, capability suitability, framework policy, or all possible paths. REST permission proof accepts a direct return of selected capability checks, not an independently validated permission policy.

## 5. Critical false-positive and false-negative risks

### High priority

1. **Authorization downgrades unrelated vulnerability types.** `_judge_taint_findings()` applies authorization evidence generically. Existing tests explicitly expect a guarded SQL query finding to be downgraded. Authorization may affect reachability, but it does not sanitize SQL or output.
2. **Framework call discovery misses parsed control-flow nodes.** The taint engine handles `ControlStatement`, but WordPress-specific call collection does not recursively traverse it. The switch/AJAX probe produced no finding and no incompleteness warning.
3. **Output context can be wrong across PHP/HTML boundaries.** The script-context probe was reported as mitigated HTML output, risking a false negative for JavaScript-context XSS.
4. **Bare include/require syntax can be silently missed.** `include $path;` parsed complete but had no sink flow.
5. **Authorization proof does not establish adequate permission.** Recognizing `current_user_can()` does not establish that the requested capability protects the operation.

### Additional risks

- Branches and loops are merged/visited approximately, causing overtaint and missed loop-carried or path-specific behavior.
- Dynamic dispatch, namespace aliasing, inheritance, callbacks, and cross-file flows are incomplete.
- Narrow sanitizer and query-builder patterns can produce both false positives and false negatives.
- Coverage exclusions are explicit but not dependency-aware; excluded code may still be security-relevant to included code.
- A complete coverage status is not equivalent to a complete syntax or semantic analysis.
- Time budgets are cooperative/after-the-fact, not hard interruption guarantees; executor shutdown waits for running work.

## 6. Validation and evidence

The current 118 tests are predominantly synthetic PHP snippets and hand-authored fixture files. They establish selected parser diagnostics, traces, sanitizer/authorization examples, framework patterns, report shapes, coverage dispositions, and CLI compatibility.

Examples in `tests/real_files/`—including `vuln_xss.php`, `safe_xss.php`, `vuln_sqli.php`, and `vuln_traversal.php`—are constructed examples, not independently verified vulnerabilities in released plugins. Their expected outputs validate those exact inputs only.

`BOOK.md` records a 25-plugin benchmark and manual review of candidate flows. It reports high false-positive counts among reviewed SQL and XSS flow records, including unresolved cases. This is useful empirical evidence but is not a labeled vulnerable/fixed corpus and cannot establish general recall, precision, or exploitability.

`GUIDE.md` documents historical WP Go Maps 7.11.17/7.11.18 results. The current test suite does not contain a reproducible vulnerable/fixed source pair or automated CVE regression. This audit did not independently verify that ground truth offline.

## 7. Missing foundational components

- A structural, versioned PHP AST/IR with grammar validation and explicit unsupported-node handling.
- A CFG with sound branch dominance, returns, exceptions, and bounded loop fixed-point analysis.
- A bounded, ambiguity-aware call/include graph and callback/closure resolution.
- Explicit heap, global, and framework request-state models.
- Sink-specific sanitizer proofs; authorization must not substitute for data sanitization.
- An authorization policy model that distinguishes request integrity (nonce/CSRF) from permissions and checks capability suitability.
- A reproducible, independently verified vulnerable/fixed corpus with source hashes and review notes.
- Per-detector precision/recall measurements on labeled cases; current tests do not provide these metrics.

## 8. Staged redesign plan

1. **Define fail-closed syntax boundaries.** Maintain a versioned PHP syntax corpus and verify that unsupported or ambiguously parsed constructs always make analysis incomplete.
2. **Build a structural IR.** Preserve expression trees, class/name metadata, and source locations. Model `include`/`require`, namespaces/aliases, closures, callback arrays, and common constructs—or explicitly reject them.
3. **Add CFG and bounded data-flow semantics.** Model branch dominance, exceptions, loops to a bounded fixed point, globals, and same-plugin call/include edges.
4. **Separate reachability from sanitization.** Apply sink-specific proofs. Authorization can affect exposure but must never sanitize SQL, HTML, shell commands, paths, or URLs.
5. **Implement framework security models independently.** Treat AJAX authorization, REST permission policy, and CSRF/request integrity as separate analyses.
6. **Create verified ground truth before adding detector types.** Include vulnerable/fixed versions, source hashes, independent verification notes, positive/negative cases, and expected incomplete statuses.
7. **Rebenchmark after correctness work.** Keep coverage gaps, unsupported files, audit counts, and unresolved findings visible. “No active findings” must not mean “clean.”

## 9. Claims Hunter OS must not make yet

- Complete PHP parsing, full control-flow/call-graph analysis, or sound whole-plugin taint analysis.
- General cross-file analysis or reliable dynamic callback/include resolution.
- Comprehensive SQLi, XSS, authorization, CSRF, upload, traversal, command-injection, or SSRF detection.
- That a `DOWNGRADED` finding is safe, or that complete file coverage means a plugin is secure.
- General detection accuracy, false-positive rate, or false-negative rate based on the current tests or convenience benchmark.
- Laravel, Django, or Node.js security analysis; those platforms are marker-detected, not supported analyzers.
