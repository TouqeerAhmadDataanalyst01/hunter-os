# Hunter OS V4: A Practical Guide

## Contents

1. [What Hunter OS Is](#1-what-hunter-os-is)
2. [What It Does Today](#2-what-it-does-today)
3. [Requirements and Setup](#3-requirements-and-setup)
4. [Where Files Go](#4-where-files-go)
5. [How a Scan Runs](#5-how-a-scan-runs)
6. [Platform Detection](#6-platform-detection)
7. [WordPress Checks and Filters](#7-wordpress-checks-and-filters)
8. [Understanding Findings](#8-understanding-findings)
9. [Reports and Duplicate History](#9-reports-and-duplicate-history)
10. [Commands You Can Use](#10-commands-you-can-use)
11. [Tests and GitHub Actions](#11-tests-and-github-actions)
12. [Troubleshooting](#12-troubleshooting)
13. [Limitations and Safe Use](#13-limitations-and-safe-use)

## 1. What Hunter OS Is

Hunter OS is a Python command-line program for reviewing source code that is already available on your machine. It uses local files, simple pattern checks, and Markdown reports. It does not need API keys, and its scanner does not send source code or scan results to a remote service.

The current V4 branch adds project-platform identification and an explicit platform option. It is not yet a multi-language vulnerability scanner: only the existing WordPress-oriented PHP checks run. Laravel, Django, and Node.js projects can be identified, but the program tells you that their security rules are not implemented and skips scanning them.

A useful mental model is:

> Hunter OS highlights code worth a human review. It does not prove that a vulnerability exists.

## 2. What It Does Today

The current implementation can:

- Read plugin slugs from `targets/wordpress.txt`.
- Use source from a local plugin directory or extract a ZIP already stored in the repository.
- Identify WordPress, Laravel, Django, or Node.js from conventional marker files.
- Run three existing text-pattern checks on in-scope PHP files for a WordPress project.
- List checked files and summarize skipped paths, including oversized, unreadable, and out-of-scope sources.
- Parse a documented subset of PHP into source-located functions, methods, assignments, calls, returns, and conditional branches. This parser is not yet used by vulnerability detection.
- Ignore common generated and dependency directories.
- Look for selected authorization-related tokens near a match and record them as context without suppressing the finding.
- Write Markdown and JSON reports and keep local duplicate history.
- Preview eligible source paths with `--dry-run` and return meaningful exit codes.
- Run its tests locally and in GitHub Actions.

It does not download targets, query vulnerability databases, generate exploit requests, calculate payouts, or assign a verified severity score.

## 3. Requirements and Setup

Use Python 3.10 or newer. The application and tests use the Python standard library; no `pip install` step or API key is required.

Open a terminal at the repository root and check Python:

```bash
python --version
```

Run the test suite:

```bash
python -m unittest discover -s tests -v
```

Run the compile check used by CI:

```bash
python -m compileall -q main.py analyzer tests
```

## 4. Where Files Go

### Targets

`targets/wordpress.txt` is the current slug list. Despite its name, it is also the list that `main.py --target` validates against. Add one valid slug per line. Blank lines and lines beginning with `#` are ignored, and duplicate slugs are removed.

For slug `my-plugin`, provide one of these:

```text
targets/plugins/my-plugin/       # extracted local source
```

or:

```text
targets/archives/my-plugin.zip   # ZIP you obtained and saved locally
```

The directory source takes precedence if both are present. ZIP extraction uses a unique directory below `/tmp/plugins/`; a later scan extracts into a new isolated directory instead of reusing stale content. Hunter OS does not delete earlier extraction directories.

### Reports

Reports are written under `reports/<slug>/`. The Markdown report is named `report_patchstack.md`; the name is just a local report filename and does not mean that Patchstack is contacted. Duplicate observations are saved in `reports/history.json`.

## 5. How a Scan Runs

When you run `python main.py --target my-plugin`, the program:

1. Parses the command-line arguments.
2. Confirms `my-plugin` appears in `targets/wordpress.txt`.
3. Looks for `targets/plugins/my-plugin/`, then `targets/archives/my-plugin.zip`.
4. Extracts a local ZIP if needed, enforcing archive/member/expanded-size limits and path/symlink checks in a new isolated directory.
5. Detects the project platform unless you chose `--platform` explicitly.
6. Runs the WordPress PHP heuristics only if the selected platform is `wordpress`.
7. Prints the count of files checked by the existing heuristics and summarizes files/trees not analyzed, with example paths.
8. Prints the potential-finding count and how many matches have a nearby auth token.
9. Writes JSON for all matches from the current run. A nearby auth token is context, not proof the operation is protected.
10. Skips duplicate Markdown/history entries recorded in the previous 14 days; new findings are appended to Markdown and recorded in local history.

The scanner does not start WordPress or execute plugin code. It reads source as text.

## 6. Platform Detection

Automatic detection looks for these marker files:

| Platform | Marker |
| --- | --- |
| WordPress | `wp-config.php` |
| Laravel | `artisan` |
| Django | `manage.py` |
| Node.js | `package.json` |

Marker searches ignore `vendor`, `node_modules`, `dist`, `.git`, and `__pycache__` directories. If exactly one platform marker is found, that platform is selected. If multiple markers are found, detection is ambiguous and returns no platform. If no marker is found but a non-ignored PHP file exists, the project is treated as WordPress, which supports standalone plugin packages.

Select automatic detection or force a platform with:

```bash
python main.py --target my-plugin --platform auto
python main.py --target my-plugin --platform wordpress
python main.py --target laravel-app --platform laravel
python main.py --target django-app --platform django
python main.py --target node-app --platform nodejs
```

A forced platform changes the platform selection; it does not add rules. For Laravel, Django, and Node.js, the current CLI prints a notice and does not run vulnerability checks. Do not interpret that as a clean security result.

## 7. WordPress Checks and Filters

The analyzer currently considers `.php` files at the project root and beneath `includes/`, `admin/`, and `public/`. It ignores files inside directory components named `vendor`, `node_modules`, `dist`, `.git`, `__pycache__`, `tests`, or `test`. Matching is case-insensitive for directory names. A filename containing the word `vendor` is not excluded unless a parent directory has that name.

### PHP parser foundation

`analyzer/php_parser.py` is an offline, standard-library-only parser foundation. It recognizes named functions, classes and methods, simple assignments, variable references, call expressions, returns, and `if`/`elseif`/`else` branches. It preserves file, line, column, and offset locations. Expression text is retained as a bounded token span with its variable references and recognized calls; it is not a full expression AST.

The supported subset does not include namespaces/imports, class inheritance/interfaces, typed/defaulted/reference/variadic parameters, return types, loops, switch/try constructs, closures/arrow functions, interpolated strings, heredoc/nowdoc, PHP attributes, short echo tags, inline HTML, or PHP-specific statements such as `echo` and `include`. Those constructs produce diagnostics, and any diagnostic makes `Program.complete` false. Malformed delimiters, source/token limits, and unreadable files likewise cannot be reported as a complete parse. Expressions are retained as opaque token spans rather than fully grammar-validated expression trees, so `complete` means no known unsupported construct or structural parse error was encountered—not full PHP syntax validation. This foundation is not yet connected to scanning or vulnerability findings; the existing regex checks remain operational.

### Taint engine foundation (M2)

`analyzer/taint.py` can be called independently with a parsed `Program` and configurable source, sink, sanitizer, and propagator definitions. Its initial registry includes common WordPress request sources, selected SQL/command/file/network call sinks, and context-labeled sanitizer examples. It follows simple and compound variable assignments, nested call arguments/returns, and both sides of `if` branches. It never uses nearby authorization tokens as protection. Context-matched sanitizer evidence marks a flow as mitigated but preserves it in the result; a sanitizer for another context does not. Nonce verification is only labeled as nonce evidence and is not authorization proof.

The engine refuses to analyze a parser result with diagnostics. Its default bounds are 8 nested user-function calls, 100,000 execution steps, 10,000 flows, and 10,000 tainted values per variable. Limit exhaustion retains any partial flows but marks the result incomplete and adds a diagnostic. Unknown calls conservatively propagate tainted arguments. Branches are merged without proving conditions, and functions are examined independently because framework entry points are not implemented. Complex PHP expressions, aliases, and cross-file calls are not modeled. The CLI's default `--engine=regex` path retains the V4 JSON list and report behavior; `--engine=taint` runs regex and taint analysis and writes a JSON object with the unchanged V4 records under `findings`, plus `v5_taint_findings` and `v5_audit`.

The M3 judge stub downgrades but retains flows when a sanitizer is effective for that sink context or when a recognized `current_user_can()`/`user_can()` condition guards the sink in the same function. It recognizes a sink inside the permission-true branch, or a sink after a negated permission check whose denied branch terminates. This limited check does not prove permission sufficiency, complete control-flow dominance, or framework callback policy. Nonce checks are not authorization proof. Downgrades are copied into `v5_audit`; incomplete parses are emitted as low-confidence findings with an explicit `incomplete parse` note. This opt-in path does not implement M4 detector rules, framework entry points, or V5 Markdown reporting.

Each source file is limited to 2 MB. The current text heuristics look for:

- **File upload input:** `$_FILES`.
- **SQL query input:** `$wpdb->query(` with `$_POST` in the same query text within a limited character range.
- **Cookie boolean comparison:** `$_COOKIE` near `== true` or `true ==`.

These are deliberately rough signals. The upload check sees the input token; it does not prove that an unsafe file is stored. The SQL check does not perform full data-flow analysis. The cookie check does not understand the surrounding authorization design.

### Nearby authorization tokens

Within the 50 lines before the matched token, the analyzer looks for any of these strings:

- `current_user_can`
- `check_ajax_referer`
- `check_admin_referer`
- `wp_verify_nonce`
- `is_user_logged_in`
- `permission_callback`

If any appears, the match remains `POTENTIAL`, but `auth_present` is set to `true` and the token is recorded. This is only a context clue: it does not prove the check protects this code path. Matches with or without a token require manual review.

## 8. Understanding Findings

A report heading starts with `Potential`. That word matters: a pattern match is not a confirmed bug. Review the referenced file and line in context, then verify the data flow, access controls, sanitization, and whether the code can actually be reached.

The Markdown report contains:

- Finding type and plugin slug.
- Relative source filename and line number.
- A short explanation of the heuristic.
- A small excerpt of source as evidence.
- Confidence, nearby-auth context, and an explicit manual-verification flag.
- Sections for PoC, Impact, and CVSS that explicitly avoid inventing those details.

The JSON report `report_json.json` is overwritten each run and describes that run's findings. It includes file, line, type, confidence, auth presence, platform, evidence, status, and `manual_verification_required`.

No exploit code or request is generated. The report's PoC section is an authorization and manual-review note.

## 9. Reports and Duplicate History

The report is appended to rather than replaced, so multiple findings for one slug can coexist in `reports/<slug>/report_patchstack.md`.

Before appending, the program checks `reports/history.json` for the same plugin slug, relative filename, and line number recorded within 14 days. If found, it prints a duplicate message and skips the report write. A changed line number is considered a new location. Deleting a report does not delete its history, so a repeat may be skipped until the history entry is older than 14 days or is removed manually.

Treat the history file as local workspace data. It is not a remote vulnerability database.

## 10. Commands You Can Use

Scan one configured target:

```bash
python main.py --target vuln-test
```

Scan every slug in `targets/wordpress.txt`:

```bash
python main.py
```

Choose a platform explicitly:

```bash
python main.py --target my-plugin --platform wordpress
```

List eligible files without running the heuristics or writing reports:

```bash
python main.py --target my-plugin --dry-run
```

The CLI returns `0` for a clean scan/dry-run, `1` when matches exist, `2` for missing or invalid target/source/archive configuration, `3` for ambiguous or unsupported platform handling, and `4` for internal source-directory or eligible-file listing errors.

Inspect reports and history:

```bash
ls reports/my-plugin/
cat reports/my-plugin/report_patchstack.md
cat reports/history.json
```

Run all automated tests:

```bash
python -m unittest discover -s tests -v
```

## 11. Tests and GitHub Actions

`tests/test_scanner.py` covers the current WordPress heuristic and local archive/history/report behavior. `tests/test_v4_multi.py` covers platform markers, ambiguous marker handling, the platform CLI override, the authorization window, JSON output, dry-run, exit codes, temporary report storage, and synthetic inclusion/exclusion cases.

The workflow at `.github/workflows/tests.yml` runs compileall and the unit suite on Python 3.10, 3.11, and 3.12 for pushes and pull requests. It does not download plugins or run target scans. GitHub Actions must fetch its checkout/setup actions and Python runtime, but the Hunter OS scanner itself makes no remote requests.

## 12. Troubleshooting

### `Target is not listed`

Add the exact slug on its own line in `targets/wordpress.txt`. Make sure a previous line ends with a newline so two names do not accidentally join together.

### `No local source was found`

Put source in `targets/plugins/<slug>/` or put a locally obtained ZIP at `targets/archives/<slug>.zip`. Hunter OS will not fetch it for you.

### `Could not detect a supported project platform`

Check for the expected marker file. If it is a WordPress plugin without `wp-config.php`, ensure it contains a root or non-ignored PHP file. If conflicting framework markers exist, choose a platform explicitly.

### No report appears

Check the CLI output for a duplicate. Also confirm the PHP file is within the permitted directories, is not under an ignored directory, and is no larger than 2 MB. A nearby auth token is shown as context but does not suppress report generation.

### ZIP extraction errors

Use a valid local ZIP and check for suspicious archive paths, symlinks, oversized archives, or oversized individual files. Extraction is limited to 100 MB compressed input, 10,000 members, 20 MB per member, and 200 MB total expanded data; the extractor streams files and rejects unsafe members.

## 13. Limitations and Safe Use

- V4 identifies WordPress, Laravel, Django, and Node.js, but only WordPress has source heuristics today.
- The current vulnerability checks remain regular expressions, not data-flow analysis. The separate PHP parser supports only a documented subset and is not a complete PHP AST.
- The M2 taint engine is a standalone analysis foundation, not a scanner detector. Its flows are conservative evidence, not proof of exploitability or authorization failure.
- `LIKELY SAFE` is not proof of safety; absence of a match is not proof that the project is secure.
- The scanner analyzes local source only and does not execute it, contact external services, or validate behavior in a running application.
- The project does not generate exploit requests, assign bounty values, or produce verified severity scores.
- Only scan code you own or are authorized to review. Handle source archives and generated reports as potentially sensitive files.

For a short run checklist, see [MANUAL.md](MANUAL.md).
