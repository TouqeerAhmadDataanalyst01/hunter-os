# Hunter OS

Hunter OS is an offline source-review tool. It can identify WordPress, Laravel, Django, and Node.js project markers. **Only WordPress PHP analysis is implemented**; the other platforms are identified but skipped without a security scan.

Use `--engine=regex` (the default) for V4 behavior, or `--engine=taint` to run the unchanged V4 checks alongside bounded PHP taint and WordPress-specific checks. The opt-in engine detects tainted data reaching HTML output, SQL, shell, file, upload, and outbound-request sinks; analyzes literal WordPress AJAX hooks, shortcode callbacks, and REST route callbacks; and reports selected high-confidence hardcoded credential patterns. These are potential findings requiring review, not confirmed vulnerabilities.

The parser remains an explicitly bounded PHP subset, not a complete PHP AST. Laravel, Django, and Node.js project markers can be identified, but their routes and handlers are not analyzed. A single PHP file can be scanned with either engine; the direct-file form prints JSON to stdout. Taint mode also accepts a source directory or local ZIP archive, with reports written to disk. Folder and ZIP scans are limited to 10,000 PHP files, and `--timeout` is a cooperative taint-analysis budget checked between bounded per-file analyses. Sanitized or same-function authorization-guarded findings are retained in `v5_audit`; only active findings appear in `v5_taint_findings`. Markdown reports include V5 traces and evidence. No scanned PHP is executed.

Use Python 3.10 or newer. No packages or API keys are needed. Configured plugin source must already exist in `targets/plugins/<slug>/` or `targets/archives/<slug>.zip`; direct folder and ZIP inputs are read from their supplied local paths. The program never downloads targets or contacts vulnerability databases.

```bash
python main.py --target vuln-test
python main.py --target vuln-test --dry-run
python main.py --target vuln-test --engine=taint
python main.py --engine=taint /path/to/vuln.php
python main.py --engine=taint /path/to/plugin-directory
python main.py --engine=taint --timeout 60 /path/to/plugin.zip
python -m unittest discover -s tests -v
```

Plugin-scan results are written to `reports/<slug>/report_patchstack.md` and `reports/<slug>/report_json.json`. Folder/ZIP scan reports use a slug derived from the supplied path. Duplicate history is local at `reports/history.json`. The direct-file form writes its combined V4/V5 JSON result to stdout. Every match is a heuristic requiring manual verification; nearby auth tokens are recorded as context and do not suppress a match. Regex mode remains the default and preserves V4 report behavior.

See [MANUAL.md](MANUAL.md) for a quick start and [BOOK.md](BOOK.md) for the full guide. GitHub Actions runs tests and compilation only; it does not scan plugin targets.