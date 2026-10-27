# Hunter OS

Hunter OS is an offline source-review tool. It can identify WordPress, Laravel, Django, and Node.js project markers. **Only WordPress PHP heuristics are implemented**; the other platforms are identified but skipped without a security scan.

Use Python 3.10 or newer. No packages or API keys are needed. Source must already exist in `targets/plugins/<slug>/` or `targets/archives/<slug>.zip`; the program never downloads targets or contacts vulnerability databases.

```bash
python main.py --target vuln-test
python main.py --target vuln-test --dry-run
python -m unittest discover -s tests -v
```

Results are written to `reports/<slug>/report_patchstack.md` and `reports/<slug>/report_json.json`. Duplicate history is local at `reports/history.json`. Every match is a heuristic requiring manual verification; nearby auth tokens are recorded as context and do not suppress a match.

See [MANUAL.md](MANUAL.md) for a quick start and [BOOK.md](BOOK.md) for the full guide. GitHub Actions runs tests and compilation only; it does not scan plugin targets.