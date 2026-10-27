# How to Run Hunter-OS Manually

## Quick Start (2 min)

Hunter-OS scans plugin source already available in the workspace. It does not download plugins or contact external vulnerability databases.

1. Put the plugin source in `targets/plugins/file-manager/`, or download its ZIP manually and place it at `targets/archives/file-manager.zip`.
2. Run:

```bash
python main.py --target file-manager
ls reports/file-manager/
cat reports/file-manager/report_patchstack.md
```

If the plugin source or ZIP is missing, the scanner prints a manual download instruction and exits that target without making a network request. See `targets/archives/README.md` for the expected archive location.

To preview eligible source files without running heuristics or writing reports:

```bash
python main.py --target file-manager --dry-run
```

The scanner reports heuristic matches for manual review. A match is not a confirmed vulnerability, and reports do not generate exploit requests or assign an unverified severity score.

## Scan All Configured Targets

Add one plugin slug per line to `targets/wordpress.txt`, and provide local source or a local archive for each slug. Then run:

```bash
python main.py
```

## Run Tests

```bash
python -m unittest discover -s tests -v
```

## Exit Codes

- `0`: scan or dry-run completed without potential findings.
- `1`: one or more heuristic matches were found; review the reports manually.
- `2`: target, configuration, local source, or archive is missing or invalid.
- `3`: platform is ambiguous, unsupported, or has no implemented scanner.
- `4`: an internal source-directory or eligible-file listing error occurred.

Nearby authorization tokens are included as report context; they do not prove safety or hide the match. Results are saved in both Markdown and JSON under `reports/<slug>/`.