# Hunter OS v2

Hunter OS v2 is a small, offline source-review helper for WordPress plugins you are authorized to inspect. It uses Python's standard library and makes no network requests.

## Setup

Use Python 3.10 or newer. No packages or API keys are required.

Place plugin source in `targets/plugins/<slug>/`, or place a ZIP you already have in `targets/archives/<slug>.zip`. The list of slugs is `targets/wordpress.txt`. The tool does not download plugin archives from WordPress.org.

Run the scanner from the repository root:

```sh
python main.py
```

The checks flag heuristic patterns involving `$_FILES`, `$wpdb->query` and `$_POST`, or cookies and comparisons with `true`. A match is not proof of a vulnerability. Confirm data flow, nonce and capability checks, reachability, and impact manually.

Markdown review notes are saved under `reports/<slug>/report_patchstack.md`. The local duplicate history is `reports/.finding_history.json` and uses a 14-day window. No requests are sent to Patchstack, Wordfence, or any other service. Reports intentionally do not generate exploit requests, payout estimates, or unverified CVSS scores.

## Tests

```sh
python -m unittest discover -s tests -v
```