# Hunter OS A–Z Guide for Windows 10

This guide is for beginners using **Command Prompt** or **PowerShell**. You do not need a VS Code terminal. Hunter OS scans local plugin source files; it does not run the plugin.

## 1. What Hunter OS is

Hunter OS is an offline source-code review tool. Its default `regex` engine preserves the earlier V4 checks. The optional `taint` engine runs those checks alongside a bounded PHP parser and WordPress-focused source-to-sink analysis.

The taint engine can report potential:

- **SQL injection (SQLi):** request-derived data that appears to reach selected WordPress database query methods without a recognized SQL-safe preparation or validation path.
- **Cross-site scripting (XSS):** request-derived data that appears to reach parsed `echo` or `print` output without a recognized context-appropriate escaping path.

These are leads for a human reviewer, not confirmed vulnerabilities. The benchmark in this guide also demonstrates why: many candidate flows require interpretation, and the parser is intentionally incomplete.

### What it does not find or prove

Hunter OS is not a complete PHP parser or a general-purpose security scanner. It does not:

- Find every SQLi or XSS, or prove that a reported flow is exploitable.
- Analyze every PHP construct, dynamic callback, plugin interaction, or cross-file flow.
- Run the plugin, emulate WordPress, or test a live site.
- Analyze Laravel, Django, or Node.js security rules; identifying a project is not the same as supporting its analysis.
- Prove that a permission check is correct, or that a plugin is secure because no findings appeared.
- Replace a professional security review, code audit, or authorized testing process.

Only scan code you own or are authorized to review. Do not use a finding as a public accusation without independent verification.

## 2. Requirements

- Windows 10
- Git for Windows
- Python 3.11 or newer (the project supports Python 3.10+)
- Internet access for the initial Git clone and for obtaining plugin ZIPs; **the scanner itself does not need internet**
- A few hundred megabytes free for the repository, plugin archives, and extracted files

## 3. Install from Command Prompt

Open **Command Prompt** from the Windows Start menu. PowerShell works too; the examples below use `py`, which is commonly installed with Python on Windows.

Check that Git and Python are available:

```bat
git --version
py --version
```

Clone and enter the repository:

```bat
git clone https://github.com/TouqeerAhmadDataanalyst01/hunter-os.git
cd hunter-os
```

There is currently **no `requirements.txt`** in this repository. Hunter OS uses the Python standard library, so there is no dependency installation step; `pip install -r requirements.txt` would fail because that file does not exist. Check the command-line options:

```bat
py main.py --help
```

## 4. Prepare and scan a plugin

1. Obtain a plugin ZIP from a source you trust. For the historical WP Go Maps comparison below, use the exact 7.11.17 or 7.11.18 archive. Do not substitute the current latest release and assume it has the same code.
2. In File Explorer, right-click the ZIP and choose **Extract All…**.
3. Keep the extracted folder path handy. Point Hunter OS to the folder containing the plugin PHP files (the folder that contains the plugin's root files and directories such as `includes`).
4. In Command Prompt, scan the folder:

```bat
py main.py --engine=taint "C:\Users\YourName\Downloads\plugin-folder"
```

Replace the example path with your real path. Quotes are important when a path contains spaces. Use `--engine=regex` to run the V4-compatible checks only.

> **Command note:** this project does not have a `scan` subcommand. The form `py main.py scan C:\path\to\plugin` is not valid here: `scan` would be treated as the source path. Use `py main.py --engine=taint "C:\path\to\plugin"` instead.

### Three real examples

**Example A — scan a plugin folder**

```bat
py main.py --engine=taint "C:\Users\YourName\Downloads\contact-form-7"
```

This produces V4 and V5 results for the eligible PHP files in that folder.

**Example B — historical WP Go Maps 7.11.17**

After extracting the 7.11.17 ZIP, run:

```bat
py main.py --engine=taint "C:\Users\YourName\Downloads\wp-google-maps-7.11.17"
```

In the recorded test of that release, the vulnerable REST API path produced **2 active SQLi flows**. Review the report and confirm the exact source, query construction, affected version, and reachability before describing these as vulnerabilities.

**Example C — historical WP Go Maps 7.11.18**

After extracting the 7.11.18 ZIP, run:

```bat
py main.py --engine=taint "C:\Users\YourName\Downloads\wp-google-maps-7.11.18"
```

In the recorded test of that release, the corresponding CVE SQLi path had **0 active findings and 1 audit entry** labeled `allowlist fix recognized`. That audit entry is evidence that a narrow schema-derived allowlist pattern was recognized; it is not a blanket certification that the release or plugin is safe.

Folder scans write reports under the repository's `reports` directory. The folder name is used to create a report slug. A scan may return a nonzero exit code when it has findings; that alone does not mean the scan crashed.

## 5. Read the results

In taint mode, the JSON report preserves the separate result categories:

- **V4 findings (`findings`):** results from the earlier regex checks. Their shape and meaning are separate from the V5 taint results.
- **V5 active (`v5_taint_findings`):** taint results not downgraded by the judge. They need review; “active” does not mean confirmed exploitable.
- **V5 audit (`v5_audit`):** downgraded findings and incomplete-analysis records retained for inspection. Check the reason, trace, sanitizer evidence, authorization evidence, and notes.
- **V5 coverage (`v5_coverage`):** a status for each discovered PHP file. Unsupported, oversized, unreadable, or skipped in-scope files mean the scan is incomplete, not clean. Explicit exclusions show their paths and classifications.

### What “DOWNGRADED” means

The analysis found a source-to-sink path but recognized evidence that may reduce the risk, such as a context-appropriate sanitizer or a supported authorization guard. The finding is preserved in the audit data rather than silently removed. A downgrade is not a guarantee of safety: verify that the sanitizer is effective for the exact output/query context, and that any permission check protects the relevant operation.

### What “allowlist fix recognized” means

For the tested WP Go Maps 7.11.18 code shape, Hunter OS recognized a schema-derived database-column allowlist flowing through a query builder and placed the candidate in audit with that note. This is a narrow pattern recognizer, not a general proof engine. It does not establish that every SQL statement or every path in the plugin is safe.

## 6. Manually verify a candidate in five minutes

This is a quick triage checklist, not a substitute for a full review:

1. **Open the exact file and line.** Use Notepad, Notepad++, or another editor. Confirm the file belongs to the scanned release.
2. **Follow the trace from source to sink.** Identify the input (for example `$_GET`, `$_POST`, or a REST parameter), each assignment/call, and the output or database operation.
3. **Inspect the real operation.** For SQL, read the complete query and its preparation/bound values. For XSS, determine whether the output is HTML text, an attribute, a URL, JavaScript, or JSON.
4. **Check the mitigation in context.** Verify that values are actually passed to the escaping/preparation function and that the correct placeholder or output context is used. Sanitizing input is not automatically equivalent to escaping output.
5. **Check reachability and access.** Find how the function is registered or called. Determine whether a permission callback or capability check protects this operation; a nonce alone is not authorization.
6. **Record uncertainty.** If the parser marks the file incomplete, calls are dynamic, or the trace crosses unsupported code, label the result unverified and ask a qualified reviewer.

Do not test a client’s live site or send crafted requests as part of this five-minute check. Obtain written authorization and a separately approved test plan before any dynamic testing.

## 7. One-page client report template

Copy this section into a separate client document and fill it in. Do not include secrets, customer data, or unverified exploit claims.

### Hunter OS Source Review

**Client / project:**  
**Reviewer:**  
**Review date:**  
**Authorization / scope reference:**  
**Plugin name and version:**  
**Source archive / SHA-256 (if recorded):**  
**Hunter OS commit / engine:**  

**Scope and method:** Local, static source review only. Scanned files: ____. Incomplete files: ____. PHP parser subset limitations apply. No plugin code was executed and no live site was tested.

**Summary:**  
- V4 regex findings: ____  
- V5 active findings: ____  
- V5 audit / downgraded / incomplete records: ____  
- Manually confirmed issues: ____  
- Unresolved candidates: ____  

**Candidate 1**  
- Category and file:  
- Source → sink trace:  
- Manual verification performed:  
- Mitigation / access-control evidence:  
- Confidence and remaining uncertainty:  
- Recommended next step:  

**Conclusion:** These results are static-analysis leads, not a certification or proof of exploitability. Absence of findings does not prove the plugin is secure.

## 8. Common Windows 10 errors

### “`python` is not recognized” or “`py` is not recognized”

Check installation from Command Prompt:

```bat
py --version
python --version
```

If both fail, install Python 3.11 or newer from the official Python distribution and enable the option to add Python to PATH. Close and reopen Command Prompt, then check again. If Python is installed but `py` is unavailable, try `python main.py --help`.

### “`pip` is not recognized”

This project currently has no dependency requirements to install. If you need pip for another project, try:

```bat
py -m pip --version
```

Do not run `pip install -r requirements.txt` for this checkout; there is no `requirements.txt`.

### A path with spaces is split or not found

Put double quotes around the full path:

```bat
py main.py --engine=taint "C:\Users\Your Name\Downloads\My Plugin"
```

### “Expected a source directory or ZIP archive”

The path may be misspelled, may point to a file other than a ZIP, or may point to the ZIP’s parent folder instead of its extracted directory. Check it in File Explorer and quote it in the command.

### `py main.py scan ...` does not work

There is no `scan` subcommand. Use the supported positional path form:

```bat
py main.py --engine=taint "C:\full\path\to\extracted-plugin"
```

### The report says “incomplete parse”

Some PHP syntax is outside the parser’s implemented subset. The file is not a clean result: inspect it manually or use a PHP-aware review process. Do not treat an incomplete file as fully analyzed.

### The command finishes with a nonzero exit code

A nonzero code can indicate findings or an invalid source path. Read the console output and report files to distinguish those cases. A finding is not automatically a confirmed vulnerability.

## 9. Commands cheat sheet

Run these from the repository folder in Command Prompt:

| Purpose | Command |
|---|---|
| Show help | `py main.py --help` |
| Scan a folder with legacy V4 checks | `py main.py --engine=regex "C:\path\to\plugin"` |
| Scan a folder with V4 + V5 taint | `py main.py --engine=taint "C:\path\to\plugin"` |
| Scan a local ZIP | `py main.py --engine=taint "C:\path\to\plugin.zip"` |
| Set taint time budget | `py main.py --engine=taint --timeout 60 "C:\path\to\plugin"` |
| Scan one PHP file | `py main.py --engine=taint "C:\path\to\plugin.php"` |
| List eligible files for a configured target | `py main.py --target my-plugin --dry-run` |
| Run the test suite | `py -m unittest discover -s tests -v` |

Use `py main.py --target my-plugin` only when that slug is configured in `targets\wordpress.txt` and the plugin source is already available in the repository’s configured local source folders. Hunter OS does not download the target for you.

## 10. FAQ — 10 common questions

1. **Does Hunter OS upload my plugin source?**  
   No. The scanner analyzes local files and does not send source to a cloud service.

2. **Does the scanner execute PHP?**  
   No. It parses supported source constructs; it does not run scanned PHP.

3. **Do I need to install Python packages?**  
   No for the current checkout. It has no `requirements.txt` and uses the Python standard library.

4. **Which engine should I use?**  
   Use `regex` to preserve V4 behavior. Use `taint` to run V4 plus the opt-in bounded PHP/WordPress analysis.

5. **Does “0 active SQLi” mean the plugin is secure?**  
   No. The engine may miss flows, and analysis may be incomplete. It is not a security certification.

6. **Does a V5 active finding prove a vulnerability?**  
   No. It is a candidate source-to-sink flow requiring manual verification.

7. **Does “DOWNGRADED” mean I can ignore the issue?**  
   No. The finding remains in audit. Confirm the evidence and context before deciding its significance.

8. **Does a nonce prove a user is authorized?**  
   No. A nonce can help protect request integrity, but it is not a capability or authorization check.

9. **Why are some files listed as incomplete?**  
   They use syntax or analysis patterns that this bounded parser/engine cannot fully assess. Treat them as unreviewed by V5.

10. **Can I sell or advertise a plugin as “Hunter OS certified”?**  
    No. This project does not certify software. Describe the exact static review scope, engine, version, results, and limitations instead.

## 11. Benchmark proof and caveats

On 2026-11-05, Hunter OS scanned **25 latest-stable WordPress.org plugin archives**, covering **2,168 eligible PHP files**. The tuned result had **0 active SQL findings** and **14 active XSS-context findings**. Manual review confirmed 13 of those 14 XSS flow records as false positives; one Rank Math JSON-response flow remained unresolved. These are counts from a small convenience sample, not a general false-positive rate, vulnerability prevalence study, or proof that the scanned plugins are safe.

The benchmark table, versions, timings, audit counts, incomplete-file counts, and methodology are recorded in [BOOK.md](BOOK.md). One intended SEO sample (`yoast-seo`) was unavailable from the latest-stable endpoint during that benchmark; Rank Math was substituted.
