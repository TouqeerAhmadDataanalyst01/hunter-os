# Potential Unauthenticated File Upload in vuln-test

## Description

File upload input is present, but no capability or nonce check was found in this file.

This is a static-analysis heuristic, not a confirmed vulnerability. Review the surrounding code, data flow, and access controls before drawing conclusions.

**Source:** `test.php` at line 3

## PoC

No exploit request is generated. Validate behavior only in a local, isolated environment for which you have authorization.

## Impact

Not assessed. Impact depends on reachability, authentication requirements, input validation, and deployment configuration.

## CVSS

Not scored. A CVSS score requires manual validation and a confirmed impact assessment.

## Evidence

```text
1: <?php
2: // no auth check
3: if(isset($_FILES["f"])){
4:  move_uploaded_file($_FILES["f"]["tmp_name"], "/tmp/pwn.php");
5: }
```
