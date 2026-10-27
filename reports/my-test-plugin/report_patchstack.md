# Potential Unauthenticated File Upload in my-test-plugin

## Description

File upload input is present, but no capability or nonce check was found in this file.

This is a static-analysis heuristic, not a confirmed vulnerability. Review the surrounding code, data flow, and access controls before drawing conclusions.

**Source:** `my-test-plugin.php` at line 6

## PoC

No exploit request is generated. Validate behavior only in a local, isolated environment for which you have authorization.

## Impact

Not assessed. Impact depends on reachability, authentication requirements, input validation, and deployment configuration.

## CVSS

Not scored. A CVSS score requires manual validation and a confirmed impact assessment.

## Evidence

```text
4: */
5: // Test Case 1 - should be flagged as file upload
6: if (isset($_FILES['file'])) {
7:   move_uploaded_file($_FILES['file']['tmp_name'], '/tmp/uploaded');
8: }
```

---

# Potential Unauthenticated SQL Injection in my-test-plugin

## Description

A database query call and POST input occur in this file; verify that values are validated and parameterized.

This is a static-analysis heuristic, not a confirmed vulnerability. Review the surrounding code, data flow, and access controls before drawing conclusions.

**Source:** `my-test-plugin.php` at line 12

## PoC

No exploit request is generated. Validate behavior only in a local, isolated environment for which you have authorization.

## Impact

Not assessed. Impact depends on reachability, authentication requirements, input validation, and deployment configuration.

## CVSS

Not scored. A CVSS score requires manual validation and a confirmed impact assessment.

## Evidence

```text
10: // Test Case 2 - should be flagged as SQLi
11: global $wpdb;
12: $wpdb->query("SELECT * FROM users WHERE id = " . $_POST['id']);
```
