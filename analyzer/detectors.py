"""High-confidence source text checks used by the opt-in taint engine."""

from __future__ import annotations

import bisect
import math
import re


_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
)
_AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)
    (?P<name>
        \$?[A-Za-z_][A-Za-z0-9_]*
        (?:secret|password|passwd|token|api[_-]?key|access[_-]?key|client[_-]?secret)
        [A-Za-z0-9_]*
    )
    \s*(?:=|=>|:)\s*
    (?P<quote>['"])
    (?P<value>[^'"\r\n]{20,256})
    (?P=quote)
    """
)
_PLACEHOLDER_TERMS = (
    "example",
    "sample",
    "placeholder",
    "changeme",
    "change-me",
    "your-",
    "replace",
    "dummy",
    "fake",
    "test",
    "xxx",
    "123456",
    "password",
)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {character: value.count(character) for character in set(value)}
    return -sum(
        (count / len(value)) * math.log2(count / len(value))
        for count in counts.values()
    )


def _is_placeholder(value: str) -> bool:
    folded = value.casefold()
    return any(term in folded for term in _PLACEHOLDER_TERMS)


def _comment_mask(source: str) -> bytearray:
    mask = bytearray(len(source))
    state = "code"
    cursor = 0
    while cursor < len(source):
        character = source[cursor]
        following = source[cursor + 1] if cursor + 1 < len(source) else ""
        if state == "line_comment":
            if character == "\n":
                state = "code"
            else:
                mask[cursor] = 1
        elif state == "block_comment":
            mask[cursor] = 1
            if character == "*" and following == "/":
                mask[cursor + 1] = 1
                state = "code"
                cursor += 1
        elif state in {"single", "double", "backtick"}:
            if character == "\\":
                cursor += 1
            elif (
                (state == "single" and character == "'")
                or (state == "double" and character == '"')
                or (state == "backtick" and character == "`")
            ):
                state = "code"
        elif character == "/" and following == "/":
            mask[cursor : cursor + 2] = b"\x01\x01"
            state = "line_comment"
            cursor += 1
        elif character == "/" and following == "*":
            mask[cursor : cursor + 2] = b"\x01\x01"
            state = "block_comment"
            cursor += 1
        elif character == "#" and following != "[":
            mask[cursor] = 1
            state = "line_comment"
        elif character == "'":
            state = "single"
        elif character == '"':
            state = "double"
        elif character == "`":
            state = "backtick"
        cursor += 1
    return mask


def detect_hardcoded_secrets(
    source: str, relative_file: str
) -> list[dict[str, object]]:
    """Return only high-confidence literal credentials, excluding placeholders."""
    matches: dict[int, tuple[int, str, str]] = {}
    for match in _PRIVATE_KEY.finditer(source):
        matches[match.start()] = (
            match.start(),
            "private key material",
            match.group(0),
        )
    for match in _AWS_ACCESS_KEY.finditer(source):
        value = match.group(0)
        if not _is_placeholder(value):
            matches[match.start()] = (match.start(), "AWS access key", value)
    for match in _SECRET_ASSIGNMENT.finditer(source):
        value = match.group("value")
        if _is_placeholder(value) or _entropy(value) < 3.5:
            continue
        matches[match.start("value")] = (
            match.start("value"),
            match.group("name"),
            value,
        )

    findings: list[dict[str, object]] = []
    comments = _comment_mask(source)
    line_starts = [0]
    line_starts.extend(
        index + 1 for index, character in enumerate(source) if character == "\n"
    )
    for offset, (location, name, value) in sorted(matches.items()):
        if comments[location]:
            continue
        line = bisect.bisect_right(line_starts, location)
        findings.append(
            {
                "file": relative_file,
                "line": line,
                "type": "Hardcoded Secret",
                "status": "POTENTIAL",
                "confidence": "high",
                "context": "secret",
                "source": {
                    "name": name,
                    "file": relative_file,
                    "line": line,
                },
                "sink": {
                    "name": "hardcoded credential literal",
                    "file": relative_file,
                    "line": line,
                },
                "trace": [
                    {
                        "kind": "literal_secret",
                        "name": name,
                        "file": relative_file,
                        "line": line,
                    }
                ],
                "sanitizer_evidence": [],
                "auth_evidence": [],
                "note": (
                    "High-confidence credential pattern; verify the value and rotate "
                    "it if it is active."
                ),
                "evidence_length": len(value),
            }
        )
    return findings
