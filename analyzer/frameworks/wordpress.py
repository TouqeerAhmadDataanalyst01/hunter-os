"""Bounded WordPress hook, shortcode, and REST route discovery."""

from __future__ import annotations

import re
from dataclasses import dataclass

from analyzer.php_parser import (
    Assignment,
    CallStatement,
    Expression,
    FunctionDef,
    IfStatement,
    OutputStatement,
    Program,
    ReturnStatement,
    SourceLocation,
    Statement,
)


_ARRAY_STRING = re.compile(
    r"""(?ix)
    ['"](?P<key>callback|permission_callback)['"]\s*=>\s*
    ['"](?P<value>[A-Za-z_\\][A-Za-z0-9_\\]*)['"]
    """
)


@dataclass(frozen=True)
class WordPressEntryPoint:
    kind: str
    name: str
    callback: str
    location: SourceLocation
    route: str | None = None
    permission_callback: str | None = None


def _literal_string(value: str) -> str | None:
    value = value.strip()
    if len(value) < 2 or value[0] not in {"'", '"'} or value[-1] != value[0]:
        return None
    if "\\" in value[1:-1]:
        return None
    return value[1:-1]


def _option_callbacks(value: str) -> tuple[str | None, str | None]:
    callback = None
    permission_callback = None
    for match in _ARRAY_STRING.finditer(value):
        key = match.group("key").casefold()
        if key == "callback":
            callback = match.group("value")
        elif key == "permission_callback":
            permission_callback = match.group("value")
    return callback, permission_callback


def _function_statements(program: Program) -> list[tuple[Statement, ...]]:
    scopes: list[tuple[Statement, ...]] = [tuple(program.statements)]
    for function in program.functions:
        scopes.append(tuple(function.body))
    for class_def in program.classes:
        for method in class_def.methods:
            scopes.append(tuple(method.body))
    return scopes


def discover_wordpress_entrypoints(program: Program) -> list[WordPressEntryPoint]:
    """Recognize literal callback registrations represented by parsed calls.

    Closures, dynamic callback expressions, and route options that cannot be
    read as simple literal key/value pairs are deliberately left unrecognized.
    """
    entry_points: list[WordPressEntryPoint] = []
    seen: set[tuple[str, str, str, int]] = set()
    for statements in _function_statements(program):
        for expression in _expressions(statements):
            for call in expression.calls:
                name = call.name.casefold()
                if name in {"add_action", "add_filter"} and len(call.arguments) >= 2:
                    hook = _literal_string(call.arguments[0])
                    callback = _literal_string(call.arguments[1])
                    if (
                        hook is not None
                        and callback is not None
                        and hook.casefold().startswith("wp_ajax_")
                    ):
                        _append_entry(
                            entry_points,
                            seen,
                            WordPressEntryPoint("ajax", hook, callback, call.location),
                        )
                elif name == "add_shortcode" and len(call.arguments) >= 2:
                    shortcode = _literal_string(call.arguments[0])
                    callback = _literal_string(call.arguments[1])
                    if shortcode is not None and callback is not None:
                        _append_entry(
                            entry_points,
                            seen,
                            WordPressEntryPoint(
                                "shortcode", shortcode, callback, call.location
                            ),
                        )
                elif name == "register_rest_route" and len(call.arguments) >= 3:
                    namespace = _literal_string(call.arguments[0])
                    route = _literal_string(call.arguments[1])
                    callback, permission_callback = _option_callbacks(
                        call.arguments[2]
                    )
                    if namespace is not None and route is not None and callback is not None:
                        _append_entry(
                            entry_points,
                            seen,
                            WordPressEntryPoint(
                                "rest",
                                namespace,
                                callback,
                                call.location,
                                route,
                                permission_callback,
                            ),
                        )
    return entry_points


def _append_entry(
    entries: list[WordPressEntryPoint],
    seen: set[tuple[str, str, str, int]],
    entry: WordPressEntryPoint,
) -> None:
    key = (
        entry.kind,
        entry.name.casefold(),
        entry.callback.casefold(),
        entry.location.offset,
    )
    if key not in seen:
        seen.add(key)
        entries.append(entry)


def _expressions(statements: tuple[Statement, ...]) -> list[Expression]:
    expressions: list[Expression] = []
    for statement in statements:
        if isinstance(statement, Assignment):
            expressions.append(statement.value)
        elif isinstance(statement, CallStatement):
            expressions.append(statement.expression)
        elif isinstance(statement, OutputStatement):
            expressions.extend(statement.expressions)
        elif isinstance(statement, ReturnStatement) and statement.value is not None:
            expressions.append(statement.value)
        elif isinstance(statement, IfStatement):
            expressions.append(statement.condition)
            expressions.extend(_expressions(statement.then_body))
            expressions.extend(_expressions(statement.else_body))
    return expressions


def resolve_entrypoint_callbacks(
    entry_points: list[WordPressEntryPoint],
    functions: list[FunctionDef],
) -> list[tuple[WordPressEntryPoint, FunctionDef]]:
    """Return only unique direct callback-to-function matches."""
    by_name: dict[str, list[FunctionDef]] = {}
    for function in functions:
        by_name.setdefault(function.name.casefold(), []).append(function)
        if function.class_name:
            by_name.setdefault(
                f"{function.class_name}::{function.name}".casefold(), []
            ).append(function)
    resolved: list[tuple[WordPressEntryPoint, FunctionDef]] = []
    for entry_point in entry_points:
        candidates = by_name.get(entry_point.callback.casefold(), [])
        if len(candidates) == 1:
            resolved.append((entry_point, candidates[0]))
    return resolved
