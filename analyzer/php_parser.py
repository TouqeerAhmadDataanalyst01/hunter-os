"""A bounded parser for a documented subset of PHP, not a complete PHP AST."""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from pathlib import Path


MAX_PHP_SOURCE_BYTES = 2_000_000
MAX_PHP_LINES = 2_000
MAX_PHP_TOKENS = 200_000
MAX_NESTED_CONDITIONALS = 128
MAX_NESTED_CONTROLS = 128
MAX_NESTED_CALLS = 128

_OPERATORS = (
    "?->",
    "<=>",
    "===",
    "!==",
    "...",
    "??=",
    "->",
    "::",
    "=>",
    "==",
    "!=",
    "<=",
    ">=",
    "&&",
    "||",
    "??",
    "+=",
    "-=",
    "*=",
    "/=",
    "%=",
    ".=",
    "++",
    "--",
    "**",
    "<<",
    ">>",
)
_ASSIGNMENTS = {"=", ".=", "+=", "-=", "*=", "/=", "%=", "??="}
_INCOMPLETE_EXPRESSION_ENDINGS = {
    "=",
    ".=",
    "+=",
    "-=",
    "*=",
    "/=",
    "%=",
    "+",
    "-",
    "*",
    "/",
    "%",
    ".",
    "!",
    "~",
    "&",
    "|",
    "^",
    "&&",
    "||",
    "??",
    "==",
    "===",
    "!=",
    "!==",
    "<",
    ">",
    "<=",
    ">=",
    "=>",
    "->",
    "?->",
    "::",
    "?",
    ":",
    ",",
}
_NON_CALL_NAMES = {
    "if",
    "elseif",
    "while",
    "for",
    "foreach",
    "switch",
    "catch",
    "function",
    "fn",
    "match",
    "clone",
    "echo",
    "print",
    "isset",
    "empty",
    "unset",
    "eval",
}
_UNSUPPORTED_CONTROLS = {
    "goto",
}
_UNSUPPORTED_STATEMENTS = {
    "declare",
    "enum",
    "const",
    "yield",
    "endif",
    "endwhile",
    "endfor",
    "endforeach",
    "function",
    "class",
    "abstract",
    "final",
    "readonly",
}
_UNSUPPORTED_EXPRESSION_KEYWORDS = {
    "match",
    "yield",
    "eval",
    "clone",
}


@dataclass(frozen=True)
class SourceLocation:
    file: str
    line: int
    column: int
    offset: int


@dataclass(frozen=True)
class Diagnostic:
    message: str
    location: SourceLocation
    code: str = "unsupported_syntax"


@dataclass(frozen=True)
class Call:
    name: str
    arguments: tuple[str, ...]
    location: SourceLocation
    argument_locations: tuple[SourceLocation, ...] = ()
    argument_variables: tuple[tuple[str, ...], ...] = ()
    argument_variable_locations: tuple[tuple[SourceLocation, ...], ...] = ()
    argument_calls: tuple[tuple[Call, ...], ...] = ()
    end_offset: int = 0


@dataclass(frozen=True)
class Expression:
    text: str
    variables: tuple[str, ...]
    calls: tuple[Call, ...]
    location: SourceLocation
    variable_locations: tuple[SourceLocation, ...] = ()


@dataclass(frozen=True)
class Assignment:
    target: str
    value: Expression
    location: SourceLocation
    operator: str = "="


@dataclass(frozen=True)
class CallStatement:
    expression: Expression
    location: SourceLocation


@dataclass(frozen=True)
class OutputStatement:
    kind: str
    expressions: tuple[Expression, ...]
    location: SourceLocation


@dataclass(frozen=True)
class ReturnStatement:
    value: Expression | None
    location: SourceLocation


@dataclass(frozen=True)
class GlobalStatement:
    variables: tuple[str, ...]
    location: SourceLocation


@dataclass(frozen=True)
class IfStatement:
    condition: Expression
    then_body: tuple[Statement, ...]
    else_body: tuple[Statement, ...]
    location: SourceLocation


@dataclass(frozen=True)
class ControlStatement:
    kind: str
    expression: Expression | None
    body: tuple[Statement, ...]
    branches: tuple[tuple[Expression | None, tuple[Statement, ...]], ...]
    location: SourceLocation
    iteration_variables: tuple[str, ...] = ()


Statement = (
    Assignment
    | CallStatement
    | OutputStatement
    | ReturnStatement
    | GlobalStatement
    | IfStatement
    | ControlStatement
)


@dataclass(frozen=True)
class FunctionDef:
    name: str
    parameters: tuple[str, ...]
    body: tuple[Statement, ...]
    location: SourceLocation
    kind: str = "function"
    class_name: str | None = None
    modifiers: tuple[str, ...] = ()


@dataclass(frozen=True)
class ClassDef:
    name: str
    methods: tuple[FunctionDef, ...]
    properties: tuple[Assignment, ...]
    location: SourceLocation
    kind: str = "class"


@dataclass
class Program:
    file: str
    functions: list[FunctionDef] = field(default_factory=list)
    classes: list[ClassDef] = field(default_factory=list)
    statements: list[Statement] = field(default_factory=list)
    namespace: str | None = None
    imports: list[str] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    complete: bool = True


@dataclass(frozen=True)
class _Token:
    kind: str
    value: str
    start: int
    end: int


class _Lexer:
    def __init__(self, source: str, file: str, diagnostics: list[Diagnostic]):
        self.source = source
        self.file = file
        self.diagnostics = diagnostics
        self.line_starts = [0]
        self.line_starts.extend(
            index + 1 for index, character in enumerate(source) if character == "\n"
        )

    def location(self, offset: int) -> SourceLocation:
        line_index = bisect.bisect_right(self.line_starts, offset) - 1
        return SourceLocation(
            self.file,
            line_index + 1,
            offset - self.line_starts[line_index] + 1,
            offset,
        )

    def _diagnose(self, message: str, offset: int, code: str) -> None:
        self.diagnostics.append(Diagnostic(message, self.location(offset), code))

    def tokenize(self) -> list[_Token]:
        source = self.source
        if len(source.encode("utf-8", errors="replace")) > MAX_PHP_SOURCE_BYTES:
            self._diagnose(
                f"PHP source exceeds {MAX_PHP_SOURCE_BYTES} bytes",
                0,
                "source_limit",
            )
            return []
        if source.count("\n") + 1 > MAX_PHP_LINES:
            self._diagnose(
                f"PHP source exceeds {MAX_PHP_LINES} lines",
                0,
                "line_limit",
            )
            return []

        first_opening = source.find("<?")
        leading_text = source[:first_opening] if first_opening >= 0 else ""
        has_php_tag = source.lstrip().startswith("<?") or leading_text.lstrip().startswith("<")
        in_php = not has_php_tag
        cursor = 0
        tokens: list[_Token] = []
        while cursor < len(source):
            if not in_php:
                opening = source.find("<?", cursor)
                if opening < 0:
                    if source[cursor:].strip():
                        self._diagnose(
                            "Inline HTML is outside the parsed PHP subset",
                            cursor,
                            "inline_html",
                        )
                    break
                if source[cursor:opening].strip():
                    self._diagnose(
                        "Inline HTML is outside the parsed PHP subset",
                        cursor,
                        "inline_html",
                    )
                if source[opening : opening + 5].lower() == "<?php":
                    cursor = opening + 5
                elif source.startswith("<?=", opening):
                    self._diagnose(
                        "Short echo tags are not supported",
                        opening,
                        "unsupported_tag",
                    )
                    cursor = opening + 3
                else:
                    self._diagnose(
                        "Short PHP tags are not supported",
                        opening,
                        "unsupported_tag",
                    )
                    cursor = opening + 2
                in_php = True
                continue

            if source.startswith("?>", cursor):
                cursor += 2
                in_php = False
                continue

            character = source[cursor]
            if character.isspace():
                cursor += 1
                continue

            if character == "#" and source.startswith("#[", cursor):
                self._diagnose(
                    "PHP attributes are not supported",
                    cursor,
                    "unsupported_syntax",
                )
                tokens.append(_Token("unsupported", "#[", cursor, cursor + 2))
                cursor += 2
                continue
            if source.startswith("//", cursor) or character == "#":
                end = source.find("\n", cursor)
                cursor = len(source) if end < 0 else end + 1
                continue
            if source.startswith("/*", cursor):
                end = source.find("*/", cursor + 2)
                if end < 0:
                    self._diagnose(
                        "Unterminated block comment",
                        cursor,
                        "malformed_source",
                    )
                    break
                cursor = end + 2
                continue

            if source.startswith("<<<", cursor):
                cursor = self._consume_heredoc(cursor, tokens)
                continue
            if character == "`":
                end, closed = self._consume_quoted(cursor, "`")
                if not closed:
                    self._diagnose("Unterminated backtick expression", cursor, "malformed_source")
                self._diagnose(
                    "Backtick shell expressions are not supported",
                    cursor,
                    "unsupported_syntax",
                )
                tokens.append(_Token("unsupported", source[cursor:end], cursor, end))
                cursor = end
                continue
            if character in ("'", '"'):
                end, closed = self._consume_quoted(cursor, character)
                value = source[cursor:end]
                if not closed:
                    self._diagnose("Unterminated string literal", cursor, "malformed_source")
                tokens.append(_Token("string", value, cursor, end))
                cursor = end
                continue

            if character == "$" and cursor + 1 < len(source) and (
                source[cursor + 1].isalpha() or source[cursor + 1] == "_"
            ):
                match = re.match(r"\$[A-Za-z_][A-Za-z0-9_]*", source[cursor:])
                assert match is not None
                end = cursor + match.end()
                tokens.append(_Token("variable", source[cursor:end], cursor, end))
                cursor = end
                continue
            if character.isalpha() or character == "_":
                match = re.match(r"[A-Za-z_][A-Za-z0-9_]*", source[cursor:])
                assert match is not None
                end = cursor + match.end()
                tokens.append(_Token("identifier", source[cursor:end], cursor, end))
                cursor = end
                continue
            if character.isdigit():
                match = re.match(r"(?:0[xX][0-9A-Fa-f]+|[0-9]+(?:\.[0-9]+)?)", source[cursor:])
                assert match is not None
                end = cursor + match.end()
                tokens.append(_Token("number", source[cursor:end], cursor, end))
                cursor = end
                continue

            operator = next(
                (value for value in _OPERATORS if source.startswith(value, cursor)),
                None,
            )
            if operator is not None:
                end = cursor + len(operator)
                tokens.append(_Token("symbol", operator, cursor, end))
                cursor = end
            elif character in "(){}[];,.:?+-*/%!=<>|&^~@\\":
                tokens.append(_Token("symbol", character, cursor, cursor + 1))
                cursor += 1
            else:
                self._diagnose(
                    f"Unrecognized character {character!r}",
                    cursor,
                    "malformed_source",
                )
                tokens.append(_Token("unsupported", character, cursor, cursor + 1))
                cursor += 1

            if len(tokens) >= MAX_PHP_TOKENS:
                self._diagnose(
                    f"PHP source exceeds {MAX_PHP_TOKENS} tokens",
                    cursor,
                    "token_limit",
                )
                return tokens
        return tokens

    @staticmethod
    def _has_complex_interpolation(value: str) -> bool:
        inner = value[1:-1]
        if re.search(r"(?<!\\)\$\{|\{[^}]*\$[A-Za-z_]", inner):
            return True
        return re.search(
            r"(?<!\\)\$[A-Za-z_][A-Za-z0-9_]*(?:\[|->|\?->)",
            inner,
        ) is not None

    def _consume_quoted(self, start: int, quote: str) -> tuple[int, bool]:
        cursor = start + 1
        while cursor < len(self.source):
            if self.source[cursor] == "\\":
                cursor += 2
            elif self.source[cursor] == quote:
                return cursor + 1, True
            else:
                cursor += 1
        return len(self.source), False

    def _consume_heredoc(self, start: int, tokens: list[_Token]) -> int:
        line_end = self.source.find("\n", start)
        if line_end < 0:
            end = len(self.source)
        else:
            header = self.source[start + 3 : line_end].strip()
            label_match = re.match(r"(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1", header)
            if label_match is None:
                self._diagnose("Malformed heredoc/nowdoc header", start, "malformed_source")
                end = len(self.source)
            else:
                label = label_match.group(2)
                closing = re.search(
                    rf"(?m)^[ \t]*{re.escape(label)};?(?=[ \t]|$)",
                    self.source[line_end + 1 :],
                )
                if closing is None:
                    end = len(self.source)
                else:
                    label_start = closing.group(0).find(label)
                    end = (
                        line_end
                        + 1
                        + closing.start()
                        + label_start
                        + len(label)
                    )
                if closing is None:
                    self._diagnose(
                        "Unterminated heredoc/nowdoc",
                        start,
                        "malformed_source",
                    )
        tokens.append(_Token("string", self.source[start:end], start, end))
        return end


class _Parser:
    def __init__(
        self,
        tokens: list[_Token],
        file: str,
        source: str,
        diagnostics: list[Diagnostic],
    ):
        self.tokens = tokens
        self.file = file
        self.source = source
        self.diagnostics = diagnostics
        self.line_starts = [0]
        self.line_starts.extend(
            index + 1 for index, character in enumerate(source) if character == "\n"
        )
        self.index = 0
        self.nested_conditionals = 0
        self.nested_controls = 0

    def location(self, offset: int) -> SourceLocation:
        line_index = bisect.bisect_right(self.line_starts, offset) - 1
        return SourceLocation(
            self.file,
            line_index + 1,
            offset - self.line_starts[line_index] + 1,
            offset,
        )

    def _peek(self, distance: int = 0) -> _Token | None:
        index = self.index + distance
        return self.tokens[index] if index < len(self.tokens) else None

    def _take(self) -> _Token | None:
        token = self._peek()
        if token is not None:
            self.index += 1
        return token

    def _accept(self, value: str) -> _Token | None:
        if self._peek() is not None and self._peek().value == value:
            return self._take()
        return None

    def _diagnose(
        self, message: str, token: _Token | None = None, code: str = "unsupported_syntax"
    ) -> None:
        offset = token.start if token is not None else len(self.source)
        self.diagnostics.append(Diagnostic(message, self.location(offset), code))

    def parse(self) -> Program:
        program = Program(self.file)
        while self._peek() is not None:
            before = self.index
            token = self._peek()
            if token is not None and token.value == ";":
                self._take()
            elif token is not None and token.value.lower() == "function":
                function = self._parse_function(None)
                if function is not None:
                    program.functions.append(function)
            elif token is not None and token.value.lower() in {
                "class", "interface", "trait"
            }:
                class_def = self._parse_classlike()
                if class_def is not None:
                    program.classes.append(class_def)
            elif token is not None and token.value.lower() == "namespace":
                self._parse_namespace(program)
            elif token is not None and token.value.lower() == "use":
                self._parse_import(program)
            else:
                statement = self._parse_statement()
                if statement is not None:
                    program.statements.append(statement)
            if self.index == before:
                self._diagnose("Parser made no progress", token, "parser_error")
                self._take()
        program.diagnostics = self.diagnostics
        program.complete = not self.diagnostics
        return program

    def _parse_namespace(self, program: Program) -> None:
        start = self._take()
        assert start is not None
        name: list[_Token] = []
        while self._peek() is not None and self._peek().value not in (";", "{"):
            token = self._take()
            if token is not None:
                name.append(token)
        if self._accept(";") is not None:
            program.namespace = self._text(name).strip()
            return
        if self._accept("{") is None:
            self._diagnose("Malformed namespace declaration", start, "parser_error")
            return
        program.namespace = self._text(name).strip()
        while self._peek() is not None and self._peek().value != "}":
            before = self.index
            token = self._peek()
            if token is not None and token.value.lower() == "function":
                function = self._parse_function(None)
                if function is not None:
                    program.functions.append(function)
            elif token is not None and token.value.lower() in {"class", "interface", "trait"}:
                class_def = self._parse_classlike()
                if class_def is not None:
                    program.classes.append(class_def)
            elif token is not None and token.value.lower() == "use":
                self._parse_import(program)
            else:
                statement = self._parse_statement()
                if statement is not None:
                    program.statements.append(statement)
            if self.index == before:
                self._diagnose("Parser made no progress in namespace", token, "parser_error")
                self._take()
        if self._accept("}") is None:
            self._diagnose("Unterminated namespace block", start, "parser_error")

    def _parse_import(self, program: Program) -> None:
        start = self._take()
        assert start is not None
        tokens = self._read_until_semicolon()
        if not tokens:
            self._diagnose("Empty use declaration", start, "parser_error")
            return
        program.imports.append(self._text(tokens).strip())

    def _parse_classlike(self) -> ClassDef | None:
        start = self._take()
        assert start is not None
        class_kind = start.value.lower()
        name = self._take()
        if start is None or name is None or name.kind != "identifier":
            self._diagnose("Expected a named class declaration", start, "parser_error")
            self._skip_until("{", ";")
            if self._accept("{"):
                self._skip_balanced_block()
            else:
                self._accept(";")
            return None
        while self._peek() is not None and self._peek().value != "{":
            if self._peek().value == ";":
                self._diagnose(
                    "Class declaration has no body", start, "parser_error"
                )
                self._take()
                return None
            self._take()
        if self._accept("{") is None:
            self._diagnose("Expected class body", name, "parser_error")
            return None

        methods: list[FunctionDef] = []
        properties: list[Assignment] = []
        while self._peek() is not None and self._peek().value != "}":
            before = self.index
            modifiers: list[_Token] = []
            while (
                self._peek() is not None
                and self._peek().value.lower()
                in {"public", "protected", "private", "static", "final", "abstract", "readonly"}
            ):
                modifier = self._take()
                if modifier is not None:
                    modifiers.append(modifier)
            token = self._peek()
            if token is not None and token.value.lower() == "function":
                method = self._parse_function(
                    name.value,
                    kind="method",
                    modifiers=tuple(item.value.lower() for item in modifiers),
                )
                if method is not None:
                    methods.append(method)
            elif token is not None and token.value.lower() == "use":
                self._take()
                self._read_until_semicolon()
            elif token is not None and token.value.lower() == "const":
                self._take()
                self._read_until_semicolon()
            elif token is not None:
                member_tokens = self._read_until_semicolon()
                member_variables = [
                    item for item in member_tokens if item.kind == "variable"
                ]
                if not member_variables:
                    self._diagnose(
                        "Unsupported class member declaration: "
                        f"{self._text(member_tokens)}",
                        member_tokens[0] if member_tokens else token,
                    )
                assignment_index = self._top_level_assignment(member_tokens)
                if assignment_index is not None:
                    target_tokens = member_tokens[:assignment_index]
                    value_tokens = member_tokens[assignment_index + 1 :]
                    target = next(
                        (item for item in target_tokens if item.kind == "variable"),
                        None,
                    )
                    if target is not None and value_tokens:
                        properties.append(
                            Assignment(
                                target.value,
                                self._parse_expression(value_tokens, value_tokens[0].start),
                                self.location(target.start),
                            )
                        )
            else:
                self._diagnose("Unsupported class member declaration", token)
                self._take()
            if self.index == before:
                self._take()

        if self._accept("}") is None:
            self._diagnose("Unterminated class body", start, "parser_error")
        return ClassDef(
            name.value,
            tuple(methods),
            tuple(properties),
            self.location(start.start),
            class_kind,
        )

    def _parse_function(
        self,
        class_name: str | None,
        kind: str = "function",
        modifiers: tuple[str, ...] = (),
    ) -> FunctionDef | None:
        start = self._take()
        if start is None:
            return None
        if self._accept("&") is not None:
            self._diagnose("Reference-returning functions are not modeled", start)
        name = self._take()
        if name is None or name.kind != "identifier":
            self._diagnose(
                "Anonymous functions and closures are not supported",
                start,
            )
            self._skip_statement()
            return None
        if self._accept("(") is None:
            self._diagnose("Expected parameter list", name, "parser_error")
            self._skip_statement()
            return None
        parameter_tokens = self._read_balanced_contents("(", ")", name)
        parameter_names: list[str] = []
        for segment in self._split_top_level(parameter_tokens, ","):
            if not segment:
                continue
            variables = [token for token in segment if token.kind == "variable"]
            if variables:
                parameter_names.append(variables[0].value)
        parameters = tuple(parameter_names)
        while self._peek() is not None and self._peek().value not in ("{", ";"):
            self._take()
        if self._accept(";") is not None:
            return FunctionDef(
                name.value,
                parameters,
                (),
                self.location(start.start),
                kind,
                class_name,
                modifiers,
            )
        if self._accept("{") is None:
            self._diagnose("Expected function body", name, "parser_error")
            return None
        body = self._parse_block_contents(start)
        return FunctionDef(
            name.value,
            parameters,
            tuple(body),
            self.location(start.start),
            kind,
            class_name,
            modifiers,
        )

    def _parse_block_contents(self, start: _Token) -> list[Statement]:
        statements: list[Statement] = []
        while self._peek() is not None and self._peek().value != "}":
            before = self.index
            statement = self._parse_statement()
            if statement is not None:
                statements.append(statement)
            if self.index == before:
                self._diagnose("Parser made no progress in block", self._peek(), "parser_error")
                self._take()
        if self._accept("}") is None:
            self._diagnose("Unterminated block", start, "parser_error")
        return statements

    def _parse_statement(self) -> Statement | None:
        token = self._peek()
        if token is None:
            return None
        keyword = token.value.lower() if token.kind == "identifier" else ""
        if keyword == "if":
            return self._parse_if()
        if keyword in {"switch", "foreach", "for", "while", "do", "try"}:
            return self._parse_control_statement()
        if keyword == "return":
            return self._parse_return()
        if keyword in {"break", "continue", "throw"}:
            start = self._take()
            assert start is not None
            tokens = self._read_until_semicolon()
            expression = (
                self._parse_expression(tokens, tokens[0].start)
                if tokens
                else None
            )
            return ControlStatement(
                keyword,
                expression,
                (),
                (),
                self.location(start.start),
            )
        if keyword == "global":
            return self._parse_global()
        if keyword in {"echo", "print"}:
            return self._parse_output()
        if keyword in _UNSUPPORTED_CONTROLS:
            self._diagnose(
                f"{token.value} control-flow syntax is outside the parsed subset",
                token,
            )
            self._skip_statement()
            return None
        if keyword in _UNSUPPORTED_STATEMENTS:
            self._diagnose(
                f"{token.value} statement syntax is outside the parsed subset",
                token,
            )
            self._skip_statement()
            return None
        if token.value in ("}",):
            return None
        if token.kind == "unsupported":
            self._diagnose("Unsupported expression token", token)
            self._skip_statement()
            return None
        return self._parse_expression_statement()

    def _parse_control_statement(self) -> ControlStatement | None:
        start = self._peek()
        self.nested_controls += 1
        if self.nested_controls > MAX_NESTED_CONTROLS:
            self._diagnose(
                f"Control-flow nesting exceeds {MAX_NESTED_CONTROLS}",
                start,
                "nesting_limit",
            )
            self._skip_statement()
            self.nested_controls -= 1
            return None
        try:
            return self._parse_control_statement_inner()
        finally:
            self.nested_controls -= 1

    def _parse_control_statement_inner(self) -> ControlStatement | None:
        start = self._take()
        if start is None:
            return None
        kind = start.value.lower()
        if kind == "switch":
            expression = self._read_control_expression(start)
            if self._accept("{") is None:
                self._diagnose("Expected switch body", start, "parser_error")
                return None
            branches: list[tuple[Expression | None, tuple[Statement, ...]]] = []
            while self._peek() is not None and self._peek().value != "}":
                label = self._take()
                if label is None or label.value.lower() not in {"case", "default"}:
                    self._diagnose("Expected case/default label in switch", label, "parser_error")
                    self._skip_statement()
                    continue
                label_tokens = self._read_until_values({":"})
                self._accept(":")
                branch_expression = (
                    self._parse_expression(label_tokens, label_tokens[0].start)
                    if label_tokens and label.value.lower() == "case"
                    else None
                )
                body: list[Statement] = []
                while (
                    self._peek() is not None
                    and self._peek().value != "}"
                    and self._peek().value.lower() not in {"case", "default"}
                ):
                    before = self.index
                    statement = self._parse_statement()
                    if statement is not None:
                        body.append(statement)
                    if self.index == before:
                        self._diagnose("Parser made no progress in switch", self._peek(), "parser_error")
                        self._take()
                branches.append((branch_expression, tuple(body)))
            if self._accept("}") is None:
                self._diagnose("Unterminated switch body", start, "parser_error")
            return ControlStatement(
                kind, expression, (), tuple(branches), self.location(start.start)
            )

        if kind == "do":
            body = tuple(self._parse_body(start))
            if self._peek() is None or self._peek().value.lower() != "while":
                self._diagnose("Expected while after do body", start, "parser_error")
                return ControlStatement(kind, None, body, (), self.location(start.start))
            while_token = self._take()
            assert while_token is not None
            expression = self._read_control_expression(while_token)
            self._accept(";")
            return ControlStatement(
                "do_while", expression, body, (), self.location(start.start)
            )

        if kind == "try":
            body = tuple(self._parse_body(start))
            branches: list[tuple[Expression | None, tuple[Statement, ...]]] = []
            while self._peek() is not None and self._peek().value.lower() == "catch":
                catch_token = self._take()
                assert catch_token is not None
                catch_expression = self._read_control_expression(catch_token)
                catch_body = tuple(self._parse_body(catch_token))
                branches.append((catch_expression, catch_body))
            finally_body: tuple[Statement, ...] = ()
            if self._peek() is not None and self._peek().value.lower() == "finally":
                finally_token = self._take()
                assert finally_token is not None
                finally_body = tuple(self._parse_body(finally_token))
            if not branches and not finally_body:
                self._diagnose("try requires catch or finally", start, "parser_error")
            return ControlStatement(
                kind,
                None,
                body,
                tuple(branches) + ((None, finally_body),) if finally_body else tuple(branches),
                self.location(start.start),
            )

        expression = self._read_control_expression(start)
        iteration_variables: tuple[str, ...] = ()
        if kind == "foreach":
            match = re.search(r"\bas\b(.*)$", expression.text, re.IGNORECASE)
            if match is not None:
                iteration_variables = tuple(
                    re.findall(r"\$[A-Za-z_][A-Za-z0-9_]*", match.group(1))
                )
        body = tuple(self._parse_body(start))
        return ControlStatement(
            kind,
            expression,
            body,
            (),
            self.location(start.start),
            iteration_variables,
        )

    def _read_control_expression(self, start: _Token) -> Expression | None:
        if self._accept("(") is None:
            self._diagnose(f"Expected parenthesized expression after {start.value}", start, "parser_error")
            return None
        tokens = self._read_balanced_contents("(", ")", start)
        if not tokens:
            self._diagnose(f"{start.value} expression cannot be empty", start, "parser_error")
            return None
        return self._parse_expression(tokens, tokens[0].start)

    def _read_until_values(self, values: set[str]) -> list[_Token]:
        result: list[_Token] = []
        depths = {"(": 0, "[": 0, "{": 0}
        closing = {")": "(", "]": "[", "}": "{"}
        while self._peek() is not None:
            token = self._peek()
            assert token is not None
            if token.value in values and not any(depths.values()):
                return result
            if token.value in depths:
                depths[token.value] += 1
            elif token.value in closing:
                opener = closing[token.value]
                if depths[opener] == 0:
                    return result
                depths[opener] -= 1
            consumed = self._take()
            if consumed is not None:
                result.append(consumed)
        self._diagnose("Expected switch case delimiter", result[0] if result else None, "parser_error")
        return result

    def _parse_global(self) -> GlobalStatement:
        start = self._take()
        assert start is not None
        tokens = self._read_until_semicolon()
        segments = self._split_top_level(tokens, ",")
        if not tokens or any(
            len(segment) != 1 or segment[0].kind != "variable"
            for segment in segments
        ):
            self._diagnose("Global statement requires variables", start, "parser_error")
        variables = tuple(
            segment[0].value
            for segment in segments
            if len(segment) == 1 and segment[0].kind == "variable"
        )
        return GlobalStatement(variables, self.location(start.start))

    def _parse_if(self) -> IfStatement | None:
        start = self._take()
        self.nested_conditionals += 1
        if self.nested_conditionals > MAX_NESTED_CONDITIONALS:
            self._diagnose(
                f"Conditional nesting exceeds {MAX_NESTED_CONDITIONALS}",
                start,
                "nesting_limit",
            )
            self._skip_statement()
            self.nested_conditionals -= 1
            return None
        if start is None or self._accept("(") is None:
            self._diagnose("Expected condition after if", start, "parser_error")
            self._skip_statement()
            self.nested_conditionals -= 1
            return None
        condition_tokens = self._read_balanced_contents("(", ")", start)
        if not condition_tokens:
            self._diagnose("Conditional expression cannot be empty", start, "parser_error")
        condition = self._parse_expression(
            condition_tokens,
            condition_tokens[0].start if condition_tokens else start.start,
        )
        then_body = self._parse_body(start)
        else_body: list[Statement] = []
        if self._peek() is not None and self._peek().value.lower() == "elseif":
            nested = self._parse_if()
            if nested is not None:
                else_body.append(nested)
        elif self._peek() is not None and self._peek().value.lower() == "else":
            self._take()
            else_body = self._parse_body(start)
        statement = IfStatement(
            condition, tuple(then_body), tuple(else_body), self.location(start.start)
        )
        self.nested_conditionals -= 1
        return statement

    def _parse_body(self, start: _Token) -> list[Statement]:
        if self._accept("{") is not None:
            return self._parse_block_contents(start)
        statement = self._parse_statement()
        return [] if statement is None else [statement]

    def _parse_return(self) -> ReturnStatement:
        start = self._take()
        assert start is not None
        expression_tokens = self._read_until_semicolon()
        value = (
            self._parse_expression(expression_tokens, expression_tokens[0].start)
            if expression_tokens
            else None
        )
        return ReturnStatement(value, self.location(start.start))

    def _parse_output(self) -> OutputStatement:
        start = self._take()
        assert start is not None
        expression_tokens = self._read_until_semicolon()
        segments = (
            self._split_top_level(expression_tokens, ",")
            if start.value.lower() == "echo"
            else [expression_tokens]
        )
        expressions = tuple(
            self._parse_expression(segment, segment[0].start)
            for segment in segments
            if segment
        )
        if not expressions:
            self._diagnose(f"{start.value} requires an expression", start, "parser_error")
        return OutputStatement(start.value.lower(), expressions, self.location(start.start))

    def _parse_expression_statement(self) -> Statement | None:
        start = self._peek()
        expression_tokens = self._read_until_semicolon()
        if not expression_tokens:
            self._diagnose("Empty or malformed statement", start, "parser_error")
            return None
        assignment_index = self._top_level_assignment(expression_tokens)
        if assignment_index is not None:
            target_tokens = expression_tokens[:assignment_index]
            value_tokens = expression_tokens[assignment_index + 1 :]
            if not target_tokens or target_tokens[0].kind != "variable":
                self._diagnose("Assignment has no variable target", start, "parser_error")
                return None
            if not value_tokens:
                self._diagnose("Assignment has no value", start, "parser_error")
                return None
            target = self._text(target_tokens).strip()
            value = self._parse_expression(
                value_tokens,
                value_tokens[0].start if value_tokens else target_tokens[0].end,
            )
            return Assignment(
                target,
                value,
                self.location(target_tokens[0].start),
                expression_tokens[assignment_index].value,
            )
        expression = self._parse_expression(expression_tokens, expression_tokens[0].start)
        return CallStatement(expression, self.location(expression_tokens[0].start))

    def _read_until_semicolon(self) -> list[_Token]:
        result: list[_Token] = []
        depths = {"(": 0, "[": 0, "{": 0}
        closing = {")": "(", "]": "[", "}": "{"}
        while self._peek() is not None:
            token = self._peek()
            assert token is not None
            if token.value == ";" and not any(depths.values()):
                self._take()
                return result
            if token.value in depths:
                depths[token.value] += 1
            elif token.value in closing:
                opener = closing[token.value]
                if depths[opener] == 0:
                    if token.value == "}":
                        break
                    self._diagnose("Unbalanced expression delimiters", token, "parser_error")
                    self._take()
                    continue
                depths[opener] -= 1
            consumed = self._take()
            if consumed is not None:
                result.append(consumed)
        self._diagnose(
            "Statement is missing a terminating semicolon",
            result[0] if result else self._peek(),
            "parser_error",
        )
        return result

    def _read_balanced_contents(
        self, opener: str, closer: str, start: _Token
    ) -> list[_Token]:
        result: list[_Token] = []
        depth = 1
        while self._peek() is not None:
            token = self._take()
            assert token is not None
            if token.value == opener:
                depth += 1
            elif token.value == closer:
                depth -= 1
                if depth == 0:
                    return result
            result.append(token)
        self._diagnose(f"Unterminated {opener}{closer} group", start, "parser_error")
        return result

    def _parse_expression(self, tokens: list[_Token], offset: int) -> Expression:
        if tokens and tokens[-1].value in _INCOMPLETE_EXPRESSION_ENDINGS:
            self._diagnose(
                "Expression ends with an incomplete operator",
                tokens[-1],
                "parser_error",
            )
        for token in tokens:
            if token.kind == "unsupported":
                self._diagnose("Unsupported expression token", token)
            if (
                token.kind == "identifier"
                and token.value.lower() in _UNSUPPORTED_EXPRESSION_KEYWORDS
            ):
                self._diagnose(
                    f"{token.value} expression syntax is outside the parsed subset",
                    token,
                )
        return Expression(
            self._text(tokens),
            tuple(value for value, _ in self._variables_in_tokens(tokens)),
            tuple(self._find_calls(tokens)),
            self.location(offset),
            tuple(location for _, location in self._variables_in_tokens(tokens)),
        )

    def _variables_in_tokens(
        self, tokens: list[_Token]
    ) -> list[tuple[str, SourceLocation]]:
        variables: list[tuple[str, SourceLocation]] = []
        for index, token in enumerate(tokens):
            if token.kind == "variable":
                if (
                    token.value.casefold() == "$_server"
                    and index + 3 < len(tokens)
                    and tokens[index + 1].value == "["
                    and tokens[index + 3].value == "]"
                ):
                    key = tokens[index + 2]
                    if (
                        key.kind == "string"
                        and key.value[1:-1].casefold() == "php_self"
                    ):
                        variables.append(
                            (
                                "$_SERVER['PHP_SELF']",
                                self.location(token.start),
                            )
                        )
                        continue
                variables.append((token.value, self.location(token.start)))
            elif token.kind == "string" and token.value.startswith('"'):
                for match in re.finditer(
                    r"(?<!\\)\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})",
                    token.value,
                ):
                    variable = match.group(0)
                    if variable.startswith("${"):
                        variable = "$" + variable[2:-1]
                    variables.append(
                        (variable, self.location(token.start + match.start()))
                    )
            elif token.kind == "string" and token.value.startswith("<<<"):
                if re.match(r"""<<<\s*['"]""", token.value):
                    continue
                for match in re.finditer(
                    r"(?<!\\)\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})",
                    token.value,
                ):
                    variable = match.group(0)
                    if variable.startswith("${"):
                        variable = "$" + variable[2:-1]
                    variables.append(
                        (variable, self.location(token.start + match.start()))
                    )
        return variables

    def _find_calls(self, tokens: list[_Token], depth: int = 0) -> list[Call]:
        if depth > MAX_NESTED_CALLS:
            self._diagnose(
                f"Call expression nesting exceeds {MAX_NESTED_CALLS}",
                tokens[0] if tokens else None,
                "nesting_limit",
            )
            return []
        calls: list[Call] = []
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if token.kind != "identifier" or index + 1 >= len(tokens):
                index += 1
                continue
            if tokens[index + 1].value != "(" or token.value.lower() in _NON_CALL_NAMES:
                index += 1
                continue
            start_index = index
            while (
                start_index >= 2
                and tokens[start_index - 1].value in ("->", "?->", "::")
                and tokens[start_index - 2].kind in ("identifier", "variable")
            ):
                start_index -= 2
            while start_index > 0 and tokens[start_index - 1].value == "\\":
                start_index -= 1
                if (
                    start_index > 0
                    and tokens[start_index - 1].kind == "identifier"
                ):
                    start_index -= 1
            opening = index + 1
            parenthesis_depth = 0
            closing = opening
            for cursor in range(opening, len(tokens)):
                if tokens[cursor].value == "(":
                    parenthesis_depth += 1
                elif tokens[cursor].value == ")":
                    parenthesis_depth -= 1
                    if parenthesis_depth == 0:
                        closing = cursor
                        break
            argument_tokens = tokens[opening + 1 : closing]
            argument_segments = [
                segment
                for segment in self._split_top_level(argument_tokens, ",")
                if segment
            ]
            arguments = tuple(self._text(segment) for segment in argument_segments)
            argument_locations = tuple(
                self.location(segment[0].start) for segment in argument_segments
            )
            argument_calls = tuple(
                tuple(self._find_calls(segment, depth + 1))
                for segment in argument_segments
            )
            argument_variables_list: list[tuple[str, ...]] = []
            argument_variable_locations_list: list[tuple[SourceLocation, ...]] = []
            for argument_index, segment in enumerate(argument_segments):
                direct_variables = [
                    (value, location)
                    for value, location in self._variables_in_tokens(segment)
                    if not any(
                        child.location.offset <= location.offset < child.end_offset
                        for child in argument_calls[argument_index]
                    )
                ]
                argument_variables_list.append(
                    tuple(value for value, _ in direct_variables)
                )
                argument_variable_locations_list.append(
                    tuple(location for _, location in direct_variables)
                )
            argument_variables = tuple(argument_variables_list)
            argument_variable_locations = tuple(argument_variable_locations_list)
            calls.append(
                Call(
                    self._text(tokens[start_index : index + 1]),
                    arguments,
                    self.location(tokens[start_index].start),
                    argument_locations,
                    argument_variables,
                    argument_variable_locations,
                    argument_calls,
                    tokens[closing].end,
                )
            )
            index = closing + 1
        return calls

    def _top_level_assignment(self, tokens: list[_Token]) -> int | None:
        depths = {"(": 0, "[": 0, "{": 0}
        closing = {")": "(", "]": "[", "}": "{"}
        for index, token in enumerate(tokens):
            if token.value in depths:
                depths[token.value] += 1
            elif token.value in closing:
                depths[closing[token.value]] = max(0, depths[closing[token.value]] - 1)
            elif token.value in _ASSIGNMENTS and not any(depths.values()):
                return index
        return None

    def _split_top_level(self, tokens: list[_Token], separator: str) -> list[list[_Token]]:
        segments: list[list[_Token]] = [[]]
        depths = {"(": 0, "[": 0, "{": 0}
        closing = {")": "(", "]": "[", "}": "{"}
        for token in tokens:
            if token.value == separator and not any(depths.values()):
                segments.append([])
                continue
            if token.value in depths:
                depths[token.value] += 1
            elif token.value in closing:
                depths[closing[token.value]] = max(0, depths[closing[token.value]] - 1)
            segments[-1].append(token)
        return segments

    def _text(self, tokens: list[_Token]) -> str:
        if not tokens:
            return ""
        return self.source[tokens[0].start : tokens[-1].end].strip()

    def _skip_until(self, *values: str) -> None:
        while self._peek() is not None and self._peek().value not in values:
            self._take()

    def _skip_balanced_block(self) -> None:
        depth = 1
        while self._peek() is not None and depth:
            token = self._take()
            if token is not None and token.value == "{":
                depth += 1
            elif token is not None and token.value == "}":
                depth -= 1

    def _skip_statement(self) -> None:
        parentheses = 0
        brackets = 0
        braces = 0
        saw_body = False
        while self._peek() is not None:
            token = self._take()
            assert token is not None
            if token.value == "(":
                parentheses += 1
            elif token.value == ")":
                parentheses = max(0, parentheses - 1)
            elif token.value == "[":
                brackets += 1
            elif token.value == "]":
                brackets = max(0, brackets - 1)
            elif token.value == "{":
                braces += 1
                saw_body = True
            elif token.value == "}":
                if braces == 0:
                    self.index -= 1
                    return
                braces -= 1
                if saw_body and braces == 0 and parentheses == 0 and brackets == 0:
                    return
            elif token.value == ";" and parentheses == 0 and brackets == 0 and braces == 0:
                return


def parse_php(source: str, file: str = "<memory>") -> Program:
    """Parse supported PHP syntax and mark every incomplete/unsupported parse."""
    diagnostics: list[Diagnostic] = []
    lexer = _Lexer(source, file, diagnostics)
    tokens = lexer.tokenize()
    parser = _Parser(tokens, file, source, diagnostics)
    return parser.parse()


def parse_php_file(path: str | Path) -> Program:
    """Read and parse one PHP file without executing it."""
    source_path = Path(path)
    try:
        if source_path.stat().st_size > MAX_PHP_SOURCE_BYTES:
            location = SourceLocation(str(source_path), 1, 1, 0)
            return Program(
                str(source_path),
                diagnostics=[
                    Diagnostic(
                        f"PHP source exceeds {MAX_PHP_SOURCE_BYTES} bytes",
                        location,
                        "source_limit",
                    )
                ],
                complete=False,
            )
        source = source_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        location = SourceLocation(str(source_path), 1, 1, 0)
        return Program(
            str(source_path),
            diagnostics=[
                Diagnostic(f"Could not read PHP source: {error}", location, "read_error")
            ],
            complete=False,
        )
    return parse_php(source, str(source_path))
