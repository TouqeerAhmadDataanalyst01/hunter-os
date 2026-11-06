"""Bounded, conservative taint propagation over the PHP subset IR."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from analyzer.php_parser import (
    Assignment,
    Call,
    CallStatement,
    ControlStatement,
    Expression,
    FunctionDef,
    IfStatement,
    OutputStatement,
    Program,
    ReturnStatement,
    SourceLocation,
    Statement,
)


_TARGET_PATTERN = re.compile(
    r"(?P<variable>\$[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*(?:\[[^\]]*\]|\?->\s*(?:\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*)"
    r"|->\s*(?:\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*)))*"
    r"|(?P<static>\\?[A-Za-z_][A-Za-z0-9_]*(?:\\[A-Za-z_][A-Za-z0-9_]*)*"
    r"::\$[A-Za-z_][A-Za-z0-9_]*)(?:\s*\[[^\]]*\])*"
)
_OBJECT_RECEIVER_PATTERN = re.compile(
    r"(?P<receiver>\$[A-Za-z_][A-Za-z0-9_]*(?:->[\w]+)*)"
    r"->(?P<method>[A-Za-z_][A-Za-z0-9_]*)$"
)
_OBJECT_PROPERTY_PATTERN = re.compile(
    r"\$[A-Za-z_][A-Za-z0-9_]*(?:->[\w]+)+"
)
_SCRIPT_CONTEXT_PATTERN = re.compile(r"<\s*script\b", re.IGNORECASE)
_URL_ATTRIBUTE_PATTERN = re.compile(
    r"\b(?:href|src|action|formaction|xlink:href)\s*=\s*['\"]?",
    re.IGNORECASE,
)
_SCRIPT_ATTRIBUTE_PATTERN = re.compile(r"\bon[a-z0-9_:-]*\s*=\s*['\"]?", re.IGNORECASE)
_STYLE_ATTRIBUTE_PATTERN = re.compile(r"\bstyle\s*=\s*['\"]?", re.IGNORECASE)
_HTML_ATTRIBUTE_PATTERN = re.compile(
    r"<[A-Za-z][^>]*\b[A-Za-z_:][-A-Za-z0-9_:.]*\s*=\s*['\"]?",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class TaintSource:
    name: str
    kind: str = "variable"

    def __post_init__(self) -> None:
        if self.kind not in {"variable", "call", "literal"}:
            raise ValueError(f"Unsupported taint source kind: {self.kind}")


@dataclass(frozen=True)
class TaintSink:
    name: str
    context: str
    argument_indices: tuple[int, ...] = (0,)


@dataclass(frozen=True)
class SanitizerSpec:
    name: str
    contexts: frozenset[str]


@dataclass(frozen=True)
class PropagatorSpec:
    name: str


@dataclass(frozen=True)
class TaintLimits:
    max_call_depth: int = 3
    max_steps: int = 100_000
    max_flows: int = 10_000
    max_values_per_variable: int = 10_000

    def __post_init__(self) -> None:
        if min(
            self.max_call_depth,
            self.max_steps,
            self.max_flows,
            self.max_values_per_variable,
        ) < 1:
            raise ValueError("Taint analysis limits must all be positive")


@dataclass(frozen=True)
class TaintStep:
    kind: str
    name: str
    location: SourceLocation
    contexts: frozenset[str] = frozenset()


@dataclass(frozen=True)
class TaintFlow:
    source: TaintStep
    sink: TaintStep
    context: str
    trace: tuple[TaintStep, ...]
    sanitizers: tuple[TaintStep, ...]
    mitigated: bool


@dataclass(frozen=True)
class TaintDiagnostic:
    message: str
    code: str
    location: SourceLocation | None = None


@dataclass
class TaintAnalysisResult:
    flows: list[TaintFlow] = field(default_factory=list)
    diagnostics: list[TaintDiagnostic] = field(default_factory=list)
    complete: bool = True


DEFAULT_SOURCES = (
    *(
        TaintSource(name)
        for name in (
            "$_GET",
            "$_POST",
            "$_REQUEST",
            "$_COOKIE",
            "$_FILES",
            "$_SERVER['PHP_SELF']",
        )
    ),
    TaintSource("php://input", "literal"),
    *(TaintSource(name, "call") for name in (
        "filter_input",
        "get_param",
        "get_params",
        "get_json_params",
        "get_body_params",
    )),
)

DEFAULT_SINKS = (
    TaintSink("$wpdb->query", "sql"),
    TaintSink("$wpdb->get_results", "sql"),
    TaintSink("$wpdb->get_row", "sql"),
    TaintSink("$wpdb->get_var", "sql"),
    *(TaintSink(name, "upload", (0,)) for name in (
        "move_uploaded_file",
        "wp_handle_upload",
        "wp_handle_sideload",
    )),
    *(TaintSink(name, "sensitive_action", indices) for name, indices in (
        ("wp_delete_post", (0,)),
        ("wp_update_post", (0,)),
        ("wp_delete_user", (0,)),
        ("wp_insert_user", (0,)),
        ("update_option", (1,)),
        ("add_option", (1,)),
        ("delete_option", (0,)),
        ("update_user_meta", (0, 2)),
        ("delete_user_meta", (0, 1)),
        ("update_post_meta", (0, 2)),
        ("delete_post_meta", (0, 1)),
    )),
    *(TaintSink(name, "command") for name in (
        "exec",
        "shell_exec",
        "system",
        "passthru",
        "popen",
        "proc_open",
    )),
    *(TaintSink(name, "file_path") for name in (
        "file_get_contents",
        "file_put_contents",
        "fopen",
        "readfile",
        "unlink",
        "include",
        "include_once",
        "require",
        "require_once",
    )),
    *(TaintSink(name, "network_url") for name in (
        "wp_remote_get",
        "wp_remote_post",
        "curl_init",
    )),
)

DEFAULT_SANITIZERS = (
    SanitizerSpec("esc_html", frozenset({"html"})),
    SanitizerSpec("esc_attr", frozenset({"html", "html_attribute"})),
    SanitizerSpec("esc_url", frozenset({"html", "url"})),
    SanitizerSpec("esc_textarea", frozenset({"html"})),
    SanitizerSpec("wp_kses", frozenset({"html"})),
    SanitizerSpec("wp_kses_post", frozenset({"html"})),
    SanitizerSpec("$wpdb->prepare", frozenset({"sql"})),
    SanitizerSpec("esc_sql", frozenset({"sql_value"})),
    SanitizerSpec("intval", frozenset({"sql", "html", "html_attribute"})),
    SanitizerSpec("absint", frozenset({"sql", "html", "html_attribute"})),
    SanitizerSpec("sanitize_file_name", frozenset({"filename"})),
    SanitizerSpec("sanitize_text_field", frozenset({"input_validation"})),
    SanitizerSpec("sanitize_email", frozenset({"input_validation"})),
    SanitizerSpec("wp_check_filetype", frozenset({"file_type"})),
    SanitizerSpec("wp_verify_nonce", frozenset({"nonce"})),
)

DEFAULT_PROPAGATORS = (
    PropagatorSpec("wp_unslash"),
    PropagatorSpec("stripslashes"),
    PropagatorSpec("trim"),
    PropagatorSpec("strval"),
    PropagatorSpec("sanitize_text_field"),
)


@dataclass(frozen=True)
class _TaintedValue:
    source: TaintStep
    trace: tuple[TaintStep, ...] = ()
    sanitizers: tuple[TaintStep, ...] = ()
    sanitized_contexts: frozenset[str] = frozenset()


@dataclass
class _Execution:
    environment: dict[str, set[_TaintedValue]]
    returns: set[_TaintedValue] = field(default_factory=set)
    active: bool = True


def _call_matches(call_name: str, registered_name: str) -> bool:
    call_name = call_name.casefold().lstrip("\\")
    registered_name = registered_name.casefold()
    unqualified_name = call_name.rsplit("\\", 1)[-1]
    if call_name == registered_name or unqualified_name == registered_name:
        return True
    if registered_name.startswith("$") or "::" in registered_name or "->" in registered_name:
        return False
    return call_name.endswith(f"->{registered_name}") or unqualified_name.endswith(
        f"::{registered_name}"
    )


def _output_context(expression: str) -> str:
    if _SCRIPT_CONTEXT_PATTERN.search(expression):
        return "javascript"
    if _URL_ATTRIBUTE_PATTERN.search(expression):
        return "url"
    if _SCRIPT_ATTRIBUTE_PATTERN.search(expression):
        return "javascript"
    if _STYLE_ATTRIBUTE_PATTERN.search(expression):
        return "css"
    if _HTML_ATTRIBUTE_PATTERN.search(expression):
        return "html_attribute"
    return "html"


def _sanitizer_is_effective(sanitizer: SanitizerSpec, call: Call) -> bool:
    if sanitizer.name.casefold() != "$wpdb->prepare":
        return True
    if len(call.arguments) < 2:
        return False
    placeholders = re.findall(
        r"(?<!%)%(?:\d+\$)?[sdfi]", call.arguments[0], re.IGNORECASE
    )
    bound_arguments = len(call.arguments) - 1
    array_argument = call.arguments[1].lstrip().casefold().startswith("array(")
    if array_argument and len(call.argument_calls) > 1:
        array_call = next(
            (
                nested
                for nested in call.argument_calls[1]
                if nested.name.casefold() == "array"
            ),
            None,
        )
        if array_call is not None:
            bound_arguments = len(array_call.arguments)
    return bool(placeholders) and len(placeholders) <= bound_arguments


def _function_statements(function: FunctionDef) -> list[Statement]:
    return _function_statements_from(function.body)


def _literal_string_map(expression: str) -> bool:
    return bool(
        re.fullmatch(
            r"\s*\[\s*(?:'[^'\\]*'\s*=>\s*'[^'\\]*'\s*,?\s*)+\]\s*",
            expression,
            re.DOTALL,
        )
    )


def _sql_allowlist_return(
    function: FunctionDef,
) -> tuple[str, int | None, int] | None:
    returns = [
        statement
        for statement in _function_statements(function)
        if isinstance(statement, ReturnStatement) and statement.value is not None
    ]
    if len(returns) != 1:
        return None
    return_text = returns[0].value.text
    for statement in _function_statements(function):
        if not isinstance(statement, Assignment) or not re.fullmatch(
            r"\$[A-Za-z_][A-Za-z0-9_]*", statement.target
        ):
            continue
        map_name = statement.target
        if not _literal_string_map(statement.value.text):
            continue
        if sum(
            isinstance(item, Assignment) and item.target == map_name
            for item in _function_statements(function)
        ) != 1:
            continue
        for parameter in function.parameters:
            lookup = rf"{re.escape(map_name)}\s*\[\s*{re.escape(parameter)}\s*\]"
            if re.fullmatch(
                rf"\s*isset\s*\(\s*{lookup}\s*\)\s*\?\s*{lookup}\s*:\s*"
                r"""(['"])[^'"\\]*\1\s*""",
                return_text,
                re.IGNORECASE,
            ):
                return (
                    f"SQL allowlist validator: {function.class_name or ''}"
                    f"{'::' if function.class_name else ''}{function.name}",
                    None,
                    function.parameters.index(parameter),
                )

    for parameter in function.parameters:
        for default_index, default_parameter in enumerate(function.parameters):
            if default_index == 0:
                continue
            enum_return = re.fullmatch(
                rf"\s*in_array\s*\(\s*{re.escape(parameter)}\s*,\s*"
                r"\[\s*(?:'[^'\\]*'\s*,\s*)+'[^'\\]*'\s*\]\s*,\s*true\s*\)"
                rf"\s*\?\s*{re.escape(parameter)}\s*:\s*"
                rf"{re.escape(default_parameter)}\s*",
                return_text,
                re.IGNORECASE,
            )
            if enum_return:
                return (
                    f"SQL enum validator: {function.class_name or ''}"
                    f"{'::' if function.class_name else ''}{function.name}",
                    default_index,
                    function.parameters.index(parameter),
                )
    return None


def _target_variable(target: str) -> str | None:
    match = re.match(r"(\$[A-Za-z_][A-Za-z0-9_]*)", target)
    return match.group(1) if match else None


def _depends_on_variable(
    starts: tuple[str, ...],
    target: str,
    assignments: list[Assignment],
    max_hops: int = 3,
) -> bool:
    dependencies: dict[str, set[str]] = {}
    for assignment in assignments:
        variable = _target_variable(assignment.target)
        if variable is not None:
            dependencies.setdefault(variable, set()).update(
                assignment.value.variables
            )
    frontier = set(starts)
    visited: set[str] = set()
    for _ in range(max_hops + 1):
        if target in frontier:
            return True
        visited.update(frontier)
        frontier = {
            dependency
            for variable in frontier
            for dependency in dependencies.get(variable, set())
            if dependency not in visited
        }
    return False


def _bound_array_is_derived_from(
    bound_variables: tuple[str, ...],
    source_variable: str,
    assignments: list[Assignment],
) -> bool:
    if source_variable in bound_variables:
        return True
    for bound_variable in bound_variables:
        writes = [
            assignment
            for assignment in assignments
            if _target_variable(assignment.target) == bound_variable
        ]
        if not writes or any(
            assignment.value.text.strip().casefold() not in {"array()", "[]"}
            and not any(
                call.name.casefold() == "array_merge"
                and bound_variable in call.argument_variables[0]
                and source_variable in tuple(
                    variable
                    for group in call.argument_variables[1:]
                    for variable in group
                )
                for call in assignment.value.calls
                if call.argument_variables
            )
            for assignment in writes
        ):
            continue
        if any(
            any(
                call.name.casefold() == "array_merge"
                and source_variable
                in tuple(
                    variable
                    for group in call.argument_variables[1:]
                    for variable in group
                )
                for call in assignment.value.calls
                if call.argument_variables
            )
            for assignment in writes
        ):
            return True
    return False


def _generated_placeholder_binding(
    call: Call,
    function: FunctionDef | None,
    format_values: set[_TaintedValue],
) -> bool:
    if function is None or len(call.argument_variables) < 2:
        return False
    statements = _function_statements(function)
    assignments = [
        statement for statement in statements if isinstance(statement, Assignment)
    ]
    format_variables = call.argument_variables[0]
    bound_variables = call.argument_variables[1]
    for assignment in assignments:
        if not assignment.value.text.casefold().count("array_fill"):
            continue
        generated = re.search(
            r"array_fill\s*\(\s*0\s*,\s*count\s*\(\s*(\$[A-Za-z_][A-Za-z0-9_]*)"
            r"\s*\)\s*,\s*(['\"])(%[sdfi])\2\s*\)",
            assignment.value.text,
            re.IGNORECASE,
        )
        placeholder_variable = _target_variable(assignment.target)
        if generated is None or placeholder_variable is None:
            continue
        count_variable = generated.group(1)
        if (
            "implode" not in assignment.value.text.casefold()
            or set(assignment.value.variables) != {count_variable}
        ):
            continue
        if (
            set(format_variables) != {placeholder_variable}
            and not format_values
        ):
            continue
        if not _depends_on_variable(
            format_variables, placeholder_variable, assignments
        ):
            continue
        if not _bound_array_is_derived_from(
            bound_variables, count_variable, assignments
        ):
            continue
        if any(
            not {
                "count",
                "array_fill",
                "implode",
            }.issubset({step.name.casefold() for step in value.trace})
            or count_variable.casefold()
            not in {step.name.casefold() for step in value.trace}
            for value in format_values
        ):
            continue
        return True
    return False


def _paired_where_placeholders(
    call: Call,
    function: FunctionDef | None,
    format_values: set[_TaintedValue],
) -> bool:
    if function is None or len(call.argument_variables) < 2 or format_values:
        return False
    format_text = call.arguments[0]
    bound_variables = set(call.argument_variables[1])
    if "implode" not in format_text.casefold():
        return False
    template_variables = set(call.argument_variables[0])
    for nested_call in (
        call.argument_calls[0] if call.argument_calls else ()
    ):
        template_variables.update(
            variable
            for group in nested_call.argument_variables
            for variable in group
        )
    if not template_variables or not template_variables.intersection(
        {f"${name}" for name in ("where_conditions", "conditions")}
    ):
        return False
    template_variable = next(
        iter(
            template_variables.intersection(
                {"$where_conditions", "$conditions"}
            )
        )
    )
    bound_variable = next(
        iter(bound_variables.intersection({"$where_values", "$values"})),
        None,
    )
    if bound_variable is None:
        return False
    if template_variables != {template_variable}:
        return False

    all_assignments = [
        statement
        for statement in _function_statements(function)
        if isinstance(statement, Assignment)
    ]
    for variable in (template_variable, bound_variable):
        initializers = [
            assignment
            for assignment in all_assignments
            if assignment.target == variable
        ]
        if any(
            assignment.value.text.strip().casefold() not in {"array()", "[]"}
            for assignment in initializers
        ):
            return False
    template_appends = [
        assignment
        for assignment in all_assignments
        if assignment.target == f"{template_variable}[]"
    ]
    value_appends = [
        assignment
        for assignment in all_assignments
        if assignment.target == f"{bound_variable}[]"
    ]

    def literal_placeholder_count(expression: str) -> int:
        literal = re.fullmatch(r"\s*(['\"])(.*?)\1\s*", expression, re.DOTALL)
        if literal is None:
            return 0
        return len(re.findall(r"(?<!%)%[sdfi]", literal.group(2), re.IGNORECASE))

    placeholder_count = sum(
        literal_placeholder_count(assignment.value.text)
        for assignment in template_appends
    )
    if (
        not template_appends
        or placeholder_count != len(value_appends)
        or len(template_appends) != len(value_appends)
        or any(
            literal_placeholder_count(assignment.value.text) != 1
            for assignment in template_appends
        )
    ):
        return False

    conditional_groups: list[tuple[int, int]] = []
    pending = list(function.body)
    while pending:
        statement = pending.pop()
        if isinstance(statement, IfStatement):
            for branch in (statement.then_body, statement.else_body):
                branch_assignments = [
                    item
                    for item in _function_statements_from(branch)
                    if isinstance(item, Assignment)
                ]
                conditions = [
                    item
                    for item in branch_assignments
                    if item.target == f"{template_variable}[]"
                ]
                values = [
                    item
                    for item in branch_assignments
                    if item.target == f"{bound_variable}[]"
                ]
                if conditions:
                    conditional_groups.append(
                        (
                            sum(
                                literal_placeholder_count(item.value.text)
                                for item in conditions
                            ),
                            len(values),
                        )
                    )
            pending.extend(statement.then_body)
            pending.extend(statement.else_body)
        elif isinstance(statement, ControlStatement):
            pending.extend(statement.body)
            for _, branch_body in statement.branches:
                pending.extend(branch_body)
    return bool(conditional_groups) and all(
        placeholders == values for placeholders, values in conditional_groups
    )


def _prepared_call_has_safe_format(
    call: Call,
    function: FunctionDef | None,
    format_values: set[_TaintedValue],
) -> bool:
    if len(call.arguments) < 2:
        return False
    if (
        re.fullmatch(r"\s*(['\"]).*\1\s*", call.arguments[0], re.DOTALL)
        and _sanitizer_is_effective(
            SanitizerSpec("$wpdb->prepare", frozenset({"sql"})), call
        )
        and not format_values
    ):
        return True
    return _generated_placeholder_binding(call, function, format_values) or (
        _paired_where_placeholders(call, function, format_values)
    )


def _sql_prepared_builder(function: FunctionDef) -> bool:
    returns = [
        statement
        for statement in _function_statements(function)
        if isinstance(statement, ReturnStatement) and statement.value is not None
    ]
    if len(returns) != 1:
        return False
    return_expression = returns[0].value
    implode_calls = [
        call for call in return_expression.calls if call.name.casefold() == "implode"
    ]
    if (
        len(implode_calls) != 1
        or not return_expression.text.lstrip().casefold().startswith("implode")
        or implode_calls[0].end_offset
        != return_expression.location.offset + len(return_expression.text)
        or len(implode_calls[0].argument_variables) < 2
        or len(implode_calls[0].argument_variables[1]) != 1
    ):
        return False
    returned_array = implode_calls[0].argument_variables[1][0]
    if not returned_array:
        return False
    statements = _function_statements(function)
    appends = [
        statement
        for statement in statements
        if isinstance(statement, Assignment)
        and statement.target == f"{returned_array}[]"
    ]
    if not appends:
        return False
    for statement in statements:
        if (
            not isinstance(statement, Assignment)
            or _target_variable(statement.target) != returned_array
            or statement.target == f"{returned_array}[]"
        ):
            continue
        if statement.value.variables or statement.value.calls:
            return False
    for append in appends:
        value = append.value
        if not value.variables and not value.calls:
            continue
        prepared_call = next(
            (
                call
                for call in value.calls
                if _call_matches(call.name, "$wpdb->prepare")
            ),
            None,
        )
        if prepared_call is None or not _prepared_call_has_safe_format(
            prepared_call, function, set()
        ):
            return False
    return True


def _function_statements_from(statements: tuple[Statement, ...]) -> list[Statement]:
    result: list[Statement] = []
    pending = list(statements)
    while pending:
        statement = pending.pop()
        result.append(statement)
        if isinstance(statement, IfStatement):
            pending.extend(statement.then_body)
            pending.extend(statement.else_body)
        elif isinstance(statement, ControlStatement):
            pending.extend(statement.body)
            for _, branch_body in statement.branches:
                pending.extend(branch_body)
    return result


class _Analyzer:
    def __init__(
        self,
        program: Program,
        sources: tuple[TaintSource, ...],
        sinks: tuple[TaintSink, ...],
        sanitizers: tuple[SanitizerSpec, ...],
        propagators: tuple[PropagatorSpec, ...],
        limits: TaintLimits,
    ):
        self.program = program
        self.sources = sources
        self.sinks = sinks
        self.sanitizers = sanitizers
        self.propagators = propagators
        self.limits = limits
        self.result = TaintAnalysisResult()
        self.steps = 0
        self.current_function: FunctionDef | None = None
        self.functions: dict[str, list[FunctionDef]] = {}
        self._flow_keys: set[tuple[object, ...]] = set()
        for function in program.functions:
            self.functions.setdefault(function.name.casefold(), []).append(function)
        for class_def in program.classes:
            for method in class_def.methods:
                self.functions.setdefault(method.name.casefold(), []).append(method)
                self.functions.setdefault(
                    f"{class_def.name}::{method.name}".casefold(), []
                ).append(method)

    def _step(
        self,
        kind: str,
        name: str,
        location: SourceLocation,
        contexts: frozenset[str] = frozenset(),
    ) -> TaintStep:
        return TaintStep(kind, name, location, contexts)

    def _diagnose(
        self, message: str, code: str, location: SourceLocation | None = None
    ) -> None:
        if not any(
            item.code == code and item.message == message
            for item in self.result.diagnostics
        ):
            self.result.diagnostics.append(TaintDiagnostic(message, code, location))
        self.result.complete = False

    def _bounded_values(
        self, values: set[_TaintedValue], location: SourceLocation
    ) -> set[_TaintedValue]:
        if len(values) <= self.limits.max_values_per_variable:
            return values
        self._diagnose(
            "Taint analysis exceeded "
            f"{self.limits.max_values_per_variable} values for one variable",
            "value_limit",
            location,
        )
        ordered = sorted(
            values,
            key=lambda value: (
                value.source.location.file,
                value.source.location.offset,
                value.source.name,
                tuple((step.kind, step.location.offset) for step in value.trace),
                tuple(step.location.offset for step in value.sanitizers),
            ),
        )
        return set(ordered[: self.limits.max_values_per_variable])

    def _tick(self, location: SourceLocation | None = None) -> bool:
        self.steps += 1
        if self.steps <= self.limits.max_steps:
            return True
        self._diagnose(
            f"Taint analysis exceeded {self.limits.max_steps} execution steps",
            "step_limit",
            location,
        )
        return False

    def run(self) -> TaintAnalysisResult:
        if not self.program.complete:
            for diagnostic in self.program.diagnostics:
                self.result.diagnostics.append(
                    TaintDiagnostic(
                        f"PHP parsing incomplete: {diagnostic.message}",
                        "incomplete_parse",
                        diagnostic.location,
                    )
                )
            self.result.complete = False
            return self.result

        self._execute(self.program.statements, {})
        for function in self._all_functions():
            if self.steps > self.limits.max_steps:
                break
            self._invoke(function, [], function.location, 0)
        if self.steps > self.limits.max_steps:
            self.result.complete = False
        return self.result

    def _all_functions(self) -> list[FunctionDef]:
        functions: list[FunctionDef] = []
        seen: set[int] = set()
        for entries in self.functions.values():
            for function in entries:
                if id(function) not in seen:
                    functions.append(function)
                    seen.add(id(function))
        return functions

    def _source_for_variable(
        self, variable: str, location: SourceLocation
    ) -> set[_TaintedValue]:
        return {
            _TaintedValue(self._step("source", source.name, location))
            for source in self.sources
            if source.kind == "variable" and source.name.casefold() == variable.casefold()
        }

    def _values_for_variables(
        self,
        variables: tuple[str, ...],
        locations: tuple[SourceLocation, ...],
        environment: dict[str, set[_TaintedValue]],
        fallback_location: SourceLocation,
    ) -> set[_TaintedValue]:
        values: set[_TaintedValue] = set()
        for index, variable in enumerate(variables):
            location = locations[index] if index < len(locations) else fallback_location
            values.update(environment.get(variable, set()))
            values.update(self._source_for_variable(variable, location))
        return values

    def _call_source(self, call: Call) -> set[_TaintedValue]:
        sources = {
            _TaintedValue(self._step("source", source.name, call.location))
            for source in self.sources
            if source.kind == "call" and _call_matches(call.name, source.name)
        }
        literal_arguments = {
            argument.strip().strip("\"'").casefold()
            for argument in call.arguments
        }
        sources.update(
            _TaintedValue(self._step("source", source.name, call.location))
            for source in self.sources
            if source.kind == "literal"
            and source.name.casefold() in literal_arguments
        )
        return sources

    def _function_for_call(self, call_name: str) -> FunctionDef | None:
        normalized = call_name.lstrip("\\").casefold()
        if "::" in normalized:
            class_name, method_name = normalized.rsplit("::", 1)
            normalized = class_name.rsplit("\\", 1)[-1] + "::" + method_name
        exact = self.functions.get(normalized, [])
        if len(exact) == 1:
            return exact[0]
        if len(exact) > 1:
            self._diagnose(
                f"Ambiguous function target for call {call_name}",
                "ambiguous_call",
            )
            return None
        if "->" in call_name:
            method_name = call_name.rsplit("->", 1)[-1].casefold()
            candidates = self.functions.get(method_name, [])
            if len(candidates) == 1:
                return candidates[0]
            if len(candidates) > 1:
                self._diagnose(
                    f"Ambiguous method target for call {call_name}",
                    "ambiguous_call",
                )
        return None

    def _invoke(
        self,
        function: FunctionDef,
        arguments: list[set[_TaintedValue]],
        call_location: SourceLocation,
        depth: int,
        receiver_name: str | None = None,
        caller_environment: dict[str, set[_TaintedValue]] | None = None,
    ) -> set[_TaintedValue]:
        if not self._tick(call_location):
            return set()
        if depth >= self.limits.max_call_depth:
            self._diagnose(
                f"Call depth exceeded {self.limits.max_call_depth} at {function.name}",
                "call_depth_limit",
                call_location,
            )
            propagated: set[_TaintedValue] = set()
            call_step = self._step("call", function.name, call_location)
            for values in arguments:
                propagated.update(
                    _TaintedValue(
                        value.source,
                        value.trace + (call_step,),
                        value.sanitizers,
                        value.sanitized_contexts,
                    )
                    for value in values
                )
            return propagated

        environment: dict[str, set[_TaintedValue]] = {}
        for index, parameter in enumerate(function.parameters):
            values = arguments[index] if index < len(arguments) else set()
            parameter_step = self._step("parameter", parameter, call_location)
            environment[parameter] = self._bounded_values(
                {
                    _TaintedValue(
                        value.source,
                        value.trace
                        + (
                            self._step("call", function.name, call_location),
                            parameter_step,
                        ),
                        value.sanitizers,
                        value.sanitized_contexts,
                    )
                    for value in values
                },
                call_location,
            )
        if receiver_name is not None and caller_environment is not None:
            receiver_prefix = receiver_name + "->"
            for variable, values in caller_environment.items():
                if variable.startswith(receiver_prefix):
                    environment["$this" + variable[len(receiver_name) :]] = set(values)
        previous_function = self.current_function
        self.current_function = function
        try:
            execution = self._execute(function.body, environment, depth)
        finally:
            self.current_function = previous_function
        if receiver_name is not None and caller_environment is not None:
            for variable, values in execution.environment.items():
                if variable.startswith("$this->"):
                    caller_environment[
                        receiver_name + variable[len("$this") :]
                    ] = set(values)
        return_values: set[_TaintedValue] = set()
        for value in execution.returns:
            return_values.add(
                _TaintedValue(
                    value.source,
                    value.trace + (self._step("return", function.name, function.location),),
                    value.sanitizers,
                    value.sanitized_contexts,
                )
            )
        return self._bounded_values(return_values, call_location)

    def _evaluate_call(
        self,
        call: Call,
        environment: dict[str, set[_TaintedValue]],
        depth: int,
    ) -> set[_TaintedValue]:
        if not self._tick(call.location):
            return set()
        arguments = []
        for index in range(len(call.arguments)):
            variables = (
                call.argument_variables[index]
                if index < len(call.argument_variables)
                else ()
            )
            locations = (
                call.argument_variable_locations[index]
                if index < len(call.argument_variable_locations)
                else ()
            )
            fallback_location = (
                call.argument_locations[index]
                if index < len(call.argument_locations)
                else call.location
            )
            argument_values = self._values_for_variables(
                variables, locations, environment, fallback_location
            )
            nested_calls = (
                call.argument_calls[index]
                if index < len(call.argument_calls)
                else ()
            )
            for nested_call in nested_calls:
                argument_values.update(
                    self._evaluate_call(nested_call, environment, depth)
                )
            arguments.append(self._bounded_values(argument_values, fallback_location))
        call_values = set().union(*arguments) if arguments else set()

        self._record_sink_flows(call, arguments)

        source_values = self._call_source(call)
        if source_values:
            return source_values

        if _call_matches(call.name, "apply_filters") and len(arguments) > 1:
            filtered_values = arguments[1]
            propagation_step = self._step("propagator", "apply_filters", call.location)
            return self._bounded_values(
                {
                    _TaintedValue(
                        value.source,
                        value.trace + (propagation_step,),
                        value.sanitizers,
                        value.sanitized_contexts,
                    )
                    for value in filtered_values
                },
                call.location,
            )

        sanitizer = next(
            (
                item
                for item in self.sanitizers
                if _call_matches(call.name, item.name)
                and (
                    _prepared_call_has_safe_format(
                        call,
                        self.current_function,
                        arguments[0] if arguments else set(),
                    )
                    if item.name.casefold() == "$wpdb->prepare"
                    else _sanitizer_is_effective(item, call)
                )
            ),
            None,
        )
        if sanitizer is not None:
            sanitizer_step = self._step(
                "sanitizer", sanitizer.name, call.location, sanitizer.contexts
            )
            sanitizer_values = (
                call_values
                if sanitizer.name.casefold() == "$wpdb->prepare"
                else arguments[0] if arguments else set()
            )
            return self._bounded_values(
                {
                    _TaintedValue(
                        value.source,
                        value.trace + (sanitizer_step,),
                        value.sanitizers + (sanitizer_step,),
                        value.sanitized_contexts | sanitizer.contexts,
                    )
                    for value in sanitizer_values
                },
                call.location,
            )

        receiver_match = _OBJECT_RECEIVER_PATTERN.fullmatch(call.name)
        receiver_name = (
            receiver_match.group("receiver") if receiver_match is not None else None
        )
        function = self._function_for_call(call.name)
        if function is not None:
            allowlist = _sql_allowlist_return(function)
            if allowlist is not None:
                sanitizer_name, fallback_index, input_index = allowlist
                non_input_arguments_are_safe = all(
                    not values
                    for index, values in enumerate(arguments)
                    if index != input_index
                )
                fallback_is_safe = (
                    fallback_index is None
                    or fallback_index >= len(arguments)
                    or not arguments[fallback_index]
                )
                if non_input_arguments_are_safe and fallback_is_safe:
                    sanitizer_step = self._step(
                        "sanitizer",
                        sanitizer_name,
                        call.location,
                        frozenset({"sql"}),
                    )
                    return self._bounded_values(
                        {
                            _TaintedValue(
                                value.source,
                                value.trace + (sanitizer_step,),
                                value.sanitizers + (sanitizer_step,),
                                value.sanitized_contexts | frozenset({"sql"}),
                            )
                            for value in call_values
                        },
                        call.location,
                    )
            if _sql_prepared_builder(function):
                sanitizer_step = self._step(
                    "sanitizer",
                    f"Prepared SQL builder: {function.class_name or ''}"
                    f"{'::' if function.class_name else ''}{function.name}",
                    call.location,
                    frozenset({"sql"}),
                )
                return self._bounded_values(
                    {
                        _TaintedValue(
                            value.source,
                            value.trace + (sanitizer_step,),
                            value.sanitizers + (sanitizer_step,),
                            value.sanitized_contexts | frozenset({"sql"}),
                        )
                        for value in call_values
                    },
                    call.location,
                )
            return self._invoke(
                function,
                arguments,
                call.location,
                depth + 1,
                receiver_name,
                environment,
            )

        if receiver_name is not None and not arguments:
            property_values = environment.get(receiver_name, set())
            propagation_step = self._step("call", call.name, call.location)
            return self._bounded_values(
                {
                    _TaintedValue(
                        value.source,
                        value.trace + (propagation_step,),
                        value.sanitizers,
                        value.sanitized_contexts,
                    )
                    for value in property_values
                },
                call.location,
            )

        propagator = next(
            (item for item in self.propagators if _call_matches(call.name, item.name)),
            None,
        )
        kind = "propagator" if propagator is not None else "call"
        propagation_step = self._step(
            kind, propagator.name if propagator else call.name, call.location
        )
        return self._bounded_values(
            {
                _TaintedValue(
                    value.source,
                    value.trace + (propagation_step,),
                    value.sanitizers,
                    value.sanitized_contexts,
                )
                for value in call_values
            },
            call.location,
        )

    def _evaluate_expression(
        self,
        expression: Expression,
        environment: dict[str, set[_TaintedValue]],
        depth: int,
    ) -> set[_TaintedValue]:
        nested_call_starts = {
            nested.location.offset
            for call in expression.calls
            for nested_calls in call.argument_calls
            for nested in nested_calls
        }
        top_calls = [
            call
            for call in expression.calls
            if call.location.offset not in nested_call_starts
        ]
        direct_variables: list[str] = []
        direct_locations: list[SourceLocation] = []
        for index, variable in enumerate(expression.variables):
            location = (
                expression.variable_locations[index]
                if index < len(expression.variable_locations)
                else expression.location
            )
            if any(
                call.location.offset <= location.offset < call.end_offset
                for call in top_calls
            ):
                continue
            direct_variables.append(variable)
            direct_locations.append(location)
        direct_values = self._bounded_values(
            self._values_for_variables(
                tuple(direct_variables),
                tuple(direct_locations),
                environment,
                expression.location,
            ),
            expression.location,
        )
        for property_name in _OBJECT_PROPERTY_PATTERN.findall(expression.text):
            direct_values.update(environment.get(property_name, set()))
        direct_values = self._bounded_values(
            direct_values, expression.location
        )
        call_values: set[_TaintedValue] = set()
        for call in top_calls:
            call_values.update(self._evaluate_call(call, environment, depth))

        if len(top_calls) == 1:
            call = top_calls[0]
            expression_end = expression.location.offset + len(expression.text)
            if (
                expression.text.lstrip().casefold().startswith(call.name.casefold())
                and call.end_offset == expression_end
            ):
                return call_values
        return self._bounded_values(
            direct_values | call_values, expression.location
        )

    def _record_sink_flows(
        self, call: Call, arguments: list[set[_TaintedValue]]
    ) -> None:
        for sink_spec in self.sinks:
            if not _call_matches(call.name, sink_spec.name):
                continue
            for argument_index in sink_spec.argument_indices:
                if argument_index < 0 or argument_index >= len(arguments):
                    continue
                self._record_sink_values(
                    sink_spec.name,
                    sink_spec.context,
                    call.location,
                    arguments[argument_index],
                )

    def _record_sink_values(
        self,
        sink_name: str,
        context: str,
        location: SourceLocation,
        values: set[_TaintedValue],
    ) -> None:
        sink_step = self._step("sink", sink_name, location)
        for value in values:
            flow = TaintFlow(
                value.source,
                sink_step,
                context,
                value.trace + (sink_step,),
                value.sanitizers,
                context in value.sanitized_contexts,
            )
            key = (
                flow.source.name,
                flow.source.location.file,
                flow.source.location.offset,
                flow.sink.name,
                flow.sink.location.file,
                flow.sink.location.offset,
                flow.context,
                tuple((item.name, item.location.offset) for item in flow.sanitizers),
                flow.mitigated,
            )
            if key in self._flow_keys:
                continue
            if len(self.result.flows) >= self.limits.max_flows:
                self._diagnose(
                    f"Taint analysis exceeded {self.limits.max_flows} findings",
                    "flow_limit",
                    location,
                )
                return
            self._flow_keys.add(key)
            self.result.flows.append(flow)

    def _merge_environments(
        self, environments: list[dict[str, set[_TaintedValue]]]
    ) -> dict[str, set[_TaintedValue]]:
        merged: dict[str, set[_TaintedValue]] = {}
        for environment in environments:
            for variable, values in environment.items():
                merged.setdefault(variable, set()).update(values)
        for variable, values in merged.items():
            if values:
                merged[variable] = self._bounded_values(
                    values, next(iter(values)).source.location
                )
        return merged

    def _execute(
        self,
        statements: tuple[Statement, ...] | list[Statement],
        environment: dict[str, set[_TaintedValue]],
        depth: int = 0,
    ) -> _Execution:
        current = {name: set(values) for name, values in environment.items()}
        returns: set[_TaintedValue] = set()
        active = True
        for statement in statements:
            if not active or not self._tick(statement.location):
                break
            if isinstance(statement, Assignment):
                values = self._evaluate_expression(statement.value, current, depth)
                target_match = _TARGET_PATTERN.fullmatch(statement.target)
                if target_match is None:
                    self._diagnose(
                        f"Unsupported assignment target {statement.target}",
                        "unsupported_assignment_target",
                        statement.location,
                    )
                    continue
                target = target_match.group("variable") or target_match.group("static")
                assert target is not None
                property_match = re.match(
                    r"(?P<property>\$[A-Za-z_][A-Za-z0-9_]*->[\w]+)",
                    statement.target,
                )
                if property_match is not None:
                    target = property_match.group("property")
                if statement.operator != "=":
                    values.update(current.get(target, set()))
                elif "[" in statement.target or "->" in statement.target:
                    values.update(current.get(target, set()))
                stored_values = self._bounded_values(
                    {
                        _TaintedValue(
                            value.source,
                            value.trace
                            + (self._step("assignment", target, statement.location),),
                            value.sanitizers,
                            value.sanitized_contexts,
                        )
                        for value in values
                    },
                    statement.location,
                )
                current[target] = stored_values
            elif isinstance(statement, CallStatement):
                self._evaluate_expression(statement.expression, current, depth)
            elif isinstance(statement, OutputStatement):
                for expression in statement.expressions:
                    values = self._evaluate_expression(expression, current, depth)
                    context = _output_context(expression.text)
                    if context == "html":
                        expression_end = (
                            expression.location.offset + len(expression.text)
                        )
                        sanitizer_is_inline = any(
                            expression.location.offset
                            <= sanitizer.location.offset
                            < expression_end
                            for value in values
                            for sanitizer in value.sanitizers
                        )
                        if any(value.sanitizers for value in values) and not sanitizer_is_inline:
                            context = "unknown_output"
                    self._record_sink_values(
                        statement.kind,
                        context,
                        statement.location,
                        values,
                    )
            elif isinstance(statement, ReturnStatement):
                if statement.value is not None:
                    returns = self._bounded_values(
                        returns
                        | self._evaluate_expression(statement.value, current, depth),
                        statement.location,
                    )
                active = False
            elif isinstance(statement, IfStatement):
                self._evaluate_expression(statement.condition, current, depth)
                then_result = self._execute(statement.then_body, current, depth)
                else_result = self._execute(statement.else_body, current, depth)
                if not statement.else_body:
                    else_result = _Execution(
                        {name: set(values) for name, values in current.items()}
                    )
                returns = self._bounded_values(
                    returns | then_result.returns | else_result.returns,
                    statement.location,
                )
                active_environments = [
                    result.environment
                    for result in (then_result, else_result)
                    if result.active
                ]
                current = self._merge_environments(active_environments)
                active = bool(active_environments)
            elif isinstance(statement, ControlStatement):
                if statement.kind in {"break", "continue"}:
                    active = False
                elif statement.kind == "throw":
                    if statement.expression is not None:
                        self._evaluate_expression(statement.expression, current, depth)
                    active = False
                elif statement.kind == "switch":
                    if statement.expression is not None:
                        self._evaluate_expression(statement.expression, current, depth)
                    branch_results = [
                        self._execute(body, current, depth)
                        for _, body in statement.branches
                    ]
                    if not any(label is None for label, _ in statement.branches):
                        branch_results.append(
                            _Execution(
                                {name: set(values) for name, values in current.items()}
                            )
                        )
                    returns = self._bounded_values(
                        returns
                        | set().union(*(item.returns for item in branch_results)),
                        statement.location,
                    )
                    current = self._merge_environments(
                        [item.environment for item in branch_results]
                    )
                    active = True
                elif statement.kind == "try":
                    alternatives = [
                        self._execute(statement.body, current, depth)
                    ]
                    finally_body: tuple[Statement, ...] = ()
                    for condition, body in statement.branches:
                        if condition is None:
                            finally_body = body
                        else:
                            self._evaluate_expression(condition, current, depth)
                            alternatives.append(self._execute(body, current, depth))
                    returns = self._bounded_values(
                        returns | set().union(*(item.returns for item in alternatives)),
                        statement.location,
                    )
                    current = self._merge_environments(
                        [item.environment for item in alternatives if item.active]
                    )
                    active = any(item.active for item in alternatives)
                    if finally_body and active:
                        final_result = self._execute(finally_body, current, depth)
                        returns = self._bounded_values(
                            returns | final_result.returns, statement.location
                        )
                        current = final_result.environment
                        active = final_result.active
                else:
                    iterable_values: set[_TaintedValue] = set()
                    if statement.expression is not None:
                        iterable_values = self._evaluate_expression(
                            statement.expression, current, depth
                        )
                    loop_environment = {
                        name: set(values) for name, values in current.items()
                    }
                    for variable in statement.iteration_variables:
                        loop_environment[variable] = self._bounded_values(
                            {
                                _TaintedValue(
                                    value.source,
                                    value.trace
                                    + (
                                        self._step(
                                            "assignment",
                                            variable,
                                            statement.location,
                                        ),
                                    ),
                                    value.sanitizers,
                                    value.sanitized_contexts,
                                )
                                for value in iterable_values
                            },
                            statement.location,
                        )
                    loop_result = self._execute(
                        statement.body, loop_environment, depth
                    )
                    returns = self._bounded_values(
                        returns | loop_result.returns, statement.location
                    )
                    environments = [loop_result.environment]
                    if statement.kind != "do_while":
                        environments.append(current)
                    current = self._merge_environments(environments)
                    active = True
        return _Execution(current, returns, active)


def analyze_program(
    program: Program,
    *,
    sources: tuple[TaintSource, ...] = DEFAULT_SOURCES,
    sinks: tuple[TaintSink, ...] = DEFAULT_SINKS,
    sanitizers: tuple[SanitizerSpec, ...] = DEFAULT_SANITIZERS,
    propagators: tuple[PropagatorSpec, ...] = DEFAULT_PROPAGATORS,
    limits: TaintLimits | None = None,
) -> TaintAnalysisResult:
    """Track configured source values through the parser's supported PHP subset.

    Incomplete parser input is not analyzed. Limit-exhausted analysis may return
    partial flows, but is always marked incomplete with a diagnostic.
    """
    return _Analyzer(
        program,
        tuple(sources),
        tuple(sinks),
        tuple(sanitizers),
        tuple(propagators),
        limits or TaintLimits(),
    ).run()
