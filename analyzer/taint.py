"""Bounded, conservative taint propagation over the PHP subset IR."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from analyzer.php_parser import (
    Assignment,
    Call,
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


_TARGET_PATTERN = re.compile(r"(\$[A-Za-z_][A-Za-z0-9_]*)")


@dataclass(frozen=True)
class TaintSource:
    name: str
    kind: str = "variable"

    def __post_init__(self) -> None:
        if self.kind not in {"variable", "call"}:
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
    max_call_depth: int = 8
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
    *(TaintSource(name) for name in ("$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES")),
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
    )),
    *(TaintSink(name, "network_url") for name in (
        "wp_remote_get",
        "wp_remote_post",
        "curl_init",
    )),
)

DEFAULT_SANITIZERS = (
    SanitizerSpec("esc_html", frozenset({"html"})),
    SanitizerSpec("esc_attr", frozenset({"html_attribute"})),
    SanitizerSpec("esc_url", frozenset({"url"})),
    SanitizerSpec("wp_kses", frozenset({"html"})),
    SanitizerSpec("wp_kses_post", frozenset({"html"})),
    SanitizerSpec("$wpdb->prepare", frozenset({"sql"})),
    SanitizerSpec("esc_sql", frozenset({"sql"})),
    SanitizerSpec("sanitize_file_name", frozenset({"filename"})),
    SanitizerSpec("sanitize_text_field", frozenset({"input_validation"})),
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
    call_name = call_name.casefold()
    registered_name = registered_name.casefold()
    if call_name == registered_name:
        return True
    if registered_name.startswith("$") or "::" in registered_name or "->" in registered_name:
        return False
    return call_name.endswith(f"->{registered_name}") or call_name.endswith(
        f"::{registered_name}"
    )


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

    def _step(self, kind: str, name: str, location: SourceLocation) -> TaintStep:
        return TaintStep(kind, name, location)

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
        return {
            _TaintedValue(self._step("source", source.name, call.location))
            for source in self.sources
            if source.kind == "call" and _call_matches(call.name, source.name)
        }

    def _function_for_call(self, call_name: str) -> FunctionDef | None:
        exact = self.functions.get(call_name.casefold(), [])
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
        execution = self._execute(function.body, environment, depth)
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

        sanitizer = next(
            (item for item in self.sanitizers if _call_matches(call.name, item.name)),
            None,
        )
        if sanitizer is not None:
            sanitizer_step = self._step("sanitizer", sanitizer.name, call.location)
            return self._bounded_values(
                {
                    _TaintedValue(
                        value.source,
                        value.trace + (sanitizer_step,),
                        value.sanitizers + (sanitizer_step,),
                        value.sanitized_contexts | sanitizer.contexts,
                    )
                    for value in call_values
                },
                call.location,
            )

        function = self._function_for_call(call.name)
        if function is not None:
            return self._invoke(function, arguments, call.location, depth + 1)

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
                target = target_match.group(1)
                if statement.operator != "=":
                    values.update(current.get(target, set()))
                current[target] = self._bounded_values(
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
            elif isinstance(statement, CallStatement):
                self._evaluate_expression(statement.expression, current, depth)
            elif isinstance(statement, OutputStatement):
                for expression in statement.expressions:
                    values = self._evaluate_expression(expression, current, depth)
                    self._record_sink_values(
                        statement.kind,
                        "html",
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
