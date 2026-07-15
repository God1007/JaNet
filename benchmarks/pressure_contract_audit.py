#!/usr/bin/env python3
"""Audit P0 pressure contracts with token-aware source checks and deterministic models.

This benchmark is intentionally a hard gate rather than a load generator.  It proves that
the source contains the admission, correlation, backpressure, and loss-observability
mechanisms required before high-concurrency pressure results can be trusted.  The checker
lexes the relevant C++, proto, and JavaScript sources, locates exact function/route bodies
with balanced delimiters, and then evaluates explicit structural contracts.  It does not
decide correctness from broad whole-file regular expressions.
"""

# 文件职责：在真正讨论吞吐和延迟前，以 token/语法结构和确定性模型审计六项
# P0 压力契约。它不是负载发生器；任一契约无法被严格证明时，结果必须失败。

from __future__ import annotations

import argparse
import bisect
import datetime as dt
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


SCHEMA_VERSION = "weaknet.benchmark.v1"
COMPONENT = "pressure-contract-audit"
PROFILES = {
    "smoke": {"legacy_event_model_count": 2, "analyze_burst_model": 4},
    "standard": {"legacy_event_model_count": 128, "analyze_burst_model": 64},
    "stress": {"legacy_event_model_count": 10_000, "analyze_burst_model": 256},
}

SOURCE_PATHS = (
    "server/src/net_ping.cpp",
    "server/src/grpc_service.cpp",
    "server/include/event_manager.hpp",
    "server/src/event_manager.cpp",
    "proto/weaknet.proto",
    "client/client.cpp",
    "client/weaknet_client.h",
    "dashboard/server/index.mjs",
    "dashboard/src/App.tsx",
)

# These names are an explicit source contract, not substring matching.  A future production
# implementation may add another spelling here deliberately, together with a checker test.
DROP_COUNTER_NAMES = frozenset(
    {
        "droppedEvents",
        "dropped_events",
        "dropCount",
        "drop_count",
        "eventDrops",
        "event_drops",
        "eventsDropped",
        "events_dropped",
        "gapCount",
        "gap_count",
    }
)
SEQUENCE_FIELD_NAMES = frozenset(
    {
        "sequence",
        "eventSequence",
        "event_sequence",
        "sequenceId",
        "sequence_id",
    }
)
OVERLOAD_STATUS_CODES = frozenset({429, 503})
COMPARISON_OPERATORS = frozenset({"<", "<=", ">", ">=", "==", "===", "!=", "!=="})


class AuditError(RuntimeError):
    """表示无法安全定位或解析目标源码结构；调用方必须把它视为审计失败。"""


@dataclass(frozen=True)
class Token:
    """一个轻量源码 token，保留原文、字节区间及行列坐标用于证据定位。"""

    kind: str
    value: str
    raw: str
    start: int
    end: int
    line: int
    column: int


@dataclass(frozen=True)
class Span:
    """一对已配平定界符的 token 下标，通常表示函数、条件或消息体。"""

    open_index: int
    close_index: int


@dataclass
class SourceUnit:
    """单个待审计源码文件的文本、token、行信息和配对定界符索引。"""

    repo_root: Path
    relative_path: str
    text: str
    lines: list[str]
    tokens: list[Token]
    pairs: dict[int, int]

    @classmethod
    def load(cls, repo_root: Path, relative_path: str) -> "SourceUnit":
        """读取并词法化仓库文件；文件缺失或结构非法时抛 ``AuditError``。"""

        path = repo_root / relative_path
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise AuditError(f"cannot read required source {relative_path}: {exc}") from exc
        language = "js" if path.suffix in {".mjs", ".js", ".jsx", ".ts", ".tsx"} else "native"
        tokens = lex_source(text, language)
        return cls(
            repo_root=repo_root,
            relative_path=relative_path,
            text=text,
            lines=text.splitlines(),
            tokens=tokens,
            pairs=build_pairs(tokens),
        )

    @classmethod
    def synthetic(cls, text: str, relative_path: str = "<synthetic>.mjs") -> "SourceUnit":
        """构造内存 JS 源码单元，供 detector 自测使用且不触碰仓库文件。"""

        tokens = lex_source(text, "js")
        return cls(
            repo_root=Path("."),
            relative_path=relative_path,
            text=text,
            lines=text.splitlines(),
            tokens=tokens,
            pairs=build_pairs(tokens),
        )

    def span_tokens(self, span: Span, include_braces: bool = False) -> list[Token]:
        """返回 span 内 token；默认排除两端定界符，可按需包含。"""

        start = span.open_index if include_braces else span.open_index + 1
        end = span.close_index + 1 if include_braces else span.close_index
        return self.tokens[start:end]

    def source_between_tokens(self, start_index: int, end_index: int) -> str:
        """按 token 下标截取原始源码；反向区间返回空串。"""

        if start_index > end_index:
            return ""
        return self.text[self.tokens[start_index].start : self.tokens[end_index].end]


def utc_now() -> str:
    """返回毫秒级 RFC3339 UTC 时间戳，作为 benchmark 报告起始时间。"""

    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _line_starts(text: str) -> list[int]:
    """返回每一行在文本中的起始偏移，供 token 偏移换算行列号。"""

    starts = [0]
    starts.extend(index + 1 for index, value in enumerate(text) if value == "\n")
    return starts


def _token_position(starts: Sequence[int], offset: int) -> tuple[int, int]:
    """把字符偏移映射成从 1 开始的 ``(line, column)``。"""

    line_index = bisect.bisect_right(starts, offset) - 1
    return line_index + 1, offset - starts[line_index] + 1


def _regex_can_start(previous: Token | None) -> bool:
    """根据前一个 JS token 判断 ``/`` 是否可能开始正则，而不是除法。"""

    if previous is None:
        return True
    if previous.value in {
        "(", "[", "{", ",", ":", ";", "=", "=>", "!", "!=", "!==", "&&", "||",
        "?", "+", "-", "*", "%", "&", "|", "^", "~",
    }:
        return True
    return previous.kind == "identifier" and previous.value in {
        "return", "throw", "case", "delete", "typeof", "void", "yield", "await",
    }


def lex_source(text: str, language: str) -> list[Token]:
    """词法化足够的 C++/proto/JS 语法，返回可做结构审计的 token。

    注释、字符串、模板和 JS 正则内部的括号不参与配平，否则普通文本搜索会把
    注释或正则中的大括号误认成真实控制流。字面量未终止时抛 ``AuditError``，
    审计不会在不完整源码上继续给出通过结论。
    """

    starts = _line_starts(text)
    tokens: list[Token] = []
    i = 0
    length = len(text)
    multi = (
        ">>>=", "<<=", ">>=", "===", "!==", "...", "::", "->", "++", "--", "+=", "-=",
        "*=", "/=", "%=", "&&", "||", "<=", ">=", "==", "!=", "=>", "<<", ">>", "?.",
    )

    def append(kind: str, start: int, end: int, value: str | None = None) -> None:
        """把一个 token 连同原文位置追加到当前词法结果。"""

        raw = text[start:end]
        line, column = _token_position(starts, start)
        tokens.append(Token(kind, raw if value is None else value, raw, start, end, line, column))

    while i < length:
        char = text[i]
        if char.isspace():
            i += 1
            continue

        if text.startswith("//", i):
            newline = text.find("\n", i + 2)
            i = length if newline < 0 else newline + 1
            continue
        if text.startswith("/*", i):
            close = text.find("*/", i + 2)
            if close < 0:
                raise AuditError("unterminated block comment")
            i = close + 2
            continue

        if char in {'"', "'", "`"}:
            quote = char
            start = i
            i += 1
            while i < length:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                i += 1
            else:
                raise AuditError(f"unterminated {quote} literal")
            kind = "template" if quote == "`" else "string"
            append(kind, start, i, text[start + 1 : i - 1])
            continue

        if (
            language == "js"
            and char == "/"
            and not text.startswith("//", i)
            and not text.startswith("/*", i)
            and _regex_can_start(tokens[-1] if tokens else None)
        ):
            start = i
            i += 1
            escaped = False
            in_class = False
            while i < length:
                current = text[i]
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == "[":
                    in_class = True
                elif current == "]":
                    in_class = False
                elif current == "/" and not in_class:
                    i += 1
                    while i < length and (text[i].isalpha() or text[i].isdigit()):
                        i += 1
                    break
                elif current == "\n":
                    # It was division rather than a regex.  Keep '/' as punctuation and let
                    # the remaining characters be lexed normally.
                    i = start + 1
                    append("punct", start, i)
                    break
                i += 1
            else:
                i = start + 1
                append("punct", start, i)
                continue
            if tokens and tokens[-1].start == start:
                continue
            append("regex", start, i)
            continue

        if char.isalpha() or char in {"_", "$"}:
            start = i
            i += 1
            while i < length and (text[i].isalnum() or text[i] in {"_", "$"}):
                i += 1
            append("identifier", start, i)
            continue

        if char.isdigit():
            start = i
            i += 1
            while i < length and (text[i].isalnum() or text[i] in {"_", "."}):
                i += 1
            append("number", start, i)
            continue

        matched = next((operator for operator in multi if text.startswith(operator, i)), None)
        if matched:
            append("punct", i, i + len(matched))
            i += len(matched)
            continue

        append("punct", i, i + 1)
        i += 1

    return tokens


def build_pairs(tokens: Sequence[Token]) -> dict[int, int]:
    """配平圆/方/花括号并返回双向下标映射；不平衡时抛 ``AuditError``。"""

    openings = {"(": ")", "[": "]", "{": "}"}
    closings = {value: key for key, value in openings.items()}
    stacks: dict[str, list[int]] = {key: [] for key in openings}
    pairs: dict[int, int] = {}
    for index, token in enumerate(tokens):
        # String/template payloads deliberately keep their decoded value for exact route and
        # template checks.  Only punctuation tokens may affect syntactic delimiter balance.
        if token.kind == "punct" and token.value in openings:
            stacks[token.value].append(index)
        elif token.kind == "punct" and token.value in closings:
            opening = closings[token.value]
            if not stacks[opening]:
                raise AuditError(f"unbalanced delimiter {token.value!r} at line {token.line}")
            start = stacks[opening].pop()
            pairs[start] = index
            pairs[index] = start
    leftovers = [(opening, stack[-1]) for opening, stack in stacks.items() if stack]
    if leftovers:
        opening, index = leftovers[0]
        raise AuditError(f"unclosed delimiter {opening!r} at line {tokens[index].line}")
    return pairs


def values(tokens: Sequence[Token]) -> list[str]:
    """提取 token 的规范化值列表，供连续序列匹配使用。"""

    return [token.value for token in tokens]


def contains_sequence(tokens: Sequence[Token], expected: Sequence[str]) -> bool:
    """判断 token 流是否包含给定连续值序列。"""

    if not expected:
        return True
    token_values = values(tokens)
    width = len(expected)
    return any(token_values[index : index + width] == list(expected) for index in range(len(tokens) - width + 1))


def sequence_positions(tokens: Sequence[Token], expected: Sequence[str]) -> list[int]:
    """返回给定连续 token 序列的全部起始下标。"""

    token_values = values(tokens)
    width = len(expected)
    return [
        index
        for index in range(len(tokens) - width + 1)
        if token_values[index : index + width] == list(expected)
    ]


def find_definition_after_sequence(unit: SourceUnit, expected: Sequence[str]) -> Span:
    """定位名称序列后的原生函数定义体；找不到安全定义时抛 ``AuditError``。"""

    for start in sequence_positions(unit.tokens, expected):
        open_paren = start + len(expected)
        if open_paren >= len(unit.tokens) or unit.tokens[open_paren].value != "(":
            continue
        close_paren = unit.pairs.get(open_paren)
        if close_paren is None:
            continue
        cursor = close_paren + 1
        while cursor < len(unit.tokens) and unit.tokens[cursor].value not in {"{", ";"}:
            cursor += 1
        if cursor < len(unit.tokens) and unit.tokens[cursor].value == "{":
            close = unit.pairs.get(cursor)
            if close is not None:
                return Span(cursor, close)
    rendered = " ".join(expected)
    raise AuditError(f"cannot locate definition {rendered!r} in {unit.relative_path}")


def find_js_function(unit: SourceUnit, name: str) -> Span:
    """按函数声明名定位 JS 函数体；未找到时抛 ``AuditError``。"""

    tokens = unit.tokens
    for index in range(len(tokens) - 3):
        if tokens[index].value != "function" or tokens[index + 1].value != name:
            continue
        if tokens[index + 2].value != "(":
            continue
        close_paren = unit.pairs[index + 2]
        body_open = close_paren + 1
        if body_open < len(tokens) and tokens[body_open].value == "{":
            return Span(body_open, unit.pairs[body_open])
    raise AuditError(f"cannot locate JavaScript function {name!r} in {unit.relative_path}")


def all_js_functions(unit: SourceUnit) -> dict[str, Span]:
    """收集源码中所有具名 JS 函数及其函数体 span。"""

    result: dict[str, Span] = {}
    tokens = unit.tokens
    for index in range(len(tokens) - 3):
        if tokens[index].value != "function" or tokens[index + 1].kind != "identifier":
            continue
        name = tokens[index + 1].value
        if tokens[index + 2].value != "(":
            continue
        close_paren = unit.pairs.get(index + 2)
        if close_paren is None or close_paren + 1 >= len(tokens):
            continue
        if tokens[close_paren + 1].value == "{":
            result[name] = Span(close_paren + 1, unit.pairs[close_paren + 1])
    return result


def find_js_route(unit: SourceUnit, method: str, route: str) -> Span:
    """精确定位 ``app.method(route, handler)`` 的箭头函数体；失败时抛异常。"""

    tokens = unit.tokens
    marker = ["app", ".", method, "("]
    for start in sequence_positions(tokens, marker):
        call_open = start + 3
        call_close = unit.pairs[call_open]
        if call_open + 1 >= call_close:
            continue
        route_token = tokens[call_open + 1]
        if route_token.kind != "string" or route_token.value != route:
            continue
        arrow = next(
            (index for index in range(call_open + 2, call_close) if tokens[index].value == "=>"),
            None,
        )
        if arrow is None:
            continue
        body_open = arrow + 1
        while body_open < call_close and tokens[body_open].value != "{":
            body_open += 1
        if body_open < call_close:
            return Span(body_open, unit.pairs[body_open])
    raise AuditError(f"cannot locate app.{method}({route!r}) in {unit.relative_path}")


def find_proto_message(unit: SourceUnit, name: str) -> Span:
    """按名称定位 proto message 定义体；未找到时抛 ``AuditError``。"""

    tokens = unit.tokens
    for start in sequence_positions(tokens, ["message", name, "{"]):
        body_open = start + 2
        return Span(body_open, unit.pairs[body_open])
    raise AuditError(f"cannot locate proto message {name!r} in {unit.relative_path}")


def find_calls(unit: SourceUnit, span: Span, callee: Sequence[str]) -> list[int]:
    """返回指定 span 内某个 callee token 序列的全部真实调用位置。"""

    body = unit.tokens[span.open_index + 1 : span.close_index]
    positions: list[int] = []
    width = len(callee)
    for local in sequence_positions(body, callee):
        global_index = span.open_index + 1 + local
        next_index = global_index + width
        if next_index < span.close_index and unit.tokens[next_index].value == "(":
            positions.append(global_index)
    return positions


def call_arguments(unit: SourceUnit, callee_start: int, callee_width: int) -> list[list[Token]]:
    """按配平层级拆出一次调用的实参 token；输入不是调用时抛 ``AuditError``。"""

    open_paren = callee_start + callee_width
    if unit.tokens[open_paren].value != "(":
        raise AuditError("call_arguments called on a non-call token sequence")
    close_paren = unit.pairs[open_paren]
    arguments: list[list[Token]] = []
    current_start = open_paren + 1
    cursor = current_start
    while cursor < close_paren:
        token = unit.tokens[cursor]
        if token.value in {"(", "[", "{"}:
            cursor = unit.pairs[cursor] + 1
            continue
        if token.value == ",":
            arguments.append(unit.tokens[current_start:cursor])
            current_start = cursor + 1
        cursor += 1
    if current_start < close_paren or arguments:
        arguments.append(unit.tokens[current_start:close_paren])
    return arguments


def find_if_statements(unit: SourceUnit, span: Span) -> list[tuple[Span, Span]]:
    """返回函数体内各 ``if`` 的精确条件 span 与 consequent span。"""

    result: list[tuple[Span, Span]] = []
    tokens = unit.tokens
    cursor = span.open_index + 1
    while cursor < span.close_index:
        if tokens[cursor].value != "if" or cursor + 1 >= span.close_index:
            cursor += 1
            continue
        condition_open = cursor + 1
        if tokens[condition_open].value != "(":
            cursor += 1
            continue
        condition_close = unit.pairs[condition_open]
        body_open = condition_close + 1
        if body_open >= span.close_index:
            cursor += 1
            continue
        if tokens[body_open].value == "{":
            body_close = unit.pairs[body_open]
            result.append((Span(condition_open, condition_close), Span(body_open, body_close)))
        else:
            body_close = body_open
            while body_close < span.close_index and tokens[body_close].value != ";":
                body_close += 1
            result.append((Span(condition_open, condition_close), Span(body_open - 1, body_close)))
        cursor += 1
    return result


def enclosing_brace_span(unit: SourceUnit, token_index: int, outer: Span) -> Span:
    """返回包围目标 token 的最小花括号块；不存在更小块时返回 outer。"""

    candidates = [
        Span(index, close)
        for index, close in unit.pairs.items()
        if index < close and unit.tokens[index].value == "{" and index < token_index < close
        and outer.open_index <= index and close <= outer.close_index
    ]
    if not candidates:
        return outer
    return min(candidates, key=lambda candidate: candidate.close_index - candidate.open_index)


def evidence(
    unit: SourceUnit,
    start_line: int,
    end_line: int,
    observation: str,
) -> dict[str, Any]:
    """把指定行区间整理为带路径、观察说明和源码片段的审计证据。"""

    start = max(1, start_line)
    end = min(len(unit.lines), max(start, end_line))
    snippet = "\n".join(
        f"{line_number}: {unit.lines[line_number - 1].rstrip()}"
        for line_number in range(start, end + 1)
    )
    return {
        "path": unit.relative_path,
        "line_start": start,
        "line_end": end,
        "observation": observation,
        "snippet": snippet,
    }


def evidence_for_token(unit: SourceUnit, token_index: int, radius: int, observation: str) -> dict[str, Any]:
    """围绕一个 token 生成固定行半径的审计证据。"""

    line = unit.tokens[token_index].line
    return evidence(unit, line - radius, line + radius, observation)


def make_gate(
    name: str,
    category: str,
    passed: bool,
    hard_threshold: str,
    observed: Mapping[str, Any],
    source_evidence: Sequence[Mapping[str, Any]],
    risk: str,
    remediation: str,
    kind: str = "static_contract",
) -> dict[str, Any]:
    """构造统一门禁结果，包含阈值、观测、源码证据、风险和修复建议。"""

    return {
        "name": name,
        "category": category,
        "kind": kind,
        "status": "passed" if passed else "failed",
        "passed": passed,
        "hard_threshold": hard_threshold,
        "observed": dict(observed),
        "evidence": [dict(item) for item in source_evidence],
        "risk": risk,
        "remediation": remediation,
    }


def _simple_identifier(expression: Sequence[Token]) -> str | None:
    """表达式恰为一个标识符时返回名称，否则返回 ``None``。"""

    if len(expression) == 1 and expression[0].kind == "identifier":
        return expression[0].value
    return None


def _statement_before(tokens: Sequence[Token], index: int) -> list[Token]:
    """提取目标 token 所在的近似语句，用于声明/赋值结构判断。"""

    start = index - 1
    while start >= 0 and tokens[start].value not in {";", "{", "}"}:
        start -= 1
    end = index + 1
    while end < len(tokens) and tokens[end].value != ";":
        end += 1
    return list(tokens[start + 1 : end])


def _identifier_has_atomic_declaration(tokens: Sequence[Token], identifier: str) -> bool:
    """判断某标识符所在声明语句是否包含 ``atomic`` 类型标记。"""

    for index, token in enumerate(tokens):
        if token.value != identifier:
            continue
        statement = _statement_before(tokens, index)
        if any(item.value == "atomic" for item in statement):
            return True
    return False


def _request_sequence_atomic_proof(function_tokens: Sequence[Token], sequence_argument: Sequence[Token]) -> tuple[bool, str | None]:
    """证明请求 sequence 来自原子分配，并返回被识别的共享计数器名称。

    只接受 ``fetch_add``、由其赋值的局部变量或明确 atomic 声明三类证据；无法
    证明时返回 ``(False, candidate)``，不会因变量名含 seq 就推断线程安全。
    """

    if contains_sequence(sequence_argument, ["fetch_add"]):
        identifiers = [token.value for token in sequence_argument if token.kind == "identifier"]
        return True, identifiers[0] if identifiers else None

    direct = _simple_identifier(sequence_argument)
    if direct:
        for index, token in enumerate(function_tokens):
            if token.value != direct or index + 1 >= len(function_tokens) or function_tokens[index + 1].value != "=":
                continue
            statement = _statement_before(function_tokens, index)
            if any(item.value == "fetch_add" for item in statement):
                source_identifiers = [
                    item.value
                    for item in statement
                    if item.kind == "identifier" and item.value not in {direct, "const", "uint16_t", "uint32_t", "auto"}
                ]
                return True, source_identifiers[0] if source_identifiers else direct

    identifiers = [token.value for token in sequence_argument if token.kind == "identifier"]
    for identifier in identifiers:
        if _identifier_has_atomic_declaration(function_tokens, identifier):
            return True, identifier
    return False, identifiers[-1] if identifiers else None


def _condition_has_pair(condition: Sequence[Token], left: Sequence[str], right_value: str) -> bool:
    """判断条件中是否存在成员序列与给定值的直接比较，支持左右交换。"""

    left_positions = sequence_positions(condition, left)
    for position in left_positions:
        after = position + len(left)
        if after + 1 < len(condition) and condition[after].value in COMPARISON_OPERATORS:
            if condition[after + 1].value == right_value:
                return True
        if position >= 2 and condition[position - 1].value in COMPARISON_OPERATORS:
            if condition[position - 2].value == right_value:
                return True
    return False


def _condition_compares_members(
    condition: Sequence[Token],
    left: Sequence[str],
    right: Sequence[str],
) -> bool:
    """判断条件中两个成员 token 序列是否被比较运算符直接连接。"""

    left_positions = sequence_positions(condition, left)
    right_positions = set(sequence_positions(condition, right))
    for position in left_positions:
        after = position + len(left)
        if after < len(condition) and condition[after].value in COMPARISON_OPERATORS:
            if after + 1 in right_positions:
                return True
        before = position - 1
        if before >= 0 and condition[before].value in COMPARISON_OPERATORS:
            right_start = before - len(right)
            if right_start in right_positions and right_start + len(right) == before:
                return True
    return False


def audit_ping_sequence(unit: SourceUnit) -> dict[str, Any]:
    """审计 Ping sequence 的并发分配，返回带源码证据的硬门禁结果。

    目标是排除普通函数静态变量上的 ``++`` 数据竞争，并证明每次请求把原子
    分配结果保存后传给 ``packIcmp``；结构数量异常时抛 ``AuditError``。
    """

    ping_span = find_definition_after_sequence(unit, ["NetPing", "::", "ping"])
    pack_calls = find_calls(unit, ping_span, ["packIcmp"])
    if len(pack_calls) != 1:
        raise AuditError(f"expected one packIcmp call in NetPing::ping, found {len(pack_calls)}")
    arguments = call_arguments(unit, pack_calls[0], 1)
    if len(arguments) != 3:
        raise AuditError(f"expected packIcmp to receive three arguments, found {len(arguments)}")
    sequence_argument = arguments[2]
    function_tokens = unit.span_tokens(ping_span)
    atomic, source_identifier = _request_sequence_atomic_proof(function_tokens, sequence_argument)
    plain_static = False
    if source_identifier:
        for index, token in enumerate(function_tokens):
            if token.value != source_identifier:
                continue
            statement = _statement_before(function_tokens, index)
            if any(item.value == "static" for item in statement) and not any(
                item.value == "atomic" for item in statement
            ):
                plain_static = True
                break
    sequence_expression = " ".join(token.raw for token in sequence_argument)
    evidence_items = [
        evidence_for_token(
            unit,
            pack_calls[0],
            3,
            "packIcmp 的第三个实参是实际发出的 Echo sequence；其分配必须是并发安全的。",
        )
    ]
    return make_gate(
        name="ping.sequence_concurrency_safe",
        category="ping",
        passed=atomic and not plain_static,
        hard_threshold="共享 ICMP sequence 的非原子 read-modify-write 次数必须为 0；每个并发请求必须先保存自己的不可变 request sequence。",
        observed={
            "pack_sequence_expression": sequence_expression,
            "sequence_source_identifier": source_identifier,
            "atomic_allocation_proven": atomic,
            "plain_function_static_detected": plain_static,
        },
        source_evidence=evidence_items,
        risk="gRPC Ping 与后台 RTT 监控可并发调用进程级 NetPing 单例；普通 static uint16_t 的 ++ 是数据竞争，且可能给并发请求分配重复或不可预测的 sequence。",
        remediation="把 sequence 分配改成原子单调分配（例如 static std::atomic<uint32_t>::fetch_add），窄化为 uint16_t 后保存到局部 const requestSeq，再把 requestSeq 传给 packIcmp。",
    )


def audit_ping_reply_correlation(unit: SourceUnit) -> dict[str, Any]:
    """审计 ICMP 回包是否同时关联 type、id、请求 sequence 和目标地址。"""

    ping_span = find_definition_after_sequence(unit, ["NetPing", "::", "ping"])
    pack_call = find_calls(unit, ping_span, ["packIcmp"])[0]
    arguments = call_arguments(unit, pack_call, 1)
    request_sequence = _simple_identifier(arguments[2])
    conditions = [unit.span_tokens(condition) for condition, _ in find_if_statements(unit, ping_span)]

    type_checked = any(
        _condition_has_pair(condition, ["ricmp", "->", "icmp_type"], "ICMP_ECHOREPLY")
        for condition in conditions
    )
    id_checked = any(
        _condition_has_pair(condition, ["ricmp", "->", "icmp_id"], "id")
        for condition in conditions
    )
    sequence_checked = bool(request_sequence) and any(
        _condition_has_pair(condition, ["ricmp", "->", "icmp_seq"], request_sequence)
        for condition in conditions
    )
    source_checked = any(
        _condition_compares_members(
            condition,
            ["src", ".", "sin_addr", ".", "s_addr"],
            ["dest", ".", "sin_addr", ".", "s_addr"],
        )
        or _condition_compares_members(
            condition,
            ["src", ".", "sin_addr"],
            ["dest", ".", "sin_addr"],
        )
        for condition in conditions
    )
    validation_token = next(
        (
            ping_span.open_index + 1 + position
            for position in sequence_positions(unit.span_tokens(ping_span), ["ricmp", "->", "icmp_type"])
        ),
        pack_call,
    )
    passed = type_checked and id_checked and sequence_checked and source_checked
    return make_gate(
        name="ping.reply_seq_and_target_correlation",
        category="ping",
        passed=passed,
        hard_threshold="每个被接受的 ICMP 回包必须同时满足 ECHOREPLY、request id、该调用保存的 request sequence、recvfrom source == 已解析 target；缺一项即拒绝并继续在 deadline 内接收。",
        observed={
            "stable_request_sequence_variable": request_sequence,
            "echo_reply_type_checked": type_checked,
            "request_id_checked": id_checked,
            "request_sequence_checked": sequence_checked,
            "source_target_checked": source_checked,
        },
        source_evidence=[
            evidence_for_token(
                unit,
                validation_token,
                4,
                "当前回包接受条件的完整源码；token 级比较分别验证 type/id/seq/source。",
            )
        ],
        risk="只按进程 id 接受回包时，并发 raw ICMP socket 可能消费另一个请求或另一个目标的 Echo Reply，返回错误 RTT。",
        remediation="保存局部 requestSeq；接收循环逐包校验 type、id、icmp_seq，并比较 src.sin_addr.s_addr 与 dest.sin_addr.s_addr；不匹配的包不能立即让调用失败，应继续等待到原 deadline。",
    )


@dataclass(frozen=True)
class ModuleDeclaration:
    """模块顶层变量声明及其初始化 token，供硬上限解析使用。"""

    name: str
    initializer: tuple[Token, ...]
    line: int


def _brace_depths(tokens: Sequence[Token]) -> list[int]:
    """计算每个 token 出现前的花括号深度，用于筛选模块顶层声明。"""

    depth = 0
    result: list[int] = []
    for token in tokens:
        result.append(depth)
        if token.value == "{":
            depth += 1
        elif token.value == "}":
            depth -= 1
    return result


def module_declarations(unit: SourceUnit) -> dict[str, ModuleDeclaration]:
    """提取 JS 模块顶层 ``const/let/var`` 声明及其完整初始化表达式。"""

    tokens = unit.tokens
    depths = _brace_depths(tokens)
    result: dict[str, ModuleDeclaration] = {}
    for index in range(len(tokens) - 3):
        if depths[index] != 0 or tokens[index].value not in {"const", "let", "var"}:
            continue
        name_token = tokens[index + 1]
        if name_token.kind != "identifier" or tokens[index + 2].value != "=":
            continue
        cursor = index + 3
        start = cursor
        nested = 0
        while cursor < len(tokens):
            value = tokens[cursor].value
            if value in {"(", "[", "{"}:
                nested += 1
            elif value in {")", "]", "}"}:
                nested -= 1
            elif value == ";" and nested == 0:
                break
            cursor += 1
        result[name_token.value] = ModuleDeclaration(
            name_token.value,
            tuple(tokens[start:cursor]),
            name_token.line,
        )
    return result


def _parse_positive_number(token: Token) -> int | None:
    """解析正整数字面量（含下划线和进制前缀）；非法或非正数返回 ``None``。"""

    if token.kind != "number":
        return None
    raw = token.value.replace("_", "")
    try:
        value = int(raw, 0)
    except ValueError:
        return None
    return value if value > 0 else None


def _resolve_hard_limit(token: Token, declarations: Mapping[str, ModuleDeclaration]) -> tuple[str, int] | None:
    """把正整数字面量或单字面量顶层常量解析为 ``(名称, 上限)``。"""

    literal = _parse_positive_number(token)
    if literal is not None:
        return token.raw, literal
    declaration = declarations.get(token.value)
    if declaration and len(declaration.initializer) == 1:
        value = _parse_positive_number(declaration.initializer[0])
        if value is not None:
            return declaration.name, value
    return None


def reachable_js_spans(unit: SourceUnit, root: Span) -> tuple[list[Span], list[str]]:
    """从根 handler 沿直接具名函数调用展开可达函数体，并返回函数名列表。"""

    functions = all_js_functions(unit)
    spans = [root]
    visited: set[str] = set()
    frontier = [root]
    while frontier:
        current = frontier.pop()
        body = unit.span_tokens(current)
        for index in range(len(body) - 1):
            token = body[index]
            if token.kind != "identifier" or body[index + 1].value != "(":
                continue
            if index > 0 and body[index - 1].value in {".", "?."}:
                continue
            name = token.value
            if name in functions and name not in visited:
                visited.add(name)
                spans.append(functions[name])
                frontier.append(functions[name])
    return spans, sorted(visited)


def _span_token_lists(unit: SourceUnit, spans: Sequence[Span]) -> list[list[Token]]:
    """把多个 span 转成不含外层定界符的 token 列表。"""

    return [unit.span_tokens(span) for span in spans]


def _member_calls(token_lists: Sequence[Sequence[Token]], method: str) -> set[str]:
    """找出调用指定成员方法的接收者变量名集合。"""

    result: set[str] = set()
    for tokens in token_lists:
        for index in range(len(tokens) - 3):
            if (
                tokens[index].kind == "identifier"
                and tokens[index + 1].value == "."
                and tokens[index + 2].value == method
                and tokens[index + 3].value == "("
            ):
                result.add(tokens[index].value)
    return result


def _length_bounds(
    token_lists: Sequence[Sequence[Token]],
    declarations: Mapping[str, ModuleDeclaration],
) -> dict[str, tuple[str, int]]:
    """提取 ``collection.length <op> finiteLimit`` 形式的有界集合证据。"""

    result: dict[str, tuple[str, int]] = {}
    for tokens in token_lists:
        for index in range(len(tokens) - 4):
            if (
                tokens[index].kind == "identifier"
                and tokens[index + 1].value == "."
                and tokens[index + 2].value == "length"
                and tokens[index + 3].value in COMPARISON_OPERATORS
            ):
                bound = _resolve_hard_limit(tokens[index + 4], declarations)
                if bound:
                    result[tokens[index].value] = bound
    return result


def _mutations(token_lists: Sequence[Sequence[Token]]) -> tuple[set[str], set[str]]:
    """返回被自增/加赋值和自减/减赋值的标识符集合。"""

    increments: set[str] = set()
    decrements: set[str] = set()
    for tokens in token_lists:
        for index, token in enumerate(tokens):
            if token.kind != "identifier":
                continue
            previous = tokens[index - 1].value if index > 0 else ""
            following = tokens[index + 1].value if index + 1 < len(tokens) else ""
            if previous == "++" or following in {"++", "+="}:
                increments.add(token.value)
            if previous == "--" or following in {"--", "-="}:
                decrements.add(token.value)
    return increments, decrements


def _identifier_bounds(
    token_lists: Sequence[Sequence[Token]],
    declarations: Mapping[str, ModuleDeclaration],
) -> dict[str, tuple[str, int]]:
    """提取普通标识符与有限正整数上限的比较证据。"""

    result: dict[str, tuple[str, int]] = {}
    for tokens in token_lists:
        for index in range(len(tokens) - 2):
            if tokens[index].kind != "identifier" or tokens[index + 1].value not in COMPARISON_OPERATORS:
                continue
            bound = _resolve_hard_limit(tokens[index + 2], declarations)
            if bound:
                result[tokens[index].value] = bound
    return result


def _overload_status_codes(token_lists: Sequence[Sequence[Token]]) -> set[int]:
    """收集控制区内明确返回的 429/503 过载状态码。"""

    result: set[int] = set()
    for tokens in token_lists:
        for index in range(len(tokens) - 4):
            # response.status(429) / response.status(503)
            if (
                tokens[index].kind == "identifier"
                and tokens[index + 1].value == "."
                and tokens[index + 2].value == "status"
                and tokens[index + 3].value == "("
            ):
                value = _parse_positive_number(tokens[index + 4])
                if value in OVERLOAD_STATUS_CODES:
                    result.add(value)
            # error.statusCode = 429, or object literal statusCode: 503.
            if tokens[index].value == "statusCode" and tokens[index + 1].value in {"=", ":"}:
                value = _parse_positive_number(tokens[index + 2])
                if value in OVERLOAD_STATUS_CODES:
                    result.add(value)
    return result


def detect_analyze_admission(unit: SourceUnit, spans: Sequence[Span]) -> dict[str, Any]:
    """从同一控制区证明 analyze admission，并返回结构化证据。

    可达路径中出现任意有界集合并不够：例如 ``pingHistory`` 只是历史环，不具备
    admission 语义。只有同一个配平函数/路由体同时证明队列的入队、出队和有限
    长度，active 计数器的增减和有限并发，以及 429/503 过载响应才算通过。
    这里宁可严格误报失败，也不能把无关缓存误判成资源准入控制。
    """

    declarations = module_declarations(unit)
    raw_bounded_queues: dict[str, tuple[str, int]] = {}
    linked_queue_proofs: list[dict[str, Any]] = []
    linked_active_proofs: list[dict[str, Any]] = []
    linked_status_codes: set[int] = set()

    for span in spans:
        tokens = unit.span_tokens(span)
        token_lists = [tokens]
        pushes = _member_calls(token_lists, "push")
        removes = _member_calls(token_lists, "shift") | _member_calls(token_lists, "splice")
        queue_bounds = _length_bounds(token_lists, declarations)
        local_queues = sorted(pushes & removes & set(queue_bounds))
        for name in local_queues:
            raw_bounded_queues[name] = queue_bounds[name]

        increments, decrements = _mutations(token_lists)
        active_bounds = _identifier_bounds(token_lists, declarations)
        local_active = sorted(increments & decrements & set(active_bounds))
        local_statuses = sorted(_overload_status_codes(token_lists))

        # Association is structural: all three proof families must live in this exact body.
        if not local_queues or not local_active or not local_statuses:
            continue
        start_line = unit.tokens[span.open_index].line
        end_line = unit.tokens[span.close_index].line
        for name in local_queues:
            bound_name, bound_value = queue_bounds[name]
            linked_queue_proofs.append(
                {
                    "name": name,
                    "bound": bound_name,
                    "value": bound_value,
                    "control_region": {"line_start": start_line, "line_end": end_line},
                }
            )
        for name in local_active:
            bound_name, bound_value = active_bounds[name]
            linked_active_proofs.append(
                {
                    "name": name,
                    "bound": bound_name,
                    "value": bound_value,
                    "control_region": {"line_start": start_line, "line_end": end_line},
                }
            )
        linked_status_codes.update(local_statuses)

    linked_names = {item["name"] for item in linked_queue_proofs}
    ignored = [
        {"name": name, "bound": bound[0], "value": bound[1]}
        for name, bound in sorted(raw_bounded_queues.items())
        if name not in linked_names
    ]
    passed = bool(linked_queue_proofs and linked_active_proofs and linked_status_codes)
    return {
        "passed": passed,
        "concurrency_limit_proven": bool(linked_active_proofs),
        "active_counter_candidates": linked_active_proofs,
        "bounded_queue_proven": bool(linked_queue_proofs),
        "queue_candidates": linked_queue_proofs,
        "overload_status_codes": sorted(linked_status_codes),
        "overload_response_proven": bool(linked_status_codes),
        "ignored_unrelated_bounded_queues": ignored,
    }


def analyze_detector_self_test() -> dict[str, bool]:
    """以内存源码回归测试 admission detector 的拒绝与接受两侧。

    自测不通过会抛 ``AuditError``，防止 detector 自身退化后仍给生产源码放行。
    """

    history_source = SourceUnit.synthetic(
        """
        const pingHistory = [];
        const maxPings = 240;
        function rememberPing(item) {
          pingHistory.push(item);
          while (pingHistory.length > maxPings) pingHistory.shift();
        }
        """,
        "<synthetic-history>.mjs",
    )
    history_proof = detect_analyze_admission(
        history_source,
        [find_js_function(history_source, "rememberPing")],
    )

    admission_source = SourceUnit.synthetic(
        """
        const analyzeQueue = [];
        const maxAnalyzeQueued = 8;
        const maxAnalyzeActive = 2;
        let analyzeActive = 0;
        async function withAnalyzeAdmission(task, response) {
          if (analyzeActive >= maxAnalyzeActive) {
            if (analyzeQueue.length >= maxAnalyzeQueued) {
              response.status(429);
              return;
            }
            analyzeQueue.push(task);
          }
          analyzeActive++;
          try {
            return await task();
          } finally {
            analyzeActive--;
            analyzeQueue.shift();
          }
        }
        """,
        "<synthetic-admission>.mjs",
    )
    admission_proof = detect_analyze_admission(
        admission_source,
        [find_js_function(admission_source, "withAnalyzeAdmission")],
    )

    result = {
        "history_ring_rejected": not history_proof["passed"]
        and not history_proof["bounded_queue_proven"],
        "linked_admission_accepted": bool(admission_proof["passed"]),
    }
    if not all(result.values()):
        raise AuditError(f"analyze admission detector self-test failed: {result}")
    return result


def audit_dashboard_analyze(unit: SourceUnit, profile: str) -> dict[str, Any]:
    """审计 ``/api/analyze`` 的并发、排队和过载响应是否形成闭环门禁。"""

    route = find_js_route(unit, "post", "/api/analyze")
    spans, reachable_names = reachable_js_spans(unit, route)
    detector_self_test = analyze_detector_self_test()
    proof = detect_analyze_admission(unit, spans)

    route_start = unit.tokens[route.open_index].line
    route_end = unit.tokens[route.close_index].line
    spawn_position = next(
        (
            index
            for index, token in enumerate(unit.tokens)
            if token.value == "spawn" and index + 1 < len(unit.tokens) and unit.tokens[index + 1].value == "("
        ),
        route.open_index,
    )
    return make_gate(
        name="dashboard.analyze_bounded_admission",
        category="dashboard",
        passed=bool(proof["passed"]),
        hard_threshold="同时运行的 analyze 必须受一个有限正整数上限约束；等待队列必须受独立有限正整数上限约束；队列满时必须在创建 bridge 子进程前返回 HTTP 429 或 503。",
        observed={
            "profile_burst_model": PROFILES[profile]["analyze_burst_model"],
            "reachable_named_functions": reachable_names,
            "detector_self_test": detector_self_test,
            "concurrency_limit_proven": proof["concurrency_limit_proven"],
            "active_counter_candidates": proof["active_counter_candidates"],
            "bounded_queue_proven": proof["bounded_queue_proven"],
            "queue_candidates": proof["queue_candidates"],
            "overload_status_codes": proof["overload_status_codes"],
            "overload_response_proven": proof["overload_response_proven"],
            "ignored_unrelated_bounded_queues": proof["ignored_unrelated_bounded_queues"],
        },
        source_evidence=[
            evidence(
                unit,
                route_start,
                min(route_end, route_start + 22),
                "精确定位 /api/analyze handler；其可达调用图用于证明 admission，而不是搜索任意 queue 字样。",
            ),
            evidence_for_token(
                unit,
                spawn_position,
                3,
                "每次 runRagBridge 调用会创建 Python 子进程；admission 必须在此调用之前生效。",
            ),
        ],
        risk="并发请求可无界创建 Python bridge，并在 RAG artifact 独占锁、CPU、内存和 FD 上形成资源风暴，最终拖垮 Dashboard。",
        remediation="在 /api/analyze 前增加显式 admission controller：固定 maxActive、固定 maxQueued；slot 必须 finally 释放；队列满时不采集 snapshot、不 spawn，直接返回 429（可重试限流）或 503（过载）。",
    )


def _comparison_for_buffered_amount(
    condition: Sequence[Token],
    declarations: Mapping[str, ModuleDeclaration],
) -> tuple[str, tuple[str, int]] | None:
    """解析 ``socket.bufferedAmount`` 与硬上限比较，并标记安全/超限方向。"""

    member = ["socket", ".", "bufferedAmount"]
    for position in sequence_positions(condition, member):
        after = position + len(member)
        if after + 1 < len(condition) and condition[after].value in COMPARISON_OPERATORS:
            bound = _resolve_hard_limit(condition[after + 1], declarations)
            if bound:
                operator = condition[after].value
                return ("safe" if operator in {"<", "<="} else "unsafe", bound)
        if position >= 2 and condition[position - 1].value in COMPARISON_OPERATORS:
            bound = _resolve_hard_limit(condition[position - 2], declarations)
            if bound:
                operator = condition[position - 1].value
                # LIMIT >= bufferedAmount is the safe reversed form.
                return ("safe" if operator in {">", ">="} else "unsafe", bound)
    return None


def _body_stops_send_path(tokens: Sequence[Token]) -> bool:
    """判断超限分支是否通过 continue/return/throw 等方式阻断后续 send。"""

    if any(token.value in {"continue", "return", "throw"} for token in tokens):
        return True
    return contains_sequence(tokens, ["socket", ".", "terminate", "("]) and contains_sequence(
        tokens, ["continue"]
    )


def audit_websocket_backpressure(unit: SourceUnit) -> dict[str, Any]:
    """审计每个 WebSocket ``send`` 是否受有限 bufferedAmount 上限支配。"""

    broadcast = find_js_function(unit, "broadcast")
    declarations = module_declarations(unit)
    send_positions = find_calls(unit, broadcast, ["socket", ".", "send"])
    if_statements = find_if_statements(unit, broadcast)
    comparisons: list[tuple[str, tuple[str, int], Span, Span]] = []
    for condition_span, body_span in if_statements:
        comparison = _comparison_for_buffered_amount(unit.span_tokens(condition_span), declarations)
        if comparison:
            comparisons.append((comparison[0], comparison[1], condition_span, body_span))

    guarded: list[int] = []
    for send in send_positions:
        send_block = enclosing_brace_span(unit, send, broadcast)
        for direction, _bound, condition_span, body_span in comparisons:
            if direction == "safe" and body_span.open_index < send < body_span.close_index:
                guarded.append(send)
                break
            if (
                direction == "unsafe"
                and send_block.open_index <= condition_span.open_index < body_span.close_index < send
                and _body_stops_send_path(unit.span_tokens(body_span))
            ):
                guarded.append(send)
                break

    bounds = sorted({(name, value) for _, (name, value), _, _ in comparisons})
    passed = bool(send_positions) and len(guarded) == len(send_positions) and bool(bounds)
    send_evidence = send_positions[0] if send_positions else broadcast.open_index
    return make_gate(
        name="dashboard.websocket_buffered_amount_backpressure",
        category="dashboard",
        passed=passed,
        hard_threshold="broadcast 中每一次 socket.send 都必须被 socket.bufferedAmount 与有限正整数 byte 上限支配；超过上限的路径必须 terminate/close 并 continue/return，禁止继续 send。",
        observed={
            "broadcast_send_sites": len(send_positions),
            "guarded_send_sites": len(set(guarded)),
            "buffered_amount_comparisons": len(comparisons),
            "hard_bounds": [{"name": name, "bytes": value} for name, value in bounds],
        },
        source_evidence=[
            evidence_for_token(
                unit,
                send_evidence,
                4,
                "精确定位 broadcast 内 socket.send，并检查其控制流祖先或前置终止 guard。",
            )
        ],
        risk="OPEN 只表示连接状态，不表示消费速度；慢浏览器会让 ws 内部 send buffer 无界增长并放大 Node 进程内存。",
        remediation="定义固定 maxWebSocketBufferedBytes；broadcast 先比较 socket.bufferedAmount，超限时累计独立 drop/slow-consumer 指标并 terminate/close 后 continue，只有未超限路径才 send。",
    )


def _proto_fields(unit: SourceUnit, message: Span) -> dict[str, str]:
    """解析 proto message 的字段名到类型映射，忽略字段编号等非类型部分。"""

    result: dict[str, str] = {}
    tokens = unit.span_tokens(message)
    start = 0
    for index, token in enumerate(tokens):
        if token.value != ";":
            continue
        statement = tokens[start:index]
        equals = next((pos for pos, item in enumerate(statement) if item.value == "="), None)
        if equals is not None and equals >= 2:
            field_name = statement[equals - 1].value
            field_type = " ".join(item.value for item in statement[: equals - 1])
            result[field_name] = field_type
        start = index + 1
    return result


def _counter_mutated(tokens: Sequence[Token]) -> list[str]:
    """返回代码块中被自增、自减或 ``fetch_add`` 修改的专用丢弃计数器。"""

    mutated: set[str] = set()
    for index, token in enumerate(tokens):
        if token.value not in DROP_COUNTER_NAMES:
            continue
        previous = tokens[index - 1].value if index > 0 else ""
        following = tokens[index + 1].value if index + 1 < len(tokens) else ""
        if previous in {"++", "--"} or following in {"++", "--", "+=", "-="}:
            mutated.add(token.value)
        if index + 2 < len(tokens) and tokens[index + 1].value in {".", "->"}:
            if tokens[index + 2].value == "fetch_add":
                mutated.add(token.value)
    return sorted(mutated)


def _eviction_observation(
    unit: SourceUnit,
    function_span: Span,
    eviction_call: Sequence[str],
) -> tuple[bool, list[str], int | None]:
    """检查每个队列淘汰调用所在块是否同步更新 drop counter，并返回证据位置。"""

    positions = find_calls(unit, function_span, eviction_call)
    if not positions:
        return False, [], None
    all_mutated: set[str] = set()
    for position in positions:
        block = enclosing_brace_span(unit, position, function_span)
        all_mutated.update(_counter_mutated(unit.span_tokens(block)))
    return bool(all_mutated), sorted(all_mutated), positions[0]


def audit_event_loss_observability(units: Mapping[str, SourceUnit]) -> dict[str, Any]:
    """跨 server、client、proto 和 Dashboard 审计事件丢失是否端到端可观测。

    只有每层有界队列淘汰都有独立计数、协议携带 sequence 与 drop/gap、Dashboard
    又实际映射这些字段时才通过；这样压力下的少收事件不会被误当成正常吞吐。
    """

    grpc = units["server/src/grpc_service.cpp"]
    client = units["client/client.cpp"]
    dashboard = units["dashboard/server/index.mjs"]
    proto = units["proto/weaknet.proto"]

    publish = find_definition_after_sequence(grpc, ["GrpcServer", "::", "publish"])
    push_bounded = find_definition_after_sequence(client, ["pushBounded"])
    remember = find_js_function(dashboard, "rememberEvent")

    server_recorded, server_counters, server_evict = _eviction_observation(
        grpc, publish, ["subscriber", "->", "queue", ".", "pop_front"]
    )
    client_recorded, client_counters, client_evict = _eviction_observation(
        client, push_bounded, ["queue", ".", "pop_front"]
    )
    dashboard_recorded, dashboard_counters, dashboard_evict = _eviction_observation(
        dashboard, remember, ["eventBuffer", ".", "shift"]
    )

    fields = _proto_fields(proto, find_proto_message(proto, "NetworkEvent"))
    sequence_fields = sorted(set(fields) & SEQUENCE_FIELD_NAMES)
    drop_fields = sorted(set(fields) & DROP_COUNTER_NAMES)
    normalize = find_js_function(dashboard, "normalizeEvent")
    normalize_tokens = dashboard.span_tokens(normalize)
    mapped_sequence_fields = [
        name
        for name in sequence_fields
        if contains_sequence(normalize_tokens, ["event", ".", name])
    ]
    mapped_drop_fields = [
        name
        for name in drop_fields
        if contains_sequence(normalize_tokens, ["event", ".", name])
    ]

    all_evictions_recorded = server_recorded and client_recorded and dashboard_recorded
    protocol_observable = bool(sequence_fields) and bool(drop_fields)
    dashboard_observable = bool(mapped_sequence_fields) and bool(mapped_drop_fields)
    passed = all_evictions_recorded and protocol_observable and dashboard_observable

    evidence_items: list[dict[str, Any]] = []
    for unit, position, message in (
        (grpc, server_evict, "gRPC subscriber 队列满时的淘汰块；检查同一块内是否更新专用 drop counter。"),
        (client, client_evict, "C client 有界队列淘汰块；检查同一块内是否更新专用 drop counter。"),
        (dashboard, dashboard_evict, "Dashboard eventBuffer 淘汰块；检查同一块内是否更新专用 drop counter。"),
    ):
        if position is not None:
            evidence_items.append(evidence_for_token(unit, position, 3, message))
    proto_span = find_proto_message(proto, "NetworkEvent")
    evidence_items.append(
        evidence(
            proto,
            proto.tokens[proto_span.open_index].line,
            proto.tokens[proto_span.close_index].line,
            "NetworkEvent schema 必须独立传输 sequence 与 dropped/gap，而不能复用业务 counter。",
        )
    )

    return make_gate(
        name="events.eviction_drop_gap_observable",
        category="events",
        passed=passed,
        hard_threshold="每个有界事件队列每淘汰 1 条都必须原子增加专用 drop counter；NetworkEvent 必须携带单调 sequence 与独立 dropped/gap 字段；Dashboard 必须保留并展示两者。业务 counter 不得替代这些字段。",
        observed={
            "server_subscriber_eviction_recorded": server_recorded,
            "server_drop_counters": server_counters,
            "client_queue_eviction_recorded": client_recorded,
            "client_drop_counters": client_counters,
            "dashboard_buffer_eviction_recorded": dashboard_recorded,
            "dashboard_drop_counters": dashboard_counters,
            "proto_sequence_fields": sequence_fields,
            "proto_drop_or_gap_fields": drop_fields,
            "dashboard_mapped_sequence_fields": mapped_sequence_fields,
            "dashboard_mapped_drop_or_gap_fields": mapped_drop_fields,
        },
        source_evidence=evidence_items,
        risk="队列虽有界但静默 pop/shift 会让服务端、C client 和 UI 看到不完整事件集，却无法判断缺口发生在哪一层或丢了多少条。",
        remediation="为每层队列增加独立累计 drop counter；在生产端给事件分配 uint64 单调 sequence，并扩展 proto/C API/Dashboard 模型传递 sequence 与 dropped/gap；快照和 status 暴露累计值，消费者检测 sequence 跳变。",
    )


def _return_object_property(unit: SourceUnit, function: Span, property_name: str) -> tuple[list[Token], int]:
    """提取函数 return 对象中指定属性的表达式及属性 token 下标；找不到则抛异常。"""

    tokens = unit.tokens
    for index in range(function.open_index + 1, function.close_index):
        if tokens[index].value != "return" or index + 1 >= function.close_index:
            continue
        object_open = index + 1
        if tokens[object_open].value != "{":
            continue
        object_close = unit.pairs[object_open]
        cursor = object_open + 1
        while cursor < object_close:
            if tokens[cursor].value == property_name and cursor + 1 < object_close and tokens[cursor + 1].value == ":":
                expression_start = cursor + 2
                expression_end = expression_start
                while expression_end < object_close:
                    value = tokens[expression_end].value
                    if value in {"(", "[", "{"}:
                        expression_end = unit.pairs[expression_end] + 1
                        continue
                    if value == ",":
                        break
                    expression_end += 1
                return tokens[expression_start:expression_end], cursor
            if tokens[cursor].value in {"(", "[", "{"}:
                cursor = unit.pairs[cursor] + 1
            else:
                cursor += 1
    raise AuditError(f"cannot locate return-object property {property_name!r} in {unit.relative_path}")


def _template_expression_tokens(token: Token) -> list[Token]:
    """再次词法化模板字符串中的每个 ``${...}`` 表达式；未闭合时抛异常。"""

    if token.kind != "template":
        return [token]
    raw = token.raw[1:-1]
    result: list[Token] = []
    cursor = 0
    while cursor < len(raw):
        start = raw.find("${", cursor)
        if start < 0:
            break
        depth = 1
        index = start + 2
        while index < len(raw) and depth > 0:
            if raw[index] == "{":
                depth += 1
            elif raw[index] == "}":
                depth -= 1
            index += 1
        if depth != 0:
            raise AuditError("unterminated template interpolation")
        result.extend(lex_source(raw[start + 2 : index - 1], "js"))
        cursor = index
    return result


def _expanded_expression_tokens(expression: Sequence[Token]) -> list[Token]:
    """展开表达式内模板插值并返回可用于成员引用检查的 token。"""

    result: list[Token] = []
    for token in expression:
        result.extend(_template_expression_tokens(token))
    return result


def _legacy_event_id(timestamp: int, counter: int, event_type: str) -> str:
    """复刻旧 Dashboard ID 组合规则，用于确定性碰撞回归模型。"""

    return f"{timestamp}-{counter or 0}-{event_type or 'event'}"


def _local_unique_counter_proven(
    unit: SourceUnit,
    normalize: Span,
    expression_tokens: Sequence[Token],
) -> tuple[bool, str | None]:
    """证明 ID 表达式引用了模块级、数字初始化且在 normalize 内递增的计数器。"""

    declarations = module_declarations(unit)
    body = unit.span_tokens(normalize)
    increments, _ = _mutations([body])
    referenced = {token.value for token in expression_tokens if token.kind == "identifier"}
    for identifier in sorted(referenced & increments & set(declarations)):
        declaration = declarations[identifier]
        if len(declaration.initializer) == 1 and declaration.initializer[0].kind == "number":
            return True, identifier
    return False, None


def audit_event_id_uniqueness(
    dashboard: SourceUnit,
    frontend: SourceUnit,
    proto: SourceUnit,
    profile: str,
) -> dict[str, Any]:
    """审计事件 ID 的唯一组成，并用同毫秒同 tuple 模型验证旧规则必然碰撞。

    这里不是估算哈希概率：旧 ``timestamp-counter-type`` 对相同 tuple 是 100%
    确定性重名。门禁要求 detector 先证明确有碰撞，再从生产表达式中证明协议
    sequence 或本地单调计数器；仅随机跑出“暂未重复”不能视为通过。
    """

    normalize = find_js_function(dashboard, "normalizeEvent")
    id_expression, id_property_index = _return_object_property(dashboard, normalize, "id")
    expanded = _expanded_expression_tokens(id_expression)
    expression_source = " ".join(token.raw for token in id_expression)

    proto_fields = _proto_fields(proto, find_proto_message(proto, "NetworkEvent"))
    sequence_fields = set(proto_fields) & SEQUENCE_FIELD_NAMES
    protocol_sequence_reference = next(
        (
            field
            for field in sorted(sequence_fields)
            if contains_sequence(expanded, ["event", ".", field])
        ),
        None,
    )
    local_counter_proven, local_counter = _local_unique_counter_proven(
        dashboard, normalize, expanded
    )
    proven_unique_component = bool(protocol_sequence_reference) or local_counter_proven

    model_count = PROFILES[profile]["legacy_event_model_count"]
    timestamp = 1_784_000_000_000
    counter = 0
    event_type = "Changed"
    semantic_events = [
        {
            "timestamp": timestamp,
            "counter": counter,
            "type": event_type,
            "source": f"producer-{index}",
            "message": f"distinct-event-{index}",
        }
        for index in range(model_count)
    ]
    legacy_ids = [
        _legacy_event_id(item["timestamp"], item["counter"], item["type"])
        for item in semantic_events
    ]
    unique_ids = len(set(legacy_ids))
    duplicate_ids = len(legacy_ids) - unique_ids
    legacy_collision_detected = duplicate_ids > 0

    # The model is a detector regression: it must continue proving that the old composite
    # collapses distinct events.  Production passes only after adding a separately proven
    # unique sequence component.
    passed = legacy_collision_detected and proven_unique_component
    frontend_marker = next(
        (
            index
            for index in sequence_positions(frontend.tokens, ["item", ".", "id", "===", "event", ".", "id"])
        ),
        0,
    )
    return make_gate(
        name="events.id_unique_under_same_millisecond_tuple",
        category="events",
        passed=passed,
        hard_threshold="任意两个语义不同事件即使 timestamp(ms)、type、counter 完全相同，生成的 id 也必须不同；profile 模型 duplicate_id_count 必须为 0。ID 必须引用协议单调 sequence 或经静态证明的 BFF 单调计数。",
        observed={
            "production_id_expression": expression_source,
            "protocol_sequence_reference": protocol_sequence_reference,
            "local_unique_counter": local_counter,
            "unique_component_proven": proven_unique_component,
            "legacy_model": {
                "input_events": model_count,
                "same_timestamp": timestamp,
                "same_counter": counter,
                "same_type": event_type,
                "unique_ids": unique_ids,
                "duplicate_id_count": duplicate_ids,
                "first_id": legacy_ids[0],
                "deterministic_collision_detected": legacy_collision_detected,
            },
        },
        source_evidence=[
            evidence_for_token(
                dashboard,
                id_property_index,
                4,
                "normalizeEvent 的 id 表达式被结构化提取；模板插值也会再次 token 化。",
            ),
            evidence_for_token(
                frontend,
                frontend_marker,
                3,
                "前端按 id 去重；确定性重复会直接折叠语义不同的事件。",
            ),
        ],
        risk="旧 `${timestamp}-${counter}-${type}` 是确定性复合键，不是概率哈希；同毫秒同类型且 counter 相同的两条事件必然同 ID，并被 UI 去重。",
        remediation="优先在服务端给每条事件分配 uint64 单调 sequence 并通过 proto 传递，Dashboard ID 使用 sequence；若需要 BFF 兜底，则使用进程级单调计数并明确重启 epoch，不能继续复用业务 counter。",
        kind="static_contract+deterministic_model",
    )


def command_output(command: Sequence[str], cwd: Path) -> str | None:
    """执行短时只读命令并返回非空 stdout；失败、超时或空输出返回 ``None``。"""

    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = completed.stdout.strip()
    return value if completed.returncode == 0 and value else None


def collect_environment(
    repo_root: Path,
    units: Mapping[str, SourceUnit],
    profile: str,
) -> dict[str, Any]:
    """采集运行环境、profile 参数和每个被审计源码文件的 SHA-256。"""

    git_status = command_output(
        ["git", "-c", "core.fsmonitor=false", "status", "--porcelain"], repo_root
    )
    return {
        "hostname": platform.node(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "python": sys.version.split()[0],
        "python_executable": sys.executable,
        "git_commit": command_output(["git", "rev-parse", "HEAD"], repo_root),
        "git_dirty": bool(git_status),
        "analysis_mode": "tokenized-balanced-source+deterministic-model",
        "profile_parameters": PROFILES[profile],
        "source_sha256": {
            path: hashlib.sha256(unit.text.encode("utf-8")).hexdigest()
            for path, unit in sorted(units.items())
        },
    }


def atomic_json_write(path: Path, payload: Mapping[str, Any]) -> None:
    """通过同目录临时文件原子写出 JSON，避免中断留下半份门禁结果。"""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def build_parser() -> argparse.ArgumentParser:
    """定义 contract audit 的 profile 与输出路径参数。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=sorted(PROFILES), default="smoke")
    parser.add_argument("--output", type=Path, required=True)
    return parser


def run(profile: str, output: Path) -> tuple[dict[str, Any], int]:
    """加载全部目标源码、执行六项硬门禁并写出报告，返回 ``(payload, exit_code)``。

    任一门禁失败都会让 summary 和退出码同时失败；源码读取或结构定位异常继续
    向上抛出，由 ``main`` 转成非零退出，避免“未完成审计”被解释为通过。
    """

    repo_root = Path(__file__).resolve().parents[1]
    started_at = utc_now()
    start_ns = time.perf_counter_ns()
    units = {path: SourceUnit.load(repo_root, path) for path in SOURCE_PATHS}

    benchmarks = [
        audit_ping_sequence(units["server/src/net_ping.cpp"]),
        audit_ping_reply_correlation(units["server/src/net_ping.cpp"]),
        audit_dashboard_analyze(units["dashboard/server/index.mjs"], profile),
        audit_websocket_backpressure(units["dashboard/server/index.mjs"]),
        audit_event_loss_observability(units),
        audit_event_id_uniqueness(
            units["dashboard/server/index.mjs"],
            units["dashboard/src/App.tsx"],
            units["proto/weaknet.proto"],
            profile,
        ),
    ]

    passed_count = sum(1 for benchmark in benchmarks if benchmark["passed"])
    failed = [benchmark["name"] for benchmark in benchmarks if not benchmark["passed"]]
    exit_code = 0 if not failed else 2
    duration_ms = round((time.perf_counter_ns() - start_ns) / 1_000_000, 3)
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "component": COMPONENT,
        "profile": profile,
        "environment": collect_environment(repo_root, units, profile),
        "started_at": started_at,
        "duration_ms": duration_ms,
        "benchmarks": benchmarks,
        "summary": {
            "status": "passed" if not failed else "failed",
            "total": len(benchmarks),
            "passed": passed_count,
            "failed": len(failed),
            "skipped": 0,
            "correctness_gate_passed": not failed,
            "hard_gate_failures": failed,
            "exit_code": exit_code,
        },
    }
    atomic_json_write(output, payload)
    return payload, exit_code


def main(argv: Sequence[str] | None = None) -> int:
    """命令行入口：执行审计、打印简要状态，并在任何异常时 fail-closed 返回 2。"""

    args = build_parser().parse_args(argv)
    try:
        payload, exit_code = run(args.profile, args.output)
    except Exception as exc:  # Keep CI output terse; parser failures must not be mistaken for PASS.
        print(f"pressure contract audit error: {exc}", file=sys.stderr)
        return 2
    summary = payload["summary"]
    print(
        f"{COMPONENT}: {summary['status']} "
        f"({summary['passed']}/{summary['total']} passed); report={args.output}"
    )
    for benchmark in payload["benchmarks"]:
        print(f"  {benchmark['status'].upper():6s} {benchmark['name']}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
