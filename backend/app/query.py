"""HuntForge Query Language (HQL): a safe parser that compiles to parameterised SQL.

Grammar (case-insensitive keywords)::

    expr    := or
    or      := and ( OR and )*
    and     := not ( [AND] not )*          # adjacent terms are implicitly ANDed
    not     := NOT not | atom
    atom    := '(' expr ')' | FIELD OP VALUE | VALUE      # bare VALUE = free-text search
    OP      := = | == | != | > | < | >= | <= | : | ~ | contains

Only whitelisted fields map to columns. User input is only ever bound as SQL
parameters; it is never interpolated into SQL text.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

FIELDS = {
    "timestamp": "ts", "ts": "ts", "source": "source", "event_type": "event_type", "type": "event_type",
    "outcome": "outcome", "severity": "severity", "src_ip": "src_ip", "dst_ip": "dst_ip",
    "dst_port": "dst_port", "port": "dst_port", "user": "username", "username": "username",
    "host": "hostname", "hostname": "hostname", "process": "process_name", "process_name": "process_name",
    "parent": "parent_process", "parent_process": "parent_process", "command": "command_line",
    "command_line": "command_line", "domain": "domain", "bytes_out": "bytes_out", "country": "country",
    "message": "message", "id": "id", "ingestion": "ingestion_id", "ingestion_id": "ingestion_id",
}
NUMERIC = {"dst_port", "bytes_out", "ingestion_id", "id"}
FREE_TEXT_COLUMNS = ["username", "hostname", "src_ip", "dst_ip", "domain", "process_name",
                     "command_line", "message", "event_type", "parent_process"]

MAX_TOKENS = 200
MAX_DEPTH = 20

TOKEN_RE = re.compile(
    r"""\s*(?:
        (?P<op>==|!=|>=|<=|=|>|<|:|~)
      | (?P<lp>\()
      | (?P<rp>\))
      | "(?P<dq>(?:[^"\\]|\\.)*)"
      | '(?P<sq>(?:[^'\\]|\\.)*)'
      | (?P<word>[^\s()=!<>:~"']+)
    )""",
    re.X,
)


class QueryError(ValueError):
    pass


@dataclass
class Tok:
    kind: str  # op, lp, rp, str, word
    value: str


def tokenize(text: str) -> list[Tok]:
    toks: list[Tok] = []
    pos = 0
    text = text.strip()
    while pos < len(text):
        m = TOKEN_RE.match(text, pos)
        if not m or m.end() == pos:
            raise QueryError(f"Unexpected character at position {pos}: {text[pos:pos + 10]!r}")
        pos = m.end()
        if m.group("op"):
            toks.append(Tok("op", m.group("op")))
        elif m.group("lp"):
            toks.append(Tok("lp", "("))
        elif m.group("rp"):
            toks.append(Tok("rp", ")"))
        elif m.group("dq") is not None:
            toks.append(Tok("str", re.sub(r"\\(.)", r"\1", m.group("dq"))))
        elif m.group("sq") is not None:
            toks.append(Tok("str", re.sub(r"\\(.)", r"\1", m.group("sq"))))
        elif m.group("word") is not None:
            toks.append(Tok("word", m.group("word")))
        if len(toks) > MAX_TOKENS:
            raise QueryError("Query too long")
    return toks


def _like_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class Parser:
    def __init__(self, toks: list[Tok]):
        self.t = toks
        self.i = 0
        self.depth = 0

    def peek(self, off=0) -> Tok | None:
        j = self.i + off
        return self.t[j] if j < len(self.t) else None

    def kw(self, tok: Tok | None, word: str) -> bool:
        return tok is not None and tok.kind == "word" and tok.value.upper() == word

    def parse(self) -> tuple[str, list]:
        if not self.t:
            return "1=1", []
        sql, args = self.or_()
        if self.i != len(self.t):
            raise QueryError("Unexpected token: " + self.t[self.i].value)
        return sql, args

    def or_(self):
        sql, args = self.and_()
        while self.kw(self.peek(), "OR"):
            self.i += 1
            s2, a2 = self.and_()
            sql, args = f"({sql} OR {s2})", args + a2
        return sql, args

    def and_(self):
        sql, args = self.not_()
        while True:
            nxt = self.peek()
            if nxt is None or nxt.kind == "rp" or self.kw(nxt, "OR"):
                break
            if self.kw(nxt, "AND"):
                self.i += 1
            s2, a2 = self.not_()
            sql, args = f"({sql} AND {s2})", args + a2
        return sql, args

    def not_(self):
        if self.kw(self.peek(), "NOT"):
            self.i += 1
            s, a = self.not_()
            return f"(NOT {s})", a
        return self.atom()

    def atom(self):
        tok = self.peek()
        if tok is None:
            raise QueryError("Unexpected end of query")
        if tok.kind == "lp":
            self.depth += 1
            if self.depth > MAX_DEPTH:
                raise QueryError("Query nested too deeply")
            self.i += 1
            sql, args = self.or_()
            if not self.peek() or self.peek().kind != "rp":
                raise QueryError("Missing closing parenthesis")
            self.i += 1
            self.depth -= 1
            return f"({sql})", args
        if tok.kind == "rp":
            raise QueryError("Unexpected ')'")
        if tok.kind == "op":
            raise QueryError(f"Unexpected operator {tok.value!r}")
        if self.kw(tok, "AND") or self.kw(tok, "OR"):
            raise QueryError(f"Unexpected {tok.value.upper()}; quote it to search for the literal word")
        nxt = self.peek(1)
        if tok.kind == "word" and nxt is not None and (
            nxt.kind == "op" or self.kw(nxt, "CONTAINS")
        ) and tok.value.lower() in FIELDS:
            self.i += 2
            val = self.peek()
            if val is None or val.kind not in ("word", "str"):
                raise QueryError(f"Missing value for {tok.value}")
            self.i += 1
            op = "~" if nxt.kind == "word" else nxt.value
            return self.compare(tok.value.lower(), op, val.value)
        if tok.kind == "word" and nxt is not None and nxt.kind == "op":
            raise QueryError(f"Unknown field {tok.value!r}. Known fields: " + ", ".join(sorted(set(FIELDS))))
        self.i += 1
        return self.free_text(tok.value)

    def free_text(self, value: str):
        like = f"%{_like_escape(value)}%"
        cols = " OR ".join(f"{c} LIKE ? ESCAPE '\\'" for c in FREE_TEXT_COLUMNS)
        cols += " OR raw LIKE ? ESCAPE '\\'"
        return f"({cols})", [like] * (len(FREE_TEXT_COLUMNS) + 1)

    def compare(self, field: str, op: str, value: str):
        col = FIELDS[field]
        if col in NUMERIC or col == "ts" and op in (">", "<", ">=", "<="):
            if col in NUMERIC:
                try:
                    v: object = int(value)
                except ValueError:
                    raise QueryError(f"Field {field} expects a number")
            else:
                v = value
            if op in ("=", "==", ":"):
                return f"{col} = ?", [v]
            if op == "!=":
                return f"({col} IS NULL OR {col} != ?)", [v]
            if op in (">", "<", ">=", "<="):
                return f"{col} {op} ?", [v]
            raise QueryError(f"Operator {op} not valid for {field}")
        if op in (">", "<", ">=", "<="):
            return f"{col} {op} ?", [value]
        if op == "~":
            return f"{col} LIKE ? ESCAPE '\\'", [f"%{_like_escape(value)}%"]
        if op in ("=", "==", ":", "!="):
            neg = op == "!="
            if "*" in value:
                like = _like_escape(value).replace("*", "%")
                sql = f"{col} LIKE ? ESCAPE '\\'"
            else:
                like = value
                sql = f"{col} = ? COLLATE NOCASE"
            if neg:
                return f"({col} IS NULL OR NOT ({sql}))", [like]
            return sql, [like]
        raise QueryError(f"Unsupported operator {op}")


def compile_query(text: str | None) -> tuple[str, list]:
    if not text or not text.strip():
        return "1=1", []
    if len(text) > 2000:
        raise QueryError("Query too long")
    return Parser(tokenize(text)).parse()
