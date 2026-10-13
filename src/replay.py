"""Zircolite-equivalent Sigma replay engine (stdlib only).

Zircolite (wagga40/Zircolite) evaluates Sigma rules by
  1. flattening every JSON event into one SQLite row, naming each column after
     the leaf key with non-alphanumeric characters removed,
  2. declaring every column ``COLLATE NOCASE`` and storing booleans as
     "true"/"false" and lists as their ``str()``,
  3. splitting ``Hashes``-style fields ("MD5=..,SHA256=..") into extra columns,
  4. adding any column a rule needs but the data lacks as a NULL column, and
  5. running each rule's pySigma-generated SQL (``SELECT * FROM logs WHERE ..``)
     with a ``regexp`` UDF that treats a value as non-matching if the regex runs
     longer than one second.

This module reproduces those five steps so the benchmark can run where
Zircolite's compiled dependencies are unavailable. ``crosscheck_zircolite.py``
compares its output against real Zircolite on the same inputs.
"""

from __future__ import annotations

import json
import re
import signal
import sqlite3
import tarfile
import zipfile
from functools import lru_cache
from pathlib import Path

NON_ALNUM = re.compile(r"[^a-zA-Z0-9]")
SPLIT_FIELDS = {"Hash", "Hashes", "ConfigurationFileHash"}  # Zircolite config.yaml `split`
USELESS = (None, "")  # Zircolite config.yaml `useless`
REGEX_TIMEOUT_SECONDS = 1.0
IDENT = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")
SQL_WORDS = {
    "select", "from", "logs", "where", "and", "or", "not", "like", "escape", "in",
    "is", "null", "regexp", "glob", "between", "collate", "nocase", "case", "when",
    "then", "else", "end", "lower", "upper", "instr", "coalesce", "cast", "as",
    "text", "integer", "length", "substr", "true", "false",
}


# --------------------------------------------------------------------------- data
def _members(path: Path):
    """Yield the raw bytes of every JSON member of a .zip or .tar.gz dataset."""
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if "__MACOSX/" in name or not name.lower().endswith(".json"):
                    continue
                yield zf.read(name)
    else:
        with tarfile.open(path, "r:*") as tf:
            for m in tf.getmembers():
                base = m.name.rsplit("/", 1)[-1]
                if m.isfile() and m.name.lower().endswith(".json") and not base.startswith("._"):
                    yield tf.extractfile(m).read()


def load_events(zip_path: Path) -> tuple[list[dict], int]:
    """Read every JSON-lines member of an OTRF dataset archive.

    Returns (events, number of lines that were not valid JSON objects).
    """
    events: list[dict] = []
    bad = 0
    for raw in _members(Path(zip_path)):
        text = raw.decode("utf-8", errors="replace").strip()
        if text.startswith("["):
            events.extend(e for e in json.loads(text) if isinstance(e, dict))
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue
            if isinstance(e, dict):
                events.append(e)
            else:
                bad += 1
    return events, bad


def _scalar(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, list):
        return str(v)
    if isinstance(v, int) and not -(1 << 63) <= v < (1 << 63):
        return float(v)
    return v


def flatten(event: dict, filename: str) -> dict:
    """Flatten one event the way Zircolite's flatten kernel does."""
    event = dict(event)
    event["OriginalLogfile"] = filename
    row: dict = {}
    lower_seen: set[str] = set()
    splits: dict = {}
    stack = [event]
    while stack:
        node = stack.pop()
        for k, v in node.items():
            if isinstance(v, dict):
                stack.append(v)
                continue
            if v is None or (isinstance(v, str) and v == ""):  # Zircolite `useless`
                continue
            key = NON_ALNUM.sub("", str(k))
            if not key:
                continue
            val = _scalar(v)
            if key.lower() in lower_seen:  # SQLite column names ignore case
                continue
            row[key] = val
            lower_seen.add(key.lower())
            if key in SPLIT_FIELDS and isinstance(val, str):
                for pair in val.split(","):
                    pk, found, pv = pair.partition("=")
                    pk = NON_ALNUM.sub("", pk)
                    if found and pk:
                        splits[pk] = pv
    for k, v in splits.items():  # a split pair never overrides a real field
        if k.lower() not in lower_seen:
            row[k] = v
            lower_seen.add(k.lower())
    return row


# --------------------------------------------------------------------------- sqlite
class _RegexTimeout(Exception):
    pass


def _alarm(_signum, _frame):
    raise _RegexTimeout()


@lru_cache(maxsize=1024)
def _compile(pattern: str):
    return re.compile(pattern)


class Replay:
    """One in-memory SQLite database holding one dataset's events."""

    def __init__(self, rows: list[dict]):
        self.conn = sqlite3.connect(":memory:", isolation_level=None)
        self.conn.create_function("regexp", 2, self._udf_regex)
        self.regex_timeouts = 0
        # SQLite column names ignore case; like Zircolite, the first spelling of a
        # field name seen in the dataset becomes the column for every spelling.
        types: dict[str, str] = {}
        canon: dict[str, str] = {}
        for r in rows:
            for k, v in r.items():
                kl = k.lower()
                if kl not in canon:
                    canon[kl] = k
                    types[k] = (
                        "INTEGER COLLATE NOCASE" if isinstance(v, int) else
                        "NUMERIC COLLATE NOCASE" if isinstance(v, float) else
                        "TEXT COLLATE NOCASE"
                    )
        self.columns = {k.lower() for k in types}
        cols = ", ".join(f'"{k}" {t}' for k, t in types.items())
        self.conn.execute(f"CREATE TABLE logs (row_id INTEGER PRIMARY KEY AUTOINCREMENT, {cols})")
        names = list(types)
        q = f'INSERT INTO logs ({", ".join(chr(34)+n+chr(34) for n in names)}) VALUES ({", ".join("?"*len(names))})'
        self.conn.execute("BEGIN")
        pos = {n.lower(): i for i, n in enumerate(names)}

        def values(r):
            out = [None] * len(names)
            for k, v in r.items():
                out[pos[k.lower()]] = v
            return out
        self.conn.executemany(q, (values(r) for r in rows))
        self.conn.execute("COMMIT")
        for idx in ("Channel", "EventID"):
            if idx.lower() in self.columns:
                self.conn.execute(f'CREATE INDEX "ix_{idx}" ON logs ("{idx}")')
        self.present_channels = {
            (c or "").lower() for (c,) in self.conn.execute('SELECT DISTINCT "Channel" FROM logs')
        } if "channel" in self.columns else set()

    def _udf_regex(self, pattern, value):
        if value is None:
            return 0
        try:
            rx = _compile(pattern)
        except re.error:
            return 0
        signal.setitimer(signal.ITIMER_REAL, REGEX_TIMEOUT_SECONDS)
        try:
            return 1 if rx.search(str(value)) else 0
        except _RegexTimeout:
            self.regex_timeouts += 1
            return 0
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)

    def _ensure_columns(self, rule: dict, sql: str):
        """Zircolite adds every column a rule names but the data lacks, as NULL."""
        stripped = re.sub(r"'(?:[^']|'')*'", "''", sql)  # drop string literals
        wanted = set(rule.get("required_fields") or [])
        wanted |= {w for w in IDENT.findall(stripped) if w.lower() not in SQL_WORDS}
        wanted |= set(re.findall(r'"([^"]+)"', stripped))
        for name in wanted:
            if name.lower() in self.columns or name.lower() in {"row_id", "rowid", "oid", "_rowid_"}:
                continue
            esc = name.replace('"', '""')
            self.conn.execute(f'ALTER TABLE logs ADD COLUMN "{esc}" TEXT COLLATE NOCASE')
            self.columns.add(name.lower())

    def can_match(self, rule: dict) -> bool:
        """Skip rules whose required channel is absent (Zircolite's prefilter)."""
        chans = rule.get("channel") or []
        if not chans:
            return True
        return any(c.lower() in self.present_channels for c in chans)

    def run(self, rule: dict) -> tuple[list[int], str | None]:
        """Return (matched row ids, error) for one Zircolite rule."""
        hits: list[int] = []
        for sql in rule["rule"]:
            try:
                self._ensure_columns(rule, sql)
                cur = self.conn.execute(sql.replace("SELECT *", "SELECT row_id", 1))
                hits.extend(r[0] for r in cur)
            except sqlite3.Error as exc:
                return hits, str(exc)
        return hits, None


signal.signal(signal.SIGALRM, _alarm)
