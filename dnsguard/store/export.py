"""Streaming the query log somewhere else, as JSON lines.

SQLite plus a CSV download from the console is fine for a person reading the
log, and useless for anything that wants to consume it — a log shipper, a
notebook, `jq`, whatever the household already runs. One line of JSON per query,
written to a file or to stdout, covers all of that with no schema to agree on
and no driver to install.

Deliberately *not* dnstap. dnstap is the format every other resolver speaks and
it would be the better answer here, but it is Frame Streams plus protobuf, and a
hand-rolled encoder with no conformance test against a real consumer is exactly
the sort of feature that looks present and is not. JSON lines are honest about
what they are.

Also deliberately not a second copy of the retention story: this writes, rotates
by size, and stops. Whatever consumes the stream owns it after that.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from ..errors import DNSGuardError
from ..log import get

log = get("querylog.export")

#: Rotate when the file passes this, keeping one previous generation. Small
#: enough that a forgotten export cannot fill a Pi's card, large enough that a
#: busy household still gets a useful window.
MAX_BYTES = 64 * 1024 * 1024


class JsonLinesExport:
    """Append one JSON object per query to a file, or to stdout for `-`."""

    def __init__(self, path: str, columns, *, max_bytes: int = MAX_BYTES):
        self.path = path
        self.columns = list(columns)
        self.max_bytes = max_bytes
        self._fh = None
        self._written = 0

    def _open(self):
        if self._fh is not None:
            return self._fh
        if self.path == "-":
            self._fh = sys.stdout
            return self._fh
        p = Path(self.path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        self._written = p.stat().st_size if p.exists() else 0
        self._fh = p.open("a", encoding="utf-8")
        return self._fh

    def _rotate_if_needed(self) -> None:
        if self.path == "-" or self._written < self.max_bytes:
            return
        p = Path(self.path).expanduser()
        try:
            if self._fh is not None:
                self._fh.close()
            p.replace(p.with_suffix(p.suffix + ".1"))
        except OSError:
            log.exception("could not rotate %s", p)
        finally:
            self._fh = None
            self._written = 0

    def write(self, rows) -> None:
        """`rows` are column tuples in `QueryLog._COLUMNS` order.

        Never raises: a full disk or a closed pipe on the export path must not
        stop the query log — still less DNS — so a failure disables the export
        and says so once.
        """
        if not rows:
            return
        try:
            fh = self._open()
            for row in rows:
                rec = dict(zip(self.columns, row, strict=True))
                answers = rec.get("answers")
                if isinstance(answers, str):
                    try:
                        rec["answers"] = json.loads(answers)
                    except ValueError:
                        pass
                line = json.dumps(rec, separators=(",", ":")) + "\n"
                fh.write(line)
                self._written += len(line)
            fh.flush()
            self._rotate_if_needed()
        except Exception as e:
            log.exception("query log export to %s failed; disabling it", self.path)
            self.close()
            raise ExportDisabled(str(e)) from e

    def close(self) -> None:
        if self._fh is not None and self.path != "-":
            try:
                self._fh.close()
            except OSError:
                pass
        self._fh = None


class ExportDisabled(DNSGuardError):
    """Raised once when an export has failed and been shut down."""
