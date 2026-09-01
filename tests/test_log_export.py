"""JSON-lines export of the query log."""
from __future__ import annotations

import json

import pytest
from test_store import mkrec

from trench.store import Database, QueryLog
from trench.store.export import ExportDisabled, JsonLinesExport
from trench.store.querylog import _COLUMNS


def export_to(tmp_path, **kw) -> JsonLinesExport:
    return JsonLinesExport(str(tmp_path / "q.jsonl"), _COLUMNS, **kw)


def read(path):
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]


def row(**over):
    """A full column tuple, so the export's strict zip is exercised for real."""
    values = {"ts": 1, "client_ip": "10.0.0.5", "client_id": "", "qname": "a.example",
              "qtype": "A", "proto": "udp", "action": "forwarded", "reason": "",
              "rule": "", "source": "", "upstream": "", "rcode": "NOERROR",
              "answers": "[]", "elapsed_us": 1, "dnssec": ""}
    values.update(over)
    return [values[c] for c in _COLUMNS]


def test_one_object_per_row_with_answers_as_a_list(tmp_path):
    exp = export_to(tmp_path)
    exp.write([row(qname="example.com", answers='["93.184.216.34"]',
                   upstream="1.1.1.1:53", elapsed_us=900)])
    exp.close()
    (written,) = read(tmp_path / "q.jsonl")
    assert written["qname"] == "example.com"
    assert written["answers"] == ["93.184.216.34"]   # decoded, not a JSON string
    assert set(written) == set(_COLUMNS)


def test_appending_does_not_truncate(tmp_path):
    for _ in range(2):
        exp = export_to(tmp_path)
        exp.write([row()])
        exp.close()
    assert len(read(tmp_path / "q.jsonl")) == 2


def test_rotation_keeps_one_generation(tmp_path):
    exp = export_to(tmp_path, max_bytes=600)
    for _ in range(6):                              # ~180 bytes each: rotates once
        exp.write([row()])
    exp.write([row(qname="after-rotation.example")])
    exp.close()
    assert (tmp_path / "q.jsonl.1").exists()       # the previous generation
    assert [r["qname"] for r in read(tmp_path / "q.jsonl")] == ["after-rotation.example"]


def test_a_broken_export_disables_itself_and_never_stops_the_log(tmp_path):
    exp = JsonLinesExport(str(tmp_path / "nope" / "q.jsonl"), _COLUMNS)
    exp.path = "/proc/nonexistent/definitely-not-writable/q.jsonl"
    with pytest.raises(ExportDisabled):
        exp.write([row()])
    assert exp._fh is None


@pytest.mark.asyncio
async def test_querylog_writes_through_to_the_export(tmp_path):
    db = Database(tmp_path / "e.db")
    await db.connect()
    ql = QueryLog(db, export=export_to(tmp_path))
    ql.enqueue(mkrec(qname="exported.example"))
    await ql._flush()
    ql.export.close()
    names = [r["qname"] for r in read(tmp_path / "q.jsonl")]
    assert names == ["exported.example"]
    await db.close()


@pytest.mark.asyncio
async def test_a_failing_export_is_dropped_and_the_rows_still_land(tmp_path):
    class Boom:
        path = "boom"

        def write(self, rows):
            raise OSError("disk full")

        def close(self):
            pass

    db = Database(tmp_path / "f.db")
    await db.connect()
    ql = QueryLog(db, export=Boom())
    ql.enqueue(mkrec(qname="kept.example"))
    await ql._flush()
    assert ql.export is None                       # disabled after one failure
    assert await ql.count() == 1                   # and the row is in the table
    await db.close()
