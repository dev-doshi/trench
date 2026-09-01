"""Saving the cache across a restart, and restoring it."""
from __future__ import annotations

from trench.cache import Cache
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Rcode


def _answer(name="example.com", ip="1.2.3.4", ttl=300):
    q = Message(id=1)
    q.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    resp = q.reply(Rcode.NOERROR)
    resp.answers.append(RR(q.question.name, Type.A, Class.IN, ttl, R.A(ip)))
    return q, resp


def test_cache_persistence_roundtrip(tmp_path):
    c = Cache()
    for i in range(5):
        q, resp = _answer(f"site{i}.com", f"10.0.0.{i}")
        c.put(c.key_for(q), resp)
    path = tmp_path / "cache.json"
    assert c.dump(path) == 5
    # fresh cache restores them
    c2 = Cache()
    assert c2.load(path) == 5
    q, _ = _answer("site3.com")
    hit = c2.get(c2.key_for(q))
    assert hit is not None and hit[0].answers[0].rdata.to_text() == "10.0.0.3"


def test_cache_load_missing_file(tmp_path):
    assert Cache().load(tmp_path / "nope.json") == 0
