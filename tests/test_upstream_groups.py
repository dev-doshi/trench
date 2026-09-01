"""Per-client upstream groups: routing, cache isolation, config refusal."""
from __future__ import annotations

import asyncio

import pytest

from trench.cache import Cache
from trench.clients import Client, ClientRegistry, Policy
from trench.config import Config
from trench.engine import Pipeline
from trench.errors import ConfigError
from trench.filter import FilterEngine
from trench.stats import Counters
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Rcode


class Fixed:
    """A forwarder that always answers with one address, so which server
    answered is visible in the response itself."""

    def __init__(self, addr: str):
        self.addr = addr
        self.calls = 0

    async def resolve(self, query: Message, note=None) -> Message:
        self.calls += 1
        resp = query.reply(Rcode.NOERROR)
        resp.answers.append(RR(query.question.name, Type.A, Class.IN, 60, R.A(self.addr)))
        if note is not None:
            note(self.addr)
        return resp


def mkquery(name: str) -> Message:
    m = Message(id=1)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    return m


def build(default: Fixed, groups: dict) -> Pipeline:
    reg = ClientRegistry([
        Client("10.0.0.5", "ip", "kid", Policy(name="kid", upstream_group="family")),
        Client("10.0.0.6", "ip", "work", Policy(name="work", upstream_group="office")),
        Client("10.0.0.7", "ip", "typo", Policy(name="typo", upstream_group="missing")),
    ], default=Policy(name="default"))
    return Pipeline(filter_engine=FilterEngine.compile([]), cache=Cache(),
                    forwarder=default, forwarders=groups, counters=Counters(),
                    config=Config(), clients=reg)


def answer_for(pipe: Pipeline, client: str, name: str = "example.com") -> str:
    resp = asyncio.run(pipe.resolve(mkquery(name), client))
    return resp.answers[0].rdata.to_text()


def test_client_group_selects_its_own_upstream():
    default, family, office = Fixed("1.1.1.1"), Fixed("2.2.2.2"), Fixed("3.3.3.3")
    pipe = build(default, {"family": family, "office": office})
    assert answer_for(pipe, "10.0.0.5") == "2.2.2.2"   # kid -> family
    assert answer_for(pipe, "10.0.0.6") == "3.3.3.3"   # work -> office
    assert answer_for(pipe, "9.9.9.9") == "1.1.1.1"    # unconfigured -> default


def test_group_answers_are_not_shared_through_the_cache():
    """The whole point of a group is a different answer for the same name."""
    default, family = Fixed("1.1.1.1"), Fixed("2.2.2.2")
    pipe = build(default, {"family": family})
    assert answer_for(pipe, "9.9.9.9") == "1.1.1.1"    # fills the default entry
    assert answer_for(pipe, "10.0.0.5") == "2.2.2.2"   # must not read it
    assert family.calls == 1
    # and each group still caches for itself
    assert answer_for(pipe, "10.0.0.5") == "2.2.2.2"
    assert family.calls == 1


def test_unknown_group_falls_back_but_config_refuses_it():
    default = Fixed("1.1.1.1")
    pipe = build(default, {"family": Fixed("2.2.2.2")})
    assert answer_for(pipe, "10.0.0.7") == "1.1.1.1"   # runtime cannot refuse service
    with pytest.raises(ConfigError):                    # startup can, and does
        Config.load_dict({"clients": [{"ident": "10.0.0.7", "upstream_group": "missing"}]})


def test_group_config_accepts_a_declared_group():
    cfg = Config.load_dict({
        "upstream": {"groups": {"family": ["1.1.1.3:53"]}},
        "clients": [{"ident": "10.0.0.5", "upstream_group": "family"}],
    })
    assert cfg.upstream.groups["family"] == ["1.1.1.3:53"]
