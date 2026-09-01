"""Per-group filtering: layering, precedence, refresh follow-through."""
from __future__ import annotations

import asyncio

from trench.cache import Cache
from trench.clients import Client, ClientRegistry, Policy
from trench.config import Config
from trench.engine import Pipeline
from trench.filter import Action, FilterEngine
from trench.filter.groups import LayeredFilter
from trench.filter.parser import parse_line
from trench.stats import Counters
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Rcode


def eng(*lines: str) -> FilterEngine:
    return FilterEngine.compile([parse_line(ln, "list") for ln in lines])


# --- layering ---
def test_group_rules_are_checked_before_the_default_ones():
    base = eng("||ads.example^")
    group = LayeredFilter("kids", eng("||social.example^"), lambda: base)
    assert group.match("social.example").action == Action.BLOCK   # group's own
    assert group.match("ads.example").action == Action.BLOCK      # inherited
    assert group.match("news.example").action == Action.NONE


def test_a_group_allow_rule_beats_an_inherited_block():
    """"the kids' tablet may reach this one site" has to be expressible."""
    base = eng("||games.example^")
    group = LayeredFilter("kids", eng("@@||games.example^"), lambda: base)
    assert group.match("games.example").action == Action.ALLOW


def test_a_group_can_opt_out_of_the_default_rules():
    base = eng("||ads.example^")
    group = LayeredFilter("guest", eng("||malware.example^"), lambda: base,
                          inherit=False)
    assert group.match("malware.example").action == Action.BLOCK
    assert group.match("ads.example").action == Action.NONE


def test_a_refresh_of_the_default_rules_moves_the_group_with_it():
    """A group holding a reference would filter against last week's rules."""
    current = {"engine": eng()}
    group = LayeredFilter("kids", eng(), lambda: current["engine"])
    assert group.match("ads.example").action == Action.NONE
    current["engine"] = eng("||ads.example^")
    assert group.match("ads.example").action == Action.BLOCK


def test_address_lists_stay_shared_and_client_rules_are_reported_from_both():
    base = eng("||x.example^")
    base.ips.add("203.0.113.0/24", "feed")
    group = LayeredFilter("kids", eng("||y.example^$client=10.0.0.5"), lambda: base)
    assert group.ips.match("203.0.113.9") == "feed"
    assert group.has_client_rules


# --- pipeline ---
class Fwd:
    async def resolve(self, query: Message, note=None) -> Message:
        resp = query.reply(Rcode.NOERROR)
        resp.answers.append(RR(query.question.name, Type.A, Class.IN, 60, R.A("1.2.3.4")))
        return resp


def mkquery(name: str) -> Message:
    m = Message(id=1)
    m.set_flag(0x0100, True)
    m.questions.append(Question(Name.from_text(name), Type.A, Class.IN))
    return m


def build() -> Pipeline:
    reg = ClientRegistry([
        Client("10.0.0.5", "ip", "kid", Policy(name="kid", group="kids")),
        Client("10.0.0.6", "ip", "guest", Policy(name="guest", group="guest")),
    ], default=Policy(name="default"))
    pipe = Pipeline(filter_engine=eng("||ads.example^"), cache=Cache(enabled=False),
                    forwarder=Fwd(), counters=Counters(), config=Config(), clients=reg)
    pipe.set_group_filters({
        "kids": (eng("||social.example^"), True),
        "guest": (eng(), False),
    })
    return pipe


def answer(pipe: Pipeline, client: str, name: str) -> str:
    return asyncio.run(pipe.resolve(mkquery(name), client)).answers[0].rdata.to_text()


def test_clients_resolve_under_their_own_group():
    pipe = build()
    assert answer(pipe, "10.0.0.5", "social.example") == "0.0.0.0"   # group rule
    assert answer(pipe, "10.0.0.5", "ads.example") == "0.0.0.0"      # inherited
    assert answer(pipe, "9.9.9.9", "social.example") == "1.2.3.4"    # not in the group
    assert answer(pipe, "10.0.0.6", "ads.example") == "1.2.3.4"      # opted out


def test_an_uncompiled_group_falls_back_to_the_household_rules():
    """Reached only when a group's own sources failed to fetch: the default
    rules are a better answer than no rules."""
    pipe = build()
    pipe.group_filters.pop("kids")
    assert answer(pipe, "10.0.0.5", "ads.example") == "0.0.0.0"


def test_config_ties_clients_to_declared_groups_only():
    import pytest

    from trench.errors import ConfigError
    cfg = Config.load_dict({
        "filtering": {"groups": {"kids": {"deny": ["social.example"]}}},
        "clients": [{"ident": "10.0.0.5", "group": "kids"}],
    })
    assert ClientRegistry.from_config(cfg).identify("10.0.0.5").group == "kids"
    with pytest.raises(ConfigError):
        Config.load_dict({"clients": [{"ident": "10.0.0.5", "group": "ghost"}]})


def test_gravity_compiles_group_sources(tmp_path):
    from trench.filter.groups import GroupSpec
    from trench.gravity import Gravity

    (tmp_path / "house.txt").write_text("||ads.example^\n")
    (tmp_path / "kids.txt").write_text("||social.example^\n")
    grav = Gravity([str(tmp_path / "house.txt")],
                   groups=[GroupSpec("kids", [str(tmp_path / "kids.txt")], [], [])])
    base = asyncio.run(grav.build())
    assert base.match("ads.example").action == Action.BLOCK
    engine, inherit = grav.group_engines["kids"]
    assert inherit is True
    assert engine.match("social.example").action == Action.BLOCK
    assert engine.match("ads.example").action == Action.NONE      # not duplicated


def test_a_group_whose_sources_fail_is_left_empty_not_half_loaded(tmp_path):
    from trench.filter.groups import GroupSpec
    from trench.gravity import Gravity

    (tmp_path / "house.txt").write_text("||ads.example^\n")
    grav = Gravity([str(tmp_path / "house.txt")],
                   groups=[GroupSpec("kids", [str(tmp_path / "missing.txt")], [], [])])
    asyncio.run(grav.build())
    assert "kids" not in grav.group_engines
    assert any("kids:" in e for e in grav.report.errors)


def test_replay_stands_down_when_a_group_carries_client_rules():
    """A `$client` rule is matched on the address, and a cidr client maps a whole
    range onto one Policy — so one policy tag covers every address in it, and a
    verdict for one would be replayed to the rest."""
    from trench.engine.fastpath import FastPath

    pipe = build()
    pipe.fast = FastPath(pipe)
    assert pipe.fast.usable
    pipe.set_group_filters({"kids": (eng("||social.example^$client=10.0.0.5"), True)})
    assert not pipe.fast.usable
