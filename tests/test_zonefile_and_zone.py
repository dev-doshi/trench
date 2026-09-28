"""Zone-file parsing and the authoritative answer machine.

The zone answers queries directly from a file an operator hand-wrote, so both
halves need to be right about the awkward cases: relative names, `@`, inherited
owners, multi-line SOAs, wildcards several labels up, delegations, CNAME chains
and the loops a hand-edited file can contain.
"""
from __future__ import annotations

import pytest

from trench.auth_zone import Zone, ZoneStore
from trench.auth_zone.zonefile import _logical_lines, _qualify, _rdata, _ttl, parse_zonefile
from trench.errors import ConfigError
from trench.wire import Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Flags, Rcode

ORIGIN = "example.com."


def n(s):
    return Name.from_text(s)


def query(name, rtype=Type.A, do=False):
    m = Message(id=1)
    m.set_flag(Flags.RD, True)
    m.questions.append(Question(n(name), rtype, Class.IN))
    if do:
        from trench.wire.edns import Edns
        m.edns = Edns()
        m.edns.do = True
    return m


def ask(zone, name, rtype=Type.A, do=False):
    """What the zone answers for one question."""
    return zone.lookup(n(name), int(rtype), do=do)


def _with_soa(origin):
    z = Zone(n(origin))
    z.add(n(origin), int(Type.SOA),
          R.SOA(n(f"ns.{origin}"), n(f"hm.{origin}"), 1, 7200, 3600, 1209600, 3600))
    return z


# --- helpers ---
@pytest.mark.parametrize("text,seconds", [
    ("300", 300), ("5m", 300), ("2h", 7200), ("1d", 86400), ("1w", 604800),
    ("1H", 3600),
])
def test_ttl_units(text, seconds):
    assert _ttl(text) == seconds


def test_a_relative_name_is_qualified_and_an_absolute_one_is_not():
    assert _qualify("www", n(ORIGIN)) == n("www.example.com.")
    assert _qualify("elsewhere.test.", n(ORIGIN)) == n("elsewhere.test.")
    assert _qualify("@", n(ORIGIN)) == n(ORIGIN)


def test_parenthesised_records_are_joined_into_one_logical_line():
    text = ("@ IN SOA ns hostmaster (\n"
            "    1  ; serial\n"
            "    7200 3600 1209600 3600 )\n"
            "www IN A 192.0.2.1\n")
    lines = [x for x in _logical_lines(text) if x]
    assert len(lines) == 2
    assert "SOA" in lines[0] and "1209600" in lines[0]
    assert lines[1].startswith("www")


def test_comments_are_stripped_before_counting_parentheses():
    text = "@ IN TXT \"a ; not a comment\"  ; ( unbalanced in a comment\n"
    assert [x for x in _logical_lines(text) if x]


# --- _rdata ---
@pytest.mark.parametrize("rtype,toks,check", [
    ("A", ["192.0.2.1"], lambda rd: rd.address == "192.0.2.1"),
    ("AAAA", ["2001:db8::1"], lambda rd: rd.address == "2001:db8::1"),
    ("NS", ["ns"], lambda rd: rd.name == Name.from_text("ns.example.com.")),
    ("PTR", ["host."], lambda rd: rd.name == Name.from_text("host.")),
    ("CNAME", ["real"], lambda rd: rd.name == Name.from_text("real.example.com.")),
    ("DNAME", ["other."], lambda rd: rd.name == Name.from_text("other.")),
    ("MX", ["10", "mail"], lambda rd: rd.preference == 10),
    ("SRV", ["1", "5", "443", "svc"], lambda rd: rd.port == 443),
    ("TXT", ['"v=spf1', '-all"'], lambda rd: rd.strings == [b"v=spf1 -all"]),
    ("CAA", ["0", "issue", '"letsencrypt.org"'],
     lambda rd: rd.value == b"letsencrypt.org"),
])
def test_every_supported_record_type_parses(rtype, toks, check):
    rd = _rdata(rtype, toks, n(ORIGIN))
    assert rd is not None and check(rd)


def test_an_soa_parses_all_five_numbers():
    rd = _rdata("SOA", ["ns", "hostmaster", "7", "7200", "3600", "1209600", "3600"],
                n(ORIGIN))
    assert rd.serial == 7 and rd.refresh == 7200 and rd.minimum == 3600


@pytest.mark.parametrize("rtype,toks", [
    ("A", []),                       # nothing to parse
    ("MX", ["notanumber", "mail"]),  # a preference that is not a number
    ("SRV", ["1", "5"]),             # too few fields
    ("SOA", ["ns", "hostmaster"]),   # missing the numbers entirely
    ("SOA", ["ns", "hostmaster", "1", "2"]),   # only some of the five
    ("HINFO", ["a", "b"]),           # a type the zone-file reader does not build
])
def test_an_unparseable_record_is_dropped_rather_than_raising(rtype, toks):
    assert _rdata(rtype, toks, n(ORIGIN)) is None


# --- parse_zonefile ---
ZONE = """\
$ORIGIN example.com.
$TTL 3600
@       IN SOA  ns hostmaster ( 1 7200 3600 1209600 3600 )
@       IN NS   ns
ns      IN A    192.0.2.1
www  60 IN A    192.0.2.2
        IN AAAA 2001:db8::2
alias   IN CNAME www
mail    IN MX   10 mail
txt     IN TXT  "hello world"
sub     IN NS   ns.sub
ns.sub  IN A    192.0.2.9
*.wild  IN A    192.0.2.50
"""


@pytest.fixture
def zone():
    return parse_zonefile(ZONE, ORIGIN)


def test_the_apex_and_its_soa_are_read(zone):
    assert zone.origin == n(ORIGIN)
    assert zone.soa is not None and zone.soa.serial == 1


def test_a_relative_owner_is_qualified(zone):
    assert n("www.example.com.") in zone.records


def test_an_explicit_ttl_overrides_the_default(zone):
    assert zone.ttl_of(n("www.example.com."), Type.A) == 60
    assert zone.ttl_of(n("ns.example.com."), Type.A) == 3600


def test_a_blank_owner_inherits_the_previous_one(zone):
    """Regression: leading whitespace *is* the syntax for "same owner as the
    line above", and joining logical lines used to strip it — so
    `        IN AAAA ...` landed at `IN.example.com.` instead of at `www`."""
    assert Type.AAAA in zone.records[n("www.example.com.")]
    assert n("IN.example.com.") not in zone.records


def test_a_continuation_inherits_through_a_multi_line_record():
    z = parse_zonefile(
        "$ORIGIN example.com.\n"
        "@   IN SOA ns hm (\n"
        "        1 7200 3600 1209600 3600 )\n"
        "www IN A    192.0.2.2\n"
        "    IN TXT  \"second\"\n", ORIGIN)
    assert Type.TXT in z.records[n("www.example.com.")]


def test_a_tab_indented_continuation_also_inherits():
    z = parse_zonefile("@ IN SOA ns hm ( 1 1 1 1 1 )\n"
                       "www IN A 192.0.2.2\n"
                       "\tIN AAAA 2001:db8::2\n", ORIGIN)
    assert Type.AAAA in z.records[n("www.example.com.")]


def test_a_zone_without_an_origin_directive_uses_the_argument():
    z = parse_zonefile("@ IN SOA ns hostmaster ( 1 1 1 1 1 )\n", ORIGIN)
    assert z.origin == n(ORIGIN)


def test_comments_and_blank_lines_are_skipped():
    z = parse_zonefile("; a comment\n\n@ IN SOA ns hm ( 1 1 1 1 1 )\n", ORIGIN)
    assert z.soa is not None


def test_a_line_with_nothing_after_the_class_is_skipped():
    z = parse_zonefile("@ IN SOA ns hm ( 1 1 1 1 1 )\nwww IN\n", ORIGIN)
    assert n("www.example.com.") not in z.records


def test_an_absolute_owner_is_taken_as_written():
    z = parse_zonefile("@ IN SOA ns hm ( 1 1 1 1 1 )\n"
                       "other.test. IN A 192.0.2.1\n", ORIGIN)
    assert n("other.test.") in z.records


# --- answering ---
def test_an_exact_match_is_authoritative(zone):
    ans = ask(zone, "www.example.com")
    assert ans is not None and ans.rcode == Rcode.NOERROR
    assert ans.aa is True
    assert [rr.rdata.address for rr in ans.answers] == ["192.0.2.2"]


def test_a_missing_type_at_an_existing_name_is_nodata(zone):
    ans = ask(zone, "www.example.com", Type.MX)
    assert ans.rcode == Rcode.NOERROR and ans.answers == []
    assert any(rr.rtype == Type.SOA for rr in ans.authority)


def test_a_missing_name_is_nxdomain(zone):
    ans = ask(zone, "nope.example.com")
    assert ans.rcode == Rcode.NXDOMAIN
    assert any(rr.rtype == Type.SOA for rr in ans.authority)


def test_a_name_outside_the_zone_is_not_ours(zone):
    store = ZoneStore()
    store.add(zone)
    assert store.resolve(query("elsewhere.test")) is None


def test_a_cname_is_followed_inside_the_zone(zone):
    ans = ask(zone, "alias.example.com")
    types = [rr.rtype for rr in ans.answers]
    assert Type.CNAME in types and Type.A in types


def test_a_cname_loop_terminates(zone):
    """A hand-edited file — or an inbound AXFR — turned this into a
    RecursionError, so a query flood became a CPU denial of service."""
    z = parse_zonefile("@ IN SOA ns hm ( 1 1 1 1 1 )\n"
                       "a IN CNAME b\n"
                       "b IN CNAME a\n", ORIGIN)
    ans = ask(z, "a.example.com")
    assert ans is not None
    assert len(ans.answers) <= z.MAX_CNAME_CHAIN


def test_a_cname_pointing_out_of_the_zone_stops_there(zone):
    z = parse_zonefile("@ IN SOA ns hm ( 1 1 1 1 1 )\n"
                       "a IN CNAME elsewhere.test.\n", ORIGIN)
    ans = ask(z, "a.example.com")
    assert [rr.rtype for rr in ans.answers] == [Type.CNAME]


def test_a_cname_to_a_name_that_does_not_exist_stops_there(zone):
    z = parse_zonefile("@ IN SOA ns hm ( 1 1 1 1 1 )\n"
                       "a IN CNAME missing\n", ORIGIN)
    assert [rr.rtype for rr in ask(z, "a.example.com").answers] == [Type.CNAME]


def test_a_delegation_is_referred_with_its_glue(zone):
    ans = ask(zone, "host.sub.example.com")
    assert ans is not None and ans.aa is False
    assert [rr.rtype for rr in ans.authority] == [Type.NS]
    assert [rr.rdata.address for rr in ans.additional] == ["192.0.2.9"]


def test_an_out_of_zone_nameserver_needs_no_glue():
    z = parse_zonefile("@ IN SOA ns hm ( 1 1 1 1 1 )\n"
                       "sub IN NS ns.elsewhere.test.\n", ORIGIN)
    ans = ask(z, "host.sub.example.com")
    assert ans.additional == []


def test_a_ds_query_is_answered_by_the_parent_not_referred():
    z = parse_zonefile("@ IN SOA ns hm ( 1 1 1 1 1 )\nsub IN NS ns.sub\n", ORIGIN)
    z.add(n("sub.example.com."), int(Type.DS), R.DS(1, 13, 2, b"\x00" * 32))
    ans = ask(z, "sub.example.com", Type.DS)
    assert ans.aa is True
    assert [rr.rtype for rr in ans.answers] == [Type.DS]


def test_a_signed_delegation_carries_its_ds_in_the_referral():
    z = parse_zonefile("@ IN SOA ns hm ( 1 1 1 1 1 )\n"
                       "sub IN NS ns.sub\nns.sub IN A 192.0.2.9\n", ORIGIN)
    z.add(n("sub.example.com."), int(Type.DS), R.DS(1, 13, 2, b"\x00" * 32))
    ans = ask(z, "host.sub.example.com")
    assert {rr.rtype for rr in ans.authority} == {Type.NS, Type.DS}


def test_a_wildcard_answers_a_name_it_covers(zone):
    ans = ask(zone, "anything.wild.example.com")
    assert [rr.rdata.address for rr in ans.answers] == ["192.0.2.50"]


def test_a_wildcard_covers_names_several_labels_deep(zone):
    """Trying only the parent meant `*.example.com` answered `x.example.com`
    and returned NXDOMAIN for `deep.sub.example.com`."""
    ans = ask(zone, "deep.sub.wild.example.com")
    assert [rr.rdata.address for rr in ans.answers] == ["192.0.2.50"]


def test_a_wildcard_does_not_reach_past_a_delegation():
    z = parse_zonefile("@ IN SOA ns hm ( 1 1 1 1 1 )\n"
                       "*  IN A 192.0.2.50\n"
                       "sub IN NS ns.sub\nns.sub IN A 192.0.2.9\n", ORIGIN)
    ans = ask(z, "host.sub.example.com")
    assert ans.aa is False and ans.answers == []


def test_the_apex_itself_is_never_wildcard_synthesized(zone):
    ans = ask(zone, "example.com", Type.MX)
    assert ans.answers == []


def test_a_query_with_no_question_is_not_ours(zone):
    store = ZoneStore()
    store.add(zone)
    assert store.resolve(Message(id=1)) is None


# --- the store ---
def test_the_store_finds_the_most_specific_zone():
    store = ZoneStore()
    outer = _with_soa("example.com.")
    inner = _with_soa("sub.example.com.")
    store.add(outer)
    store.add(inner)
    assert store.authoritative_for(n("x.sub.example.com.")) is inner
    assert store.authoritative_for(n("x.example.com.")) is outer
    assert store.authoritative_for(n("elsewhere.test.")) is None


def test_an_empty_store_reports_itself_empty():
    store = ZoneStore()
    assert store.empty is True
    store.add(Zone(n("example.com.")))
    assert store.empty is False


def test_replacing_a_zone_swaps_it_in_place():
    store = ZoneStore()
    first = _with_soa("example.com.")
    store.add(first)
    second = _with_soa("example.com.")
    store.replace(second)
    assert store.authoritative_for(n("x.example.com.")) is second


def test_the_store_answers_through_the_zone_it_picks():
    store = ZoneStore()
    store.add(parse_zonefile(ZONE, ORIGIN))
    resp = store.resolve(query("www.example.com"))
    assert resp is not None
    assert resp.rcode == Rcode.NOERROR
    assert resp.aa is True
    assert resp.answers[0].rdata.address == "192.0.2.2"


def test_the_store_declines_a_name_it_does_not_serve():
    store = ZoneStore()
    store.add(parse_zonefile(ZONE, ORIGIN))
    assert store.resolve(query("elsewhere.test")) is None


def test_a_directive_with_no_argument_names_the_file_and_the_line():
    """`_rdata` already declines to take the daemon down over one bad record,
    and the point of that fix was a traceback that named nothing. A `$ORIGIN`
    with no argument still raised IndexError out of `line.split()[1]`, from a
    `read_text()` in `App`, naming neither the zone nor the line."""
    with pytest.raises(ConfigError) as excinfo:
        parse_zonefile("$ORIGIN\nwww IN A 1.2.3.4\n", "example.com.")
    assert "example.com." in str(excinfo.value)
    assert "line 1" in str(excinfo.value)


def test_a_directive_that_starts_a_word_is_not_mistaken_for_one():
    """`startswith` needs no space after it, so `$ORIGIN]example.com.` is one
    token — a typo that reached `split()[1]` with nothing there."""
    with pytest.raises(ConfigError):
        parse_zonefile("$ORIGIN]example.com.\n", "example.com.")


def test_an_unparseable_ttl_is_reported_rather_than_raised_bare():
    with pytest.raises(ConfigError) as excinfo:
        parse_zonefile("$TTL 1x\n@ IN NS ns.example.com.\n", "example.com.")
    assert "$TTL" in str(excinfo.value)


def test_a_good_directive_still_does_what_it_says():
    zone = parse_zonefile("$ORIGIN sub.example.com.\n$TTL 60\nwww IN A 1.2.3.4\n",
                          "example.com.")
    owner = Name.from_text("www.sub.example.com.")
    assert zone.records[owner][Type.A][0].address == "1.2.3.4"
    assert zone.ttl_of(owner, Type.A) == 60
