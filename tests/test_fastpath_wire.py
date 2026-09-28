"""The fast path's wire helpers, and the conditions under which it stands down.

`ttl_offsets`, `edns_option` and `_skip_name` walk attacker-supplied bytes with
`unpack_from` rather than the parser, which is what makes replay cheap and what
makes getting them wrong dangerous. Everything here is a malformed or unusual
message they have to survive without reading past the buffer.
"""
from __future__ import annotations

import pytest

from trench.engine.fastpath import (
    FastPath,
    _skip_name,
    edns_option,
    query_key,
    ttl_offsets,
)
from trench.wire import RR, Class, Message, Question, Type
from trench.wire import rdata as R
from trench.wire.edns import Edns
from trench.wire.name import Name
from trench.wire.rrtypes import EDNSOption, Flags, Rcode


def n(s):
    return Name.from_text(s)


def mkquery(name="example.com", rtype=Type.A, edns=False, cookie=None):
    m = Message(id=0x1234)
    m.set_flag(Flags.RD, True)
    m.questions.append(Question(n(name), rtype, Class.IN))
    if edns or cookie is not None:
        m.edns = Edns(udp_size=1232)
        if cookie is not None:
            m.edns.set_option(EDNSOption.COOKIE, cookie)
    return m


def mkanswer(query, ttl=300, count=1, opt=False, cookie=None):
    resp = query.reply(Rcode.NOERROR)
    for i in range(count):
        resp.answers.append(RR(query.question.name, Type.A, Class.IN, ttl + i,
                               R.A(f"93.184.216.{i + 1}")))
    if opt or cookie is not None:
        resp.edns = Edns(udp_size=1232)
        if cookie is not None:
            resp.edns.set_option(EDNSOption.COOKIE, cookie)
    return resp


# --- _skip_name ---
def test_a_plain_name_is_skipped_to_its_terminator():
    blob = b"\x07example\x03com\x00rest"
    assert _skip_name(blob, 0) == 13


def test_the_root_name_is_one_byte():
    assert _skip_name(b"\x00rest", 0) == 1


def test_a_compression_pointer_is_two_bytes():
    assert _skip_name(b"\xc0\x0c", 0) == 2


def test_a_pointer_running_off_the_end_is_refused():
    assert _skip_name(b"\xc0", 0) == -1


def test_the_reserved_label_types_are_refused():
    """0b01 and 0b10 in the top bits are not defined; treating them as lengths
    is how a walker reads past its buffer."""
    assert _skip_name(b"\x40abc\x00", 0) == -1
    assert _skip_name(b"\x80abc\x00", 0) == -1


def test_a_name_with_no_terminator_is_refused():
    assert _skip_name(b"\x07example", 0) == -1
    assert _skip_name(b"", 0) == -1


# --- ttl_offsets ---
def test_the_offsets_point_at_every_ttl_field():
    q = mkquery()
    blob = mkanswer(q, ttl=300, count=3).to_wire()
    offs = ttl_offsets(blob)
    assert offs is not None and len(offs) == 3
    import struct
    assert [struct.unpack_from(">I", blob, o)[0] for o in offs] == [300, 301, 302]


def test_the_opt_pseudo_record_is_skipped():
    """The four octets in its TTL position are the extended rcode and flags;
    counting a clock down over them would corrupt the response."""
    q = mkquery(edns=True)
    blob = mkanswer(q, count=2, opt=True).to_wire()
    assert len(ttl_offsets(blob)) == 2


def test_a_message_with_no_records_has_no_offsets():
    assert ttl_offsets(mkquery().to_wire()) == ()


@pytest.mark.parametrize("blob", [b"", b"\x00" * 11])
def test_a_message_too_short_to_have_a_header_yields_nothing(blob):
    assert ttl_offsets(blob) is None
    assert edns_option(blob, int(EDNSOption.COOKIE)) is None


def test_a_truncated_question_is_refused():
    blob = mkanswer(mkquery()).to_wire()[:16]
    assert ttl_offsets(blob) is None


def test_a_truncated_record_is_refused():
    blob = mkanswer(mkquery()).to_wire()
    assert ttl_offsets(blob[:-4]) is None


def test_an_rdlength_running_past_the_end_is_refused():
    import struct
    blob = bytearray(mkanswer(mkquery()).to_wire())
    # The answer's RDLENGTH sits just before its rdata; make it implausible.
    struct.pack_into(">H", blob, len(blob) - 6, 60000)
    assert ttl_offsets(bytes(blob)) is None


def test_a_count_larger_than_the_message_is_refused():
    import struct
    blob = bytearray(mkanswer(mkquery()).to_wire())
    struct.pack_into(">H", blob, 6, 40)          # ANCOUNT says forty
    assert ttl_offsets(bytes(blob)) is None


# --- edns_option ---
def test_a_cookie_is_located_in_a_response():
    q = mkquery(cookie=b"clientcookie")
    blob = mkanswer(q, cookie=b"c" * 16).to_wire()
    found = edns_option(blob, int(EDNSOption.COOKIE))
    assert found is not None
    off, length = found
    assert length == 16 and blob[off:off + length] == b"c" * 16


def test_an_absent_option_is_reported_as_absent():
    blob = mkanswer(mkquery(edns=True), opt=True).to_wire()
    assert edns_option(blob, int(EDNSOption.COOKIE)) is None


def test_a_message_with_no_opt_has_no_options():
    assert edns_option(mkanswer(mkquery()).to_wire(),
                       int(EDNSOption.COOKIE)) is None


def test_an_option_that_is_not_the_first_is_still_found():
    q = mkquery()
    resp = mkanswer(q)
    resp.edns = Edns(udp_size=1232)
    resp.edns.set_option(EDNSOption.NSID, b"server-one")
    resp.edns.set_option(EDNSOption.COOKIE, b"k" * 16)
    found = edns_option(resp.to_wire(), int(EDNSOption.COOKIE))
    assert found is not None and found[1] == 16


def test_an_option_whose_length_overruns_the_opt_is_refused():
    import struct
    q = mkquery()
    resp = mkanswer(q, cookie=b"c" * 16)
    blob = bytearray(resp.to_wire())
    # Find the cookie and lie about its length.
    off, _ = edns_option(bytes(blob), int(EDNSOption.COOKIE))
    struct.pack_into(">H", blob, off - 2, 60000)
    assert edns_option(bytes(blob), int(EDNSOption.COOKIE)) is None


def test_a_malformed_name_stops_the_option_walk():
    blob = b"\x00\x01\x81\x80\x00\x01\x00\x00\x00\x00\x00\x01\x40bad"
    assert edns_option(blob, int(EDNSOption.COOKIE)) is None


def test_a_truncated_record_stops_the_option_walk():
    blob = b"\x00\x01\x81\x80\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00"
    assert edns_option(blob, int(EDNSOption.COOKIE)) is None


# --- query_key ---
def test_the_key_covers_the_question_and_nothing_after_it():
    a = query_key(mkquery("example.com").to_wire())
    b = query_key(mkquery("other.com").to_wire())
    assert a is not None and b is not None
    assert a[0] != b[0]


def test_the_key_is_case_insensitive_but_records_where_the_case_was():
    lower = query_key(mkquery("example.com").to_wire())
    upper = query_key(mkquery("EXAMPLE.COM").to_wire())
    assert lower[0] == upper[0], "the key must not depend on 0x20 casing"
    assert lower[1] == upper[1]


@pytest.mark.parametrize("blob", [b"", b"\x00" * 11, b"\x00" * 12])
def test_a_message_that_cannot_be_keyed_is_declined(blob):
    assert query_key(blob) is None


# --- standing down ---
def _pipeline(**over):
    from support import blocked_engine

    from trench.cache import Cache
    from trench.config import Config
    from trench.engine import Pipeline
    from trench.stats import Counters

    class Fwd:
        async def resolve(self, query, note=None):
            return mkanswer(query)

    return Pipeline(filter_engine=blocked_engine("doubleclick.net"), cache=Cache(),
                    forwarder=Fwd(), counters=Counters(),
                    config=Config.model_validate(over) if over else Config())


def test_a_disabled_recorder_serves_nothing():
    fast = FastPath(_pipeline())
    fast.enabled = False
    assert fast.usable is False


def test_a_disabled_pipeline_stands_the_recorder_down():
    pipe = _pipeline()
    fast = FastPath(pipe)
    assert fast.usable is True
    pipe.enabled = False
    assert fast.usable is False


def test_a_running_pause_stands_the_recorder_down():
    """Verdicts become a function of the clock: anything recorded now would
    outlive the pause, and anything recorded before it would be replayed
    through it."""
    pipe = _pipeline()
    fast = FastPath(pipe)
    pipe.pause(60)
    assert fast.usable is False
    pipe.resume()
    assert fast.usable is True


def test_an_active_plugin_stands_the_recorder_down():
    """A plugin may rewrite anything."""
    pipe = _pipeline()
    fast = FastPath(pipe)

    class Plugins:
        active = True

    pipe.plugins = Plugins()
    assert fast.usable is False


def test_a_client_scoped_rule_stands_the_recorder_down():
    """`$client` is matched on the address, which is not in the key — so
    whichever client asked first would have its verdict replayed to the
    other."""
    from trench.filter import FilterEngine, iter_rules
    pipe = _pipeline()
    fast = FastPath(pipe)
    assert fast.usable is True
    pipe.filter = FilterEngine.compile(
        iter_rules("||ads.example.com^$client=10.0.0.5", "list"))
    assert fast.usable is False


def test_the_table_is_bounded():
    fast = FastPath(_pipeline(), max_entries=4)
    assert fast.max_entries == 4
    assert fast.size == 0
    assert fast.clear() == 0
