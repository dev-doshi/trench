"""Adversarial + operational tests for the iterative resolver.

A recursive resolver is the one component that takes instructions from servers
it does not trust: every referral is a stranger telling us where to ask next.
The tests here are written from that point of view. Each one is an authority
tree containing a server that lies, stalls, or is simply broken, and asserts
that the resolver's answer is still correct and that it stopped asking.

The mock transport records every (server, qname, qtype) so the tests can assert
on *traffic*, not only on the final message: a resolver that gets the right
answer after 400 queries to the root is not correct.
"""
from __future__ import annotations

import pytest

from trench.resolver.recursive import Recursive, _Peer
from trench.wire import RR, Class, Message, Type
from trench.wire import rdata as R
from trench.wire.name import Name
from trench.wire.rrtypes import Flags, Rcode

ROOT, COM, AUTH, EVIL, NET = "10.0.0.1", "10.0.0.2", "10.0.0.3", "6.6.6.6", "10.0.0.4"


def n(s: str) -> Name:
    return Name.from_text(s)


def referral(zone: str, ns: str, glue: str | None = None) -> Message:
    m = Message(id=0, flags=Flags.QR)
    m.authority.append(RR(n(zone), Type.NS, Class.IN, 172800, R.NS(n(ns))))
    if glue is not None:
        m.additional.append(RR(n(ns), Type.A, Class.IN, 172800, R.A(glue)))
    return m


def answer(name: str, ip: str, *, aa: bool = True) -> Message:
    m = Message(id=0, flags=Flags.QR | (Flags.AA if aa else 0))
    m.answers.append(RR(n(name), Type.A, Class.IN, 300, R.A(ip)))
    return m


def nodata(aa: bool = True) -> Message:
    return Message(id=0, flags=Flags.QR | (Flags.AA if aa else 0))


def rcode(code: int) -> Message:
    m = Message(id=0, flags=Flags.QR)
    m.set_rcode(code)
    return m


class Tree:
    """A mock authority tree. `handlers` maps server ip -> callable(name, rtype)."""

    def __init__(self, handlers):
        self.handlers = handlers
        self.log: list[tuple[str, str, int]] = []

    async def __call__(self, ip: str, query: Message) -> Message:
        q = query.question
        name = q.name.to_text().rstrip(".").lower()
        self.log.append((ip, name, int(q.rtype)))
        h = self.handlers.get(ip)
        if h is None:
            raise ConnectionError(f"no server at {ip}")
        return h(name, int(q.rtype))

    def asked(self, ip: str) -> int:
        return sum(1 for s, _, _ in self.log if s == ip)


def ips(resp: Message) -> list[str]:
    return [rr.rdata.to_text() for rr in resp.answers if rr.rtype == Type.A]


def try_last(rec: Recursive, ip: str) -> None:
    """Make `ip` the resolver's least-preferred server.

    Nameserver order is deliberately randomised, so a failover test that just
    lists a broken server first proves nothing — half the time the good one is
    picked and the test passes without exercising anything. Seeding the latency
    estimate puts the *good* server last, so the broken one is always tried.
    """
    rec._peers[ip] = _Peer(rtt=9.0)


def two_nameservers(bad: str, good: str) -> Message:
    m = referral("com", "ns1.com", bad)
    m.authority.append(RR(n("com"), Type.NS, Class.IN, 172800, R.NS(n("ns2.com"))))
    m.additional.append(RR(n("ns2.com"), Type.A, Class.IN, 172800, R.A(good)))
    return m


# --------------------------------------------------------------- bailiwick
@pytest.mark.asyncio
async def test_upward_referral_is_refused():
    """An authority for example.com must not be able to hand us the whole TLD.

    This is the classic delegation-poisoning move: the server we are talking to
    answers a question about its own zone with a referral for a zone *above* it,
    pointing at nameservers it controls. A resolver that follows it has just
    accepted a stranger as the authority for com.
    """
    def root(name, rtype):
        return referral("com", "ns.com", COM)

    def com(name, rtype):
        return referral("example.com", "ns.example.com", AUTH)

    def hostile(name, rtype):
        # asked about its own zone; answers by claiming com belongs to evil
        return referral("com", "ns.evil.net", EVIL)

    def evil(name, rtype):
        return answer("www.example.com", EVIL)

    t = Tree({ROOT: root, COM: com, AUTH: hostile, EVIL: evil})
    rec = Recursive(t, root_hints=[ROOT], qmin=False)
    resp = await rec.resolve("www.example.com", Type.A)

    assert EVIL not in ips(resp), "followed an upward referral into a hostile zone"
    assert t.asked(EVIL) == 0, "queried a server named by an out-of-bailiwick referral"
    assert resp.rcode == Rcode.SERVFAIL


@pytest.mark.asyncio
async def test_sideways_referral_is_refused():
    """A referral must also be *toward* the name being resolved."""
    def root(name, rtype):
        return referral("com", "ns.com", COM)

    def com(name, rtype):
        return referral("example.com", "ns.example.com", AUTH)

    def hostile(name, rtype):
        return referral("bank.com", "ns.bank.com", EVIL)

    t = Tree({ROOT: root, COM: com, AUTH: hostile, EVIL: lambda *a: answer("www.example.com", EVIL)})
    rec = Recursive(t, root_hints=[ROOT], qmin=False)
    resp = await rec.resolve("www.example.com", Type.A)
    assert t.asked(EVIL) == 0
    assert EVIL not in ips(resp)


@pytest.mark.asyncio
async def test_out_of_bailiwick_glue_is_not_used():
    """Glue is only believable inside the zone that served it.

    com may state addresses for ns.example.com — it is delegating that zone. It
    may not state an address for ns.evil.net; that record belongs to net. A
    resolver that uses it lets any TLD server redirect any nameserver anywhere.
    """
    def root(name, rtype):
        if name.endswith("net") or name == "ns.evil.net":
            return referral("net", "ns.net", NET)
        return referral("com", "ns.com", COM)

    def com(name, rtype):
        return referral("example.com", "ns.evil.net", EVIL)   # glue is a lie

    def net(name, rtype):
        if name == "ns.evil.net" and rtype == Type.A:
            return answer("ns.evil.net", AUTH)                # the truth
        return nodata()

    def auth(name, rtype):
        return answer("www.example.com", "93.184.216.34")

    t = Tree({ROOT: root, COM: com, NET: net, AUTH: auth, EVIL: lambda *a: answer("www.example.com", EVIL)})
    rec = Recursive(t, root_hints=[ROOT], qmin=False)
    resp = await rec.resolve("www.example.com", Type.A)

    assert t.asked(EVIL) == 0, "believed glue the serving zone had no authority over"
    assert ips(resp) == ["93.184.216.34"]


@pytest.mark.asyncio
async def test_additional_records_are_only_glue_for_the_delegated_servers():
    """An address in the additional section is not an invitation to query it.

    The parent may state addresses for the nameservers it is delegating to.
    Every other address record it attaches — however legitimately it owns the
    name — is unrelated to this delegation, and treating it as somewhere to
    send the next query hands the parent a way to steer traffic at will.
    """
    def root(name, rtype):
        return referral("com", "ns.com", COM)

    def com(name, rtype):
        m = referral("example.com", "ns.example.com", None)   # no glue for the real NS
        m.additional.append(RR(n("decoy.com"), Type.A, Class.IN, 300, R.A(EVIL)))
        return m

    t = Tree({ROOT: root, COM: com, EVIL: lambda *a: answer("www.example.com", EVIL)})
    rec = Recursive(t, root_hints=[ROOT], qmin=False)
    resp = await rec.resolve("www.example.com", Type.A)
    assert t.asked(EVIL) == 0, "used an unrelated additional-section address as a nameserver"
    assert EVIL not in ips(resp)


@pytest.mark.asyncio
async def test_answer_section_is_restricted_to_the_zone():
    """An authority may only answer for names it is authoritative over."""
    def root(name, rtype):
        return referral("com", "ns.com", COM)

    def com(name, rtype):
        return referral("example.com", "ns.example.com", AUTH)

    def auth(name, rtype):
        m = answer("www.example.com", "93.184.216.34")
        m.answers.append(RR(n("www.bank.com"), Type.A, Class.IN, 300, R.A(EVIL)))
        return m

    t = Tree({ROOT: root, COM: com, AUTH: auth})
    rec = Recursive(t, root_hints=[ROOT], qmin=False)
    resp = await rec.resolve("www.example.com", Type.A)
    names = {rr.name.to_text() for rr in resp.answers}
    assert "www.bank.com." not in names, "kept a record smuggled into the answer section"
    assert ips(resp) == ["93.184.216.34"]


@pytest.mark.asyncio
async def test_unasked_records_from_the_same_zone_are_dropped():
    """Being authoritative is not a licence to answer questions nobody asked.

    example.com may say what it likes about other.example.com — it owns the
    name — but the client asked one question, and an answer section is not a
    delivery mechanism for whatever the server would prefer we cached.
    """
    def root(name, rtype):
        return referral("com", "ns.com", COM)

    def com(name, rtype):
        return referral("example.com", "ns.example.com", AUTH)

    def auth(name, rtype):
        m = answer("www.example.com", "93.184.216.34")
        m.answers.append(RR(n("other.example.com"), Type.A, Class.IN, 300, R.A(EVIL)))
        return m

    t = Tree({ROOT: root, COM: com, AUTH: auth})
    rec = Recursive(t, root_hints=[ROOT], qmin=False)
    resp = await rec.resolve("www.example.com", Type.A)
    assert ips(resp) == ["93.184.216.34"], "carried an unasked-for record out of the zone"


@pytest.mark.asyncio
async def test_referral_must_descend_even_with_believable_glue():
    """Isolates the "must go down" half of the referral rule.

    The hostile authority here is careful: it names a nameserver inside its own
    zone, so the glue survives the bailiwick scrub, and it points at a zone that
    genuinely encloses the name being resolved. The only thing wrong with the
    referral is its direction — com is *above* example.com, and an authority
    for a child may not reassign its parent.
    """
    def root(name, rtype):
        return referral("com", "ns.com", COM)

    def com(name, rtype):
        return referral("example.com", "ns.example.com", AUTH)

    def hostile(name, rtype):
        return referral("com", "ns.example.com", EVIL)   # glue is in bailiwick

    t = Tree({ROOT: root, COM: com, AUTH: hostile,
              EVIL: lambda *a: answer("www.example.com", EVIL)})
    rec = Recursive(t, root_hints=[ROOT], qmin=False)
    resp = await rec.resolve("www.example.com", Type.A)
    assert t.asked(EVIL) == 0, "accepted a referral that pointed back up the tree"
    assert resp.rcode == Rcode.SERVFAIL


@pytest.mark.asyncio
async def test_referral_must_point_toward_the_name():
    """Isolates the "must go toward" half of the referral rule.

    evil.com is a legitimate zone for com to delegate, and the glue is inside
    com, so both the direction test and the bailiwick scrub are satisfied. It
    simply has nothing to do with the name being resolved — following it would
    let any TLD hand any query to any of its own customers.
    """
    def root(name, rtype):
        return referral("com", "ns.com", COM)

    def com(name, rtype):
        return referral("evil.com", "ns.evil.com", EVIL)

    t = Tree({ROOT: root, COM: com, EVIL: lambda *a: answer("www.bank.com", EVIL)})
    rec = Recursive(t, root_hints=[ROOT], qmin=False)
    resp = await rec.resolve("www.bank.com", Type.A)
    assert t.asked(EVIL) == 0, "followed a referral to a zone that does not hold the name"
    assert resp.rcode == Rcode.SERVFAIL


@pytest.mark.asyncio
async def test_cname_target_outside_the_zone_is_not_answered_in_place():
    """Isolates the bailiwick rule in the answer section.

    A CNAME may legitimately point anywhere, so the target is on the chain and
    the chain rule alone would admit whatever the server attached for it. But
    example.com is not authoritative for attacker.net, so its address record for
    the target is worthless: the target has to be resolved from the top. This is
    the oldest trick in the book and the reason answers are cut to the zone.
    """
    def root(name, rtype):
        if name.endswith(".net") or name == "net":
            return referral("net", "ns.net", NET)
        return referral("com", "ns.com", COM)

    def com(name, rtype):
        return referral("example.com", "ns.example.com", AUTH)

    def auth(name, rtype):
        m = Message(id=0, flags=Flags.QR | Flags.AA)
        m.answers.append(RR(n("www.example.com"), Type.CNAME, Class.IN, 300,
                            R.CNAME(n("target.attacker.net"))))
        m.answers.append(RR(n("target.attacker.net"), Type.A, Class.IN, 300, R.A(EVIL)))
        return m

    def net(name, rtype):
        return answer("target.attacker.net", "93.184.216.34")

    t = Tree({ROOT: root, COM: com, AUTH: auth, NET: net})
    rec = Recursive(t, root_hints=[ROOT], qmin=False)
    resp = await rec.resolve("www.example.com", Type.A)
    assert EVIL not in ips(resp), "took an out-of-zone address off a CNAME target"
    assert ips(resp) == ["93.184.216.34"]


# ------------------------------------------------------------ broken servers
@pytest.mark.asyncio
async def test_servfail_from_one_nameserver_fails_over():
    """One broken nameserver in a delegation must not break the name."""
    t = Tree({ROOT: lambda *a: two_nameservers("10.9.9.9", COM),
              "10.9.9.9": lambda *a: rcode(Rcode.SERVFAIL),
              COM: lambda *a: answer("www.example.com", "93.184.216.34")})
    rec = Recursive(t, root_hints=[ROOT], qmin=False)
    try_last(rec, COM)
    resp = await rec.resolve("www.example.com", Type.A)
    assert ips(resp) == ["93.184.216.34"]
    assert t.asked("10.9.9.9") == 1, "never tried the broken server"


@pytest.mark.asyncio
async def test_refused_with_the_authoritative_bit_set_is_not_an_answer():
    """Isolates the rcode check.

    Some servers set AA on a REFUSED, so "is it authoritative" is not enough on
    its own: an empty REFUSED taken at face value becomes a NODATA for a name
    that exists.
    """
    def refusing(name, rtype):
        m = rcode(Rcode.REFUSED)
        m.set_flag(Flags.AA, True)
        return m

    t = Tree({ROOT: lambda *a: two_nameservers("10.9.9.9", COM), "10.9.9.9": refusing,
              COM: lambda *a: answer("www.example.com", "93.184.216.34")})
    rec = Recursive(t, root_hints=[ROOT], qmin=False)
    try_last(rec, COM)
    resp = await rec.resolve("www.example.com", Type.A)
    assert ips(resp) == ["93.184.216.34"], "believed an authoritative-looking REFUSED"


@pytest.mark.asyncio
async def test_lame_delegation_fails_over():
    """A server that is not authoritative and offers no referral is lame.

    Believing it produces a NODATA for a name that exists — the worst kind of
    wrong answer, because it looks like a fact.
    """
    t = Tree({ROOT: lambda *a: two_nameservers("10.9.9.9", COM),
              "10.9.9.9": lambda *a: nodata(aa=False),      # lame
              COM: lambda *a: answer("www.example.com", "93.184.216.34")})
    rec = Recursive(t, root_hints=[ROOT], qmin=False)
    try_last(rec, COM)
    resp = await rec.resolve("www.example.com", Type.A)
    assert ips(resp) == ["93.184.216.34"], "believed a lame server's empty answer"


@pytest.mark.asyncio
async def test_referral_loop_terminates_quickly():
    """A zone that refers to itself must cost a handful of queries, not the
    whole step budget."""
    def root(name, rtype):
        return referral("com", "ns.com", COM)

    def com(name, rtype):
        return referral("com", "ns.com", COM)      # no progress, forever

    t = Tree({ROOT: root, COM: com})
    rec = Recursive(t, root_hints=[ROOT], qmin=False)
    resp = await rec.resolve("www.example.com", Type.A)
    assert resp.rcode == Rcode.SERVFAIL
    assert len(t.log) <= 4, f"spent {len(t.log)} queries on a self-referral"


@pytest.mark.asyncio
async def test_cname_loop_terminates_without_duplicating_records():
    """a -> b -> a must fail, and must not return the loop as an answer."""
    def root(name, rtype):
        return referral("com", "ns.com", COM)

    def com(name, rtype):
        m = Message(id=0, flags=Flags.QR | Flags.AA)
        target = "b.com" if name == "a.com" else "a.com"
        m.answers.append(RR(n(name), Type.CNAME, Class.IN, 300, R.CNAME(n(target))))
        return m

    t = Tree({ROOT: root, COM: com})
    rec = Recursive(t, root_hints=[ROOT], qmin=False)
    resp = await rec.resolve("a.com", Type.A)
    assert resp.rcode == Rcode.SERVFAIL
    assert not resp.answers, "returned a chain that does not terminate"
    # The loop is closed on the second hop, when the target is one we have
    # already asked about — not eventually, by running out of CNAME budget.
    assert len(t.log) <= 4, f"took {len(t.log)} queries to notice a 2-name loop"


@pytest.mark.asyncio
async def test_nameserver_chase_depth_is_bounded():
    """A delegation whose nameservers live in a zone whose nameservers live in
    a zone… is a query amplifier. It must bottom out."""
    depth = {"n": 0}

    def root(name, rtype):
        depth["n"] += 1
        # every zone is delegated to a nameserver in a brand-new zone, no glue
        return referral(name.split(".", 1)[-1] if "." in name else name,
                        f"ns{depth['n']}.level{depth['n']}.example", None)

    t = Tree({ROOT: root})
    # A deliberately generous packet budget, so that the depth limit is the only
    # thing that can stop this: the budget is the backstop, not the mechanism.
    rec = Recursive(t, root_hints=[ROOT], qmin=False, max_queries=500)
    resp = await rec.resolve("www.example.com", Type.A)
    assert resp.rcode == Rcode.SERVFAIL
    assert len(t.log) < 24, f"{len(t.log)} queries chasing nameserver addresses"


@pytest.mark.asyncio
async def test_total_query_budget_is_enforced():
    """No single client question may cost an unbounded number of packets."""
    seq = {"n": 0}

    def root(name, rtype):
        seq["n"] += 1
        # a legal, strictly-descending referral chain that never terminates
        # because the tree is deeper than any name: each step invents a label
        return referral(name, f"ns.{name}", ROOT)

    t = Tree({ROOT: root})
    rec = Recursive(t, root_hints=[ROOT], qmin=False)
    resp = await rec.resolve("a.b.c.d.e.f.example.com", Type.A)
    assert resp.rcode == Rcode.SERVFAIL
    assert len(t.log) <= 40


@pytest.mark.asyncio
async def test_packet_budget_is_the_hard_stop():
    """Isolates the budget from every structural limit.

    This tree is entirely well-behaved — every referral descends, every server
    answers — it is just deep and slow. Nothing about it is detectably wrong, so
    the only thing that can stop the resolver spending packets on it is the
    count it was given.
    """
    target = "a.b.c.d.e.f.g.h.example.com"
    parts = target.split(".")
    step = {"n": 0}

    def root(name, rtype):
        # one more label of the target on each call: a legal, strictly
        # descending delegation chain with glue, all the way down
        step["n"] = min(step["n"] + 1, len(parts))
        zone = ".".join(parts[-step["n"]:])
        return referral(zone, f"ns.{zone}", ROOT)

    t = Tree({ROOT: root})
    rec = Recursive(t, root_hints=[ROOT], qmin=False, max_queries=6, max_steps=100)
    resp = await rec.resolve(target, Type.A)
    assert resp.rcode == Rcode.SERVFAIL
    assert len(t.log) <= 6, f"spent {len(t.log)} packets on a 6-packet budget"


@pytest.mark.asyncio
async def test_budget_is_checked_between_nameservers_not_only_between_steps():
    """One step may try several nameservers, so the budget is spent inside it.

    A delegation to four dead servers is an ordinary sight on the internet. If
    the budget is only consulted when moving from one zone to the next, a single
    step overshoots it by as many packets as the delegation is wide.
    """
    def root(name, rtype):
        m = Message(id=0, flags=Flags.QR)
        for i in range(4):
            m.authority.append(RR(n("com"), Type.NS, Class.IN, 172800, R.NS(n(f"ns{i}.com"))))
            m.additional.append(RR(n(f"ns{i}.com"), Type.A, Class.IN, 172800, R.A(f"10.7.0.{i}")))
        return m

    handlers = {ROOT: root}
    handlers.update({f"10.7.0.{i}": (lambda *a: nodata(aa=False)) for i in range(4)})
    t = Tree(handlers)
    rec = Recursive(t, root_hints=[ROOT], qmin=False, max_queries=2)
    resp = await rec.resolve("www.example.com", Type.A)
    assert resp.rcode == Rcode.SERVFAIL
    assert len(t.log) <= 2, f"spent {len(t.log)} packets on a 2-packet budget"


@pytest.mark.asyncio
async def test_a_delegation_cached_without_glue_is_still_usable_later():
    """A zone whose nameserver addresses had to be chased must not be poisoned
    by its own cache entry: the second query into it has to work too."""
    def root(name, rtype):
        if name.endswith(".net") or name == "net":
            return referral("net", "ns.net", NET)
        return referral("com", "ns.com", COM)

    def com(name, rtype):
        return referral("example.com", "ns.example.net", None)   # no glue

    def net(name, rtype):
        return answer("ns.example.net", AUTH)

    def auth(name, rtype):
        return answer(name, "93.184.216.34")

    t = Tree({ROOT: root, COM: com, NET: net, AUTH: auth})
    rec = Recursive(t, root_hints=[ROOT], qmin=False)
    first = await rec.resolve("www.example.com", Type.A)
    second = await rec.resolve("mail.example.com", Type.A)
    assert ips(first) == ["93.184.216.34"]
    assert ips(second) == ["93.184.216.34"], "a glueless delegation broke on reuse"


@pytest.mark.asyncio
async def test_circular_delegation_does_not_recurse_into_itself():
    """A zone served only by a nameserver inside itself, with no glue.

    Finding ns.example.com means asking the servers for example.com, which is
    the very thing being looked up. Without a guard the resolver re-enters the
    same chase until some outer limit trips; the delegation is simply broken and
    it should be abandoned at once.
    """
    def root(name, rtype):
        return referral("com", "ns.com", COM)

    def com(name, rtype):
        return referral("example.com", "ns.example.com", None)   # no glue

    t = Tree({ROOT: root, COM: com})
    # depth limit set far out of the way: the re-entry guard is what must stop this
    rec = Recursive(t, root_hints=[ROOT], qmin=False, max_ns_depth=20, max_queries=200)
    resp = await rec.resolve("www.example.com", Type.A)
    assert resp.rcode == Rcode.SERVFAIL
    assert len(t.log) <= 6, f"re-entered a circular delegation {len(t.log)} times"


# ------------------------------------------------------------ delegation cache
@pytest.mark.asyncio
async def test_delegations_are_cached_across_resolutions():
    """The root is a shared public resource, not a per-query dependency.

    Two names in the same zone must cost one walk down, not two: the second
    resolution starts at the closest cached delegation.
    """
    def root(name, rtype):
        return referral("com", "ns.com", COM)

    def com(name, rtype):
        return referral("example.com", "ns.example.com", AUTH)

    def auth(name, rtype):
        return answer(name, "93.184.216.34")

    t = Tree({ROOT: root, COM: com, AUTH: auth})
    rec = Recursive(t, root_hints=[ROOT], qmin=False)
    await rec.resolve("www.example.com", Type.A)
    first = t.asked(ROOT)
    await rec.resolve("mail.example.com", Type.A)
    await rec.resolve("ftp.example.com", Type.A)

    assert first == 1
    assert t.asked(ROOT) == 1, f"asked the root {t.asked(ROOT)} times for 3 names in one zone"
    assert t.asked(COM) == 1, "re-walked com for a zone whose delegation was known"
    assert t.asked(AUTH) == 3


@pytest.mark.asyncio
async def test_cached_delegation_expires_with_its_ttl():
    clock = {"t": 1000.0}

    def root(name, rtype):
        m = Message(id=0, flags=Flags.QR)
        m.authority.append(RR(n("com"), Type.NS, Class.IN, 10, R.NS(n("ns.com"))))
        m.additional.append(RR(n("ns.com"), Type.A, Class.IN, 10, R.A(COM)))
        return m

    t = Tree({ROOT: root, COM: lambda name, rt: answer(name, "1.2.3.4")})
    rec = Recursive(t, root_hints=[ROOT], qmin=False, clock=lambda: clock["t"])
    await rec.resolve("a.com", Type.A)
    clock["t"] += 5
    await rec.resolve("b.com", Type.A)
    assert t.asked(ROOT) == 1
    clock["t"] += 20                      # past the 10s NS TTL
    await rec.resolve("c.com", Type.A)
    assert t.asked(ROOT) == 2, "kept a delegation past its TTL"


@pytest.mark.asyncio
async def test_a_poisoned_cache_entry_cannot_be_planted_by_a_lower_zone():
    """example.com's authority must not be able to write com's delegation."""
    def root(name, rtype):
        return referral("com", "ns.com", COM)

    def com(name, rtype):
        return referral("example.com", "ns.example.com", AUTH)

    def auth(name, rtype):
        m = answer(name, "93.184.216.34")
        # smuggle a delegation for a zone this server has no authority over
        m.authority.append(RR(n("com"), Type.NS, Class.IN, 86400, R.NS(n("ns.evil.net"))))
        m.additional.append(RR(n("ns.evil.net"), Type.A, Class.IN, 86400, R.A(EVIL)))
        return m

    t = Tree({ROOT: root, COM: com, AUTH: auth, EVIL: lambda *a: answer("x", EVIL)})
    rec = Recursive(t, root_hints=[ROOT], qmin=False)
    await rec.resolve("www.example.com", Type.A)
    await rec.resolve("www.other.com", Type.A)
    assert t.asked(EVIL) == 0, "a leaf authority rewrote the com delegation"


# ------------------------------------------------------------------- budget
@pytest.mark.asyncio
async def test_resolution_gives_up_on_its_deadline():
    """A resolution has a wall-clock budget; a stalling tree cannot hold a
    client socket open indefinitely."""
    import asyncio

    async def slow(ip, query):
        await asyncio.sleep(0.05)
        return referral(query.question.name.to_text().rstrip("."),
                        "ns." + query.question.name.to_text().rstrip("."), ROOT)

    rec = Recursive(slow, root_hints=[ROOT], qmin=False, budget=0.2)
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    resp = await rec.resolve("a.b.c.d.e.f.g.example.com", Type.A)
    assert loop.time() - t0 < 1.0
    assert resp.rcode == Rcode.SERVFAIL


@pytest.mark.asyncio
async def test_a_chased_cname_still_answers_the_question_that_was_asked():
    """The reply must echo the client's question, not the end of the chain.

    Found by running the real thing against the real internet: www.bbc.co.uk
    resolves through a CNAME into fastly, and the reply came back naming
    `bbc.map.fastly.net`, so this resolver's own response checks threw the
    answer away as being about a different name.
    """
    def root(name, rtype):
        return referral("com", "ns.com", COM)

    def com(name, rtype):
        if name == "alias.com":
            m = Message(id=0, flags=Flags.QR | Flags.AA)
            m.answers.append(RR(n("alias.com"), Type.CNAME, Class.IN, 300, R.CNAME(n("real.com"))))
            return m
        return answer("real.com", "1.2.3.4")

    t = Tree({ROOT: root, COM: com})
    rec = Recursive(t, root_hints=[ROOT], qmin=False)
    resp = await rec.resolve("alias.com", Type.A)
    assert resp.question is not None
    assert resp.question.name == n("alias.com"), "answered under the CNAME target's name"
    assert resp.question.rtype == Type.A
    assert ips(resp) == ["1.2.3.4"]


# ------------------------------------------------- existing behaviour retained
@pytest.mark.asyncio
async def test_qname_minimization_still_hides_the_leaf():
    def root(name, rtype):
        return referral("com", "ns.com", COM)

    def com(name, rtype):
        return referral("example.com", "ns.example.com", AUTH)

    def auth(name, rtype):
        return answer("www.example.com", "93.184.216.34") if name == "www.example.com" else nodata()

    t = Tree({ROOT: root, COM: com, AUTH: auth})
    rec = Recursive(t, root_hints=[ROOT], qmin=True)
    resp = await rec.resolve("www.example.com", Type.A)
    assert ips(resp) == ["93.184.216.34"]
    assert not any(s in (ROOT, COM) and nm == "www.example.com" for s, nm, _ in t.log)


# ----------------------------------------------------------------- stalling
@pytest.mark.asyncio
async def test_a_nameserver_that_never_replies_cannot_hold_the_resolution():
    """The wall clock has to bind *inside* a packet, not only between them.

    A budget that is only consulted between queries is no budget at all against
    a server that simply never answers: the resolver blocks in the transport and
    the deadline passes unnoticed. This is not a rare adversarial case — a
    silently dropped UDP query looks exactly the same — and it is why the client
    sees a timeout rather than the answer a working nameserver was holding.
    """
    import asyncio

    async def tree(ip, query):
        if ip == ROOT:
            m = referral("com", "ns1.com", "10.9.9.9")
            m.authority.append(RR(n("com"), Type.NS, Class.IN, 172800, R.NS(n("ns2.com"))))
            m.additional.append(RR(n("ns2.com"), Type.A, Class.IN, 172800, R.A(COM)))
            return m
        if ip == "10.9.9.9":
            await asyncio.sleep(30)          # a black hole
        return answer("www.example.com", "93.184.216.34")

    rec = Recursive(tree, root_hints=[ROOT], qmin=False, budget=3.0, query_timeout=0.2)
    try_last(rec, COM)                       # force the black hole to be tried first
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    resp = await rec.resolve("www.example.com", Type.A)
    took = loop.time() - t0
    assert ips(resp) == ["93.184.216.34"], "gave up instead of trying the other nameserver"
    assert took < 2.0, f"a silent server held the resolution for {took:.1f}s"


@pytest.mark.asyncio
async def test_the_deadline_survives_servers_that_all_stall():
    import asyncio

    async def tree(ip, query):
        if ip == ROOT:
            return referral("com", "ns.com", COM)
        await asyncio.sleep(30)

    rec = Recursive(tree, root_hints=[ROOT], qmin=False, budget=0.8, query_timeout=0.2)
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    resp = await rec.resolve("www.example.com", Type.A)
    took = loop.time() - t0
    assert resp.rcode == Rcode.SERVFAIL
    assert took < 2.0, f"held a client for {took:.1f}s on a 0.8s budget"


@pytest.mark.asyncio
async def test_a_broken_cname_chain_fails_empty():
    """SERVFAIL and a partial chain are contradictory claims.

    Seen against the real internet on outlook.office365.com: the reply carried
    three CNAMEs *and* SERVFAIL. A client that reads the records and ignores the
    rcode follows the chain to nowhere.
    """
    def root(name, rtype):
        return referral("com", "ns.com", COM)

    def com(name, rtype):
        if name == "start.com":
            m = Message(id=0, flags=Flags.QR | Flags.AA)
            m.answers.append(RR(n("start.com"), Type.CNAME, Class.IN, 300, R.CNAME(n("dead.com"))))
            return m
        return rcode(Rcode.SERVFAIL)         # the rest of the chain is unreachable

    t = Tree({ROOT: root, COM: com})
    rec = Recursive(t, root_hints=[ROOT], qmin=False)
    resp = await rec.resolve("start.com", Type.A)
    assert resp.rcode == Rcode.SERVFAIL
    assert not resp.answers, "returned a chain alongside a failure"


# ------------------------------------------------------- unreachable families
V6 = "2001:db8::53"


@pytest.mark.asyncio
async def test_addresses_the_host_cannot_reach_are_not_offered():
    """On a v4-only box, IPv6 glue is not a slow server — it is no server.

    The root zone alone is roughly half AAAA, so a resolver that treats these
    as ordinary candidates spends several failures per resolution learning the
    same thing over and over.
    """
    def root(name, rtype):
        m = referral("com", "ns.com", COM)
        m.additional.append(RR(n("ns.com"), Type.AAAA, Class.IN, 172800, R.AAAA(V6)))
        return m

    t = Tree({ROOT: root, COM: lambda *a: answer("www.example.com", "93.184.216.34")})
    rec = Recursive(t, root_hints=[ROOT], qmin=False,
                    reachable=lambda ip: ":" not in ip)      # a host with no IPv6
    resp = await rec.resolve("www.example.com", Type.A)
    assert ips(resp) == ["93.184.216.34"]
    assert t.asked(V6) == 0, "tried an address family the host has no route to"


@pytest.mark.asyncio
async def test_all_addresses_filtered_out_still_gets_tried():
    """A reachability guess is a hint, not a veto: if it would leave nothing to
    ask, ask anyway rather than inventing a failure."""
    t = Tree({ROOT: lambda *a: referral("com", "ns.com", COM),
              COM: lambda *a: answer("www.example.com", "93.184.216.34")})
    rec = Recursive(t, root_hints=[ROOT], qmin=False, reachable=lambda ip: False)
    resp = await rec.resolve("www.example.com", Type.A)
    assert ips(resp) == ["93.184.216.34"]


@pytest.mark.asyncio
async def test_a_packet_that_never_left_does_not_cost_budget():
    """`ENETUNREACH` means the kernel sent nothing.

    Charging the budget for it lets a delegation's unreachable glue exhaust a
    resolution before any reachable nameserver is tried — which is precisely
    how www.spiegel.de failed on a v4-only Raspberry Pi while resolving fine
    everywhere else.
    """
    import errno as _errno

    def root(name, rtype):
        m = Message(id=0, flags=Flags.QR)
        for ns in ("ns1.com", "ns2.com", "ns3.com"):
            m.authority.append(RR(n("com"), Type.NS, Class.IN, 172800, R.NS(n(ns))))
        m.additional.append(RR(n("ns1.com"), Type.AAAA, Class.IN, 172800, R.AAAA("2001:db8::1")))
        m.additional.append(RR(n("ns2.com"), Type.AAAA, Class.IN, 172800, R.AAAA("2001:db8::2")))
        m.additional.append(RR(n("ns3.com"), Type.A, Class.IN, 172800, R.A(COM)))
        return m

    log_ = []

    async def tree(ip, query):
        log_.append(ip)
        if ip == ROOT:
            return root(None, None)
        if ":" in ip:
            raise OSError(_errno.ENETUNREACH, "Network is unreachable")
        return answer("www.example.com", "93.184.216.34")

    # Exactly two packets are actually sendable: the root query and the good
    # nameserver. Anything charged for the unreachable pair starves the second.
    rec = Recursive(tree, root_hints=[ROOT], qmin=False, max_queries=2,
                    reachable=lambda ip: True)      # force them to be attempted
    rec._peers[COM] = _Peer(rtt=9.0)                # and attempted last
    resp = await rec.resolve("www.example.com", Type.A)
    assert ips(resp) == ["93.184.216.34"], f"budget eaten by unsent packets; tried {log_}"
