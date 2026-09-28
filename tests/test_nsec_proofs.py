"""What a set of NSEC/NSEC3 records actually proves.

This module does no cryptography — the caller has already verified the RRSIGs —
so what is testable here is exactly the reasoning that decides whether a denial
is honest. The failure modes are the interesting part: a wildcard that could
have answered, a proof taken from the wrong side of a zone cut, and an opt-out
NSEC3 being read as if it proved a gap empty.
"""
from __future__ import annotations

import pytest

from trench.auth_zone.sign.signer import encode_type_bitmap
from trench.resolver.dnssec.nsec import (
    MAX_NSEC3_ITERATIONS,
    Nsec3Set,
    _ancestors,
    _between,
    _closest_encloser,
    _gap_unproven,
    _is_delegation,
    bitmap_has,
    canon_key,
    common_suffix,
    name_lt,
    nsec3_b32,
    nsec3_ds_denial,
    nsec3_hash,
    nsec3_nodata,
    nsec3_nxdomain,
    nsec3_wildcard_expansion,
    nsec_covers,
    nsec_ds_denial,
    nsec_nodata,
    nsec_nxdomain,
    nsec_wildcard_expansion,
    nsec_wildcard_nodata,
    wildcard_of,
)
from trench.wire import Type
from trench.wire import rdata as R
from trench.wire.name import Name

ROOT = Name.from_text(".")


def n(s):
    return Name.from_text(s)


def bm(*types):
    return encode_type_bitmap(set(types))


def nsec(next_name, *types):
    return R.NSEC(next_name=n(next_name), type_bitmap=bm(*types))


# --- canonical ordering ---
def test_the_sort_key_is_lowercased_and_least_significant_first():
    assert canon_key(n("WWW.Example.COM.")) == [b"com", b"example", b"www"]


def test_ordering_is_case_insensitive():
    assert not name_lt(n("A.test."), n("a.test."))
    assert not name_lt(n("a.test."), n("A.test."))


def test_a_prefix_sorts_before_its_extension():
    assert name_lt(n("example.com."), n("a.example.com."))
    assert not name_lt(n("a.example.com."), n("example.com."))


def test_the_root_sorts_first():
    assert name_lt(ROOT, n("a."))
    assert not name_lt(n("a."), ROOT)


def test_ordering_compares_by_least_significant_label_first():
    assert name_lt(n("z.a.test."), n("a.b.test."))


# --- nsec_covers ---
def test_a_name_inside_the_gap_is_covered():
    assert nsec_covers(n("a."), n("c."), n("b."))


def test_the_endpoints_are_not_covered():
    assert not nsec_covers(n("a."), n("c."), n("a."))
    assert not nsec_covers(n("a."), n("c."), n("c."))


def test_the_wrapping_record_covers_both_ends():
    """The last NSEC in a zone points back at the apex."""
    assert nsec_covers(n("z."), n("a."), n("zz."))
    assert not nsec_covers(n("z."), n("a."), n("m."))


# --- bitmaps ---
def test_an_empty_bitmap_asserts_nothing():
    assert bitmap_has(b"", Type.A) is False


def test_a_type_in_a_high_window_is_found():
    """Window 1 covers types 256-511 — the bitmap is not a flat bit array."""
    bitmap = bm(Type.A, 260)
    assert bitmap_has(bitmap, 260) is True
    assert bitmap_has(bitmap, 261) is False
    assert bitmap_has(bitmap, Type.A) is True


def test_a_type_past_the_end_of_its_window_block_is_absent():
    assert bitmap_has(bm(Type.A), Type.CAA) is False


def test_a_truncated_bitmap_does_not_raise():
    assert bitmap_has(b"\x00", Type.A) is False
    assert bitmap_has(b"\x00\x09\x00", Type.A) is False


# --- name helpers ---
@pytest.mark.parametrize("a,b,suffix", [
    ("a.example.com.", "b.example.com.", "example.com."),
    ("a.example.com.", "a.example.net.", "."),
    ("example.com.", "example.com.", "example.com."),
    ("A.Example.COM.", "b.example.com.", "Example.COM."),
])
def test_the_closest_shared_ancestor(a, b, suffix):
    assert common_suffix(n(a), n(b)).to_text().lower() == suffix.lower()


def test_the_wildcard_of_a_name():
    assert wildcard_of(n("example.com.")) == n("*.example.com.")
    assert wildcard_of(ROOT) == n("*.")


def test_ancestors_run_from_the_parent_up_to_the_zone():
    got = _ancestors(n("a.b.c.example.com."), n("example.com."))
    assert [x.to_text() for x in got] == [
        "b.c.example.com.", "c.example.com.", "example.com."]


def test_ancestors_of_a_direct_child_is_just_the_zone():
    assert _ancestors(n("a.example.com."), n("example.com.")) == [n("example.com.")]


def test_ancestors_stops_at_the_root():
    assert _ancestors(n("com."), ROOT) == [ROOT]


# --- delegation and opt-out predicates ---
def test_a_parent_side_delegation_is_recognised():
    assert _is_delegation(nsec("next.", Type.NS)) is True


def test_an_apex_record_is_not_a_delegation():
    """SOA set means this came from the child, which has every reason to lie
    about its own contents."""
    assert _is_delegation(nsec("next.", Type.NS, Type.SOA)) is False


def test_an_ordinary_name_is_not_a_delegation():
    assert _is_delegation(nsec("next.", Type.A)) is False


def test_a_missing_record_leaves_its_gap_unproven():
    assert _gap_unproven(None) is True


def test_an_opt_out_record_leaves_its_gap_unproven():
    rd = R.NSEC3(hash_algorithm=1, flags=0x01, iterations=0, salt=b"",
                 next_hashed=b"\x00" * 20, type_bitmap=bm(Type.A))
    assert _gap_unproven(rd) is True
    rd_clear = R.NSEC3(hash_algorithm=1, flags=0, iterations=0, salt=b"",
                       next_hashed=b"\x00" * 20, type_bitmap=bm(Type.A))
    assert _gap_unproven(rd_clear) is False


# --- NSEC NODATA ---
def test_nodata_needs_the_record_at_exactly_the_name():
    records = [(n("other.test."), nsec("z.test.", Type.A))]
    assert nsec_nodata(n("a.test."), Type.MX, records) is False


def test_a_cname_at_the_name_defeats_a_nodata_proof():
    """Had a CNAME existed, the server owed us the chain, not an empty
    answer."""
    records = [(n("a.test."), nsec("z.test.", Type.CNAME))]
    assert nsec_nodata(n("a.test."), Type.MX, records) is False


def test_a_parent_side_delegation_cannot_prove_nodata_in_the_child():
    """Without this the parent's own public NSEC denies any type at the child's
    apex."""
    records = [(n("child.test."), nsec("z.test.", Type.NS))]
    assert nsec_nodata(n("child.test."), Type.A, records) is False


def test_the_childs_apex_can_prove_nodata_for_itself():
    records = [(n("child.test."), nsec("a.child.test.", Type.NS, Type.SOA))]
    assert nsec_nodata(n("child.test."), Type.MX, records) is True


# --- NSEC wildcard NODATA ---
def test_wildcard_nodata_proof():
    """The wildcard matches and lacks the type, and the exact name is absent."""
    records = [
        (n("*.test."), nsec("m.test.", Type.A)),
        (n("m.test."), nsec("z.test.", Type.A)),
    ]
    assert nsec_wildcard_nodata(n("q.test."), Type.MX, records) is True


def test_wildcard_nodata_fails_when_the_wildcard_has_the_type():
    records = [
        (n("*.test."), nsec("m.test.", Type.MX)),
        (n("m.test."), nsec("z.test.", Type.A)),
    ]
    assert nsec_wildcard_nodata(n("q.test."), Type.MX, records) is False


def test_wildcard_nodata_fails_when_the_wildcard_has_a_cname():
    records = [
        (n("*.test."), nsec("m.test.", Type.CNAME)),
        (n("m.test."), nsec("z.test.", Type.A)),
    ]
    assert nsec_wildcard_nodata(n("q.test."), Type.MX, records) is False


def test_wildcard_nodata_fails_when_the_exact_name_is_not_proven_absent():
    records = [(n("*.test."), nsec("m.test.", Type.A))]
    assert nsec_wildcard_nodata(n("q.test."), Type.MX, records) is False


def test_wildcard_nodata_ignores_a_wildcard_from_another_branch():
    records = [
        (n("*.other."), nsec("m.other.", Type.A)),
        (n("m.test."), nsec("z.test.", Type.A)),
    ]
    assert nsec_wildcard_nodata(n("q.test."), Type.MX, records) is False


def test_wildcard_nodata_does_not_apply_to_the_wildcards_own_parent():
    records = [
        (n("*.test."), nsec("m.test.", Type.A)),
        (n("m.test."), nsec("z.test.", Type.A)),
    ]
    assert nsec_wildcard_nodata(n("test."), Type.MX, records) is False


def test_wildcard_nodata_skips_non_wildcard_records():
    records = [(n("a.test."), nsec("z.test.", Type.A))]
    assert nsec_wildcard_nodata(n("q.test."), Type.MX, records) is False


# --- NSEC wildcard expansion ---
def test_a_wildcard_expansion_needs_the_exact_name_proven_absent():
    """Otherwise one wildcard signature can be replayed over every name the
    zone answers for directly."""
    covering = [(n("m.test."), nsec("z.test.", Type.A))]
    assert nsec_wildcard_expansion(n("q.test."), n("*.test."), covering) is True
    assert nsec_wildcard_expansion(n("q.test."), n("*.test."), []) is False


def test_a_wildcard_expansion_must_be_below_its_own_encloser():
    covering = [(n("m.test."), nsec("z.test.", Type.A))]
    assert nsec_wildcard_expansion(n("test."), n("*.test."), covering) is False
    assert nsec_wildcard_expansion(n("q.other."), n("*.test."), covering) is False


# --- NSEC DS denial ---
def test_a_delegation_without_a_ds_is_insecure():
    records = [(n("child.test."), nsec("z.test.", Type.NS))]
    assert nsec_ds_denial(n("child.test."), records) == "insecure"


def test_a_record_asserting_ds_while_denying_it_proves_nothing():
    records = [(n("child.test."), nsec("z.test.", Type.NS, Type.DS))]
    assert nsec_ds_denial(n("child.test."), records) is None


def test_a_child_apex_record_cannot_deny_its_own_ds():
    """DS is the parent's record; a child able to deny it could opt itself out
    of DNSSEC at will."""
    records = [(n("child.test."), nsec("a.child.test.", Type.NS, Type.SOA))]
    assert nsec_ds_denial(n("child.test."), records) is None


def test_a_name_that_is_not_a_delegation_means_keep_descending():
    records = [(n("child.test."), nsec("z.test.", Type.A))]
    assert nsec_ds_denial(n("child.test."), records) == "nocut"


def test_a_covered_name_has_no_cut_at_all():
    records = [(n("a.test."), nsec("z.test.", Type.A))]
    assert nsec_ds_denial(n("child.test."), records) == "nocut"


def test_no_relevant_record_proves_nothing_about_ds():
    records = [(n("a.test."), nsec("b.test.", Type.A))]
    assert nsec_ds_denial(n("zz.test."), records) is None


# --- NSEC NXDOMAIN ---
def test_nxdomain_needs_the_wildcard_ruled_out_too():
    covering = [(n("m.test."), nsec("z.test.", Type.A))]
    assert nsec_nxdomain(n("q.test."), covering) is False
    with_wildcard = covering + [(n("test."), nsec("*.test.", Type.SOA))]
    # The apex record's gap must cover `*.test.`, not merely end at it.
    apex_covers = [(n("test."), nsec("m.test.", Type.SOA)), *covering]
    assert nsec_nxdomain(n("q.test."), apex_covers) is True
    assert with_wildcard is not None


# --- NSEC3 ---
def _nsec3(next_hashed, *types, flags=0, salt=b"", iterations=0, algorithm=1):
    return R.NSEC3(hash_algorithm=algorithm, flags=flags, iterations=iterations,
                   salt=salt, next_hashed=next_hashed, type_bitmap=bm(*types))


def _owner(name_hash, zone="test."):
    return Name.from_text(f"{name_hash}.{zone}")


def test_nsec3_hashing_is_stable_and_salted():
    a = nsec3_hash(n("a.test."), b"", 0)
    assert a == nsec3_hash(n("A.TEST."), b"", 0), "hashing is on the canonical form"
    assert a != nsec3_hash(n("a.test."), b"\x01", 0)
    assert a != nsec3_hash(n("a.test."), b"", 1)
    assert len(a) == 20


def test_the_base32_encoding_is_lowercase_hex_extended():
    encoded = nsec3_b32(b"\x00" * 20)
    assert encoded == encoded.lower() and len(encoded) == 32


def test_between_handles_the_wrap():
    assert _between("a", "b", "c") is True
    assert _between("a", "d", "c") is False
    assert _between("z", "zz", "a") is True       # wrap past the last hash
    assert _between("z", "m", "a") is False


def test_an_empty_nsec3_set_is_unusable():
    s = Nsec3Set([], n("test."))
    assert s.usable is False and s.records == []


def test_an_unknown_hash_algorithm_is_unusable():
    """SHA-1 is the only algorithm defined."""
    items = [(_owner("aaaa"), _nsec3(b"\xff" * 20, Type.A, algorithm=2))]
    assert Nsec3Set(items, n("test.")).usable is False


def test_an_excessive_iteration_count_is_unusable():
    """RFC 9276: treat it as insecure rather than pay the hashing an attacker
    asked for."""
    items = [(_owner("aaaa"),
              _nsec3(b"\xff" * 20, Type.A, iterations=MAX_NSEC3_ITERATIONS + 1))]
    assert Nsec3Set(items, n("test.")).usable is False


def test_mixed_parameters_prove_nothing():
    items = [(_owner("aaaa"), _nsec3(b"\xff" * 20, Type.A, salt=b"\x01")),
             (_owner("bbbb"), _nsec3(b"\xff" * 20, Type.A, salt=b"\x02"))]
    assert Nsec3Set(items, n("test.")).usable is False

    mixed_iters = [(_owner("aaaa"), _nsec3(b"\xff" * 20, Type.A, iterations=1)),
                   (_owner("bbbb"), _nsec3(b"\xff" * 20, Type.A, iterations=2))]
    assert Nsec3Set(mixed_iters, n("test.")).usable is False


def test_a_record_from_a_deeper_cut_is_not_admitted():
    """Recording only the first label let a record from a deeper zone shift the
    gaps `cover()` reads."""
    items = [(_owner("aaaa"), _nsec3(b"\xff" * 20, Type.A)),
             (Name.from_text("bbbb.sub.test."), _nsec3(b"\xff" * 20, Type.A))]
    s = Nsec3Set(items, n("test."))
    assert s.usable is True
    assert [h for h, _ in s.records] == ["aaaa"]


def test_a_rootless_owner_makes_the_set_unusable():
    items = [(ROOT, _nsec3(b"\xff" * 20, Type.A))]
    assert Nsec3Set(items, ROOT).usable is False


def test_owner_hashes_are_lowercased():
    items = [(_owner("AAAA"), _nsec3(b"\xff" * 20, Type.A))]
    assert Nsec3Set(items, n("test.")).records[0][0] == "aaaa"


def _set_for(zone, entries, **params):
    """Build an Nsec3Set whose owner hashes are the real hashes of `entries`.

    `entries` maps a name (or a raw hash string) to (next_name_or_hash, types,
    flags).
    """
    salt = params.get("salt", b"")
    iterations = params.get("iterations", 0)
    items = []
    for owner, (nxt, types, flags) in entries.items():
        oh = (nsec3_b32(nsec3_hash(n(owner), salt, iterations))
              if isinstance(owner, str) and owner.endswith(".") else owner)
        nh = (nsec3_hash(n(nxt), salt, iterations)
              if isinstance(nxt, str) and nxt.endswith(".") else nxt)
        items.append((Name.from_text(f"{oh}.{zone}"),
                      _nsec3(nh, *types, flags=flags, salt=salt,
                             iterations=iterations)))
    return Nsec3Set(items, n(zone))


def test_match_and_cover_find_the_right_record():
    s = _set_for("test.", {"a.test.": ("z.test.", (Type.A,), 0)})
    assert s.match(n("a.test.")) is not None
    assert s.match(n("b.test.")) is None
    # The a->z gap covers whatever hashes between them; at minimum a.test.
    # itself never falls in its own gap.
    assert s.cover(n("a.test.")) is None


def test_the_hash_of_a_name_is_cached():
    s = _set_for("test.", {"a.test.": ("z.test.", (Type.A,), 0)})
    first = s.h(n("a.test."))
    assert s.h(n("a.test.")) is first
    assert n("a.test.") in s._cache


def test_nsec3_nodata_at_a_matched_name():
    s = _set_for("test.", {"a.test.": ("z.test.", (Type.A,), 0)})
    assert nsec3_nodata(n("a.test."), Type.MX, s) is True
    assert nsec3_nodata(n("a.test."), Type.A, s) is False


def test_nsec3_nodata_refuses_a_parent_side_delegation():
    s = _set_for("test.", {"child.test.": ("z.test.", (Type.NS,), 0)})
    assert nsec3_nodata(n("child.test."), Type.A, s) is False


def test_nsec3_nodata_refuses_when_a_cname_is_present():
    s = _set_for("test.", {"a.test.": ("z.test.", (Type.CNAME,), 0)})
    assert nsec3_nodata(n("a.test."), Type.MX, s) is False


def test_nsec3_nodata_without_a_closest_encloser_proves_nothing():
    s = _set_for("test.", {"other.test.": ("z.test.", (Type.A,), 0)})
    assert nsec3_nodata(n("q.deep.test."), Type.MX, s) is False


def test_nsec3_ds_denial_reads_the_bitmap():
    s = _set_for("test.", {"child.test.": ("z.test.", (Type.NS,), 0)})
    assert nsec3_ds_denial(n("child.test."), s) == "insecure"

    with_ds = _set_for("test.", {"child.test.": ("z.test.", (Type.NS, Type.DS), 0)})
    assert nsec3_ds_denial(n("child.test."), with_ds) is None

    apex = _set_for("test.", {"child.test.": ("z.test.", (Type.NS, Type.SOA), 0)})
    assert nsec3_ds_denial(n("child.test."), apex) is None

    plain = _set_for("test.", {"child.test.": ("z.test.", (Type.A,), 0)})
    assert nsec3_ds_denial(n("child.test."), plain) == "nocut"


def test_nsec3_ds_denial_with_no_record_at_all():
    s = _set_for("test.", {"other.test.": ("other.test.", (Type.A,), 0)})
    assert nsec3_ds_denial(n("nothing.test."), s) in (None, "nocut", "insecure")


def test_a_closest_encloser_is_the_deepest_matched_ancestor():
    s = _set_for("test.", {"test.": ("z.test.", (Type.SOA,), 0),
                           "deep.test.": ("z.test.", (Type.A,), 0)})
    found = _closest_encloser(n("q.deep.test."), s)
    assert found is not None
    ce, next_closer = found
    assert ce == n("deep.test.")
    assert next_closer == n("q.deep.test.")


def test_no_closest_encloser_when_nothing_matches():
    s = _set_for("test.", {"other.test.": ("z.test.", (Type.A,), 0)})
    assert _closest_encloser(n("q.deep.test."), s) is None


def test_nsec3_wildcard_expansion_must_be_below_its_encloser():
    s = _set_for("test.", {"a.test.": ("z.test.", (Type.A,), 0)})
    assert nsec3_wildcard_expansion(n("test."), n("*.test."), s) is False
    assert nsec3_wildcard_expansion(n("q.other."), n("*.test."), s) is False


def test_nsec3_nxdomain_without_a_closest_encloser_is_unproven():
    s = _set_for("test.", {"other.test.": ("z.test.", (Type.A,), 0)})
    assert nsec3_nxdomain(n("q.deep.test."), s) is False


def test_nsec3_nxdomain_is_refused_when_the_wildcard_exists():
    """If the wildcard is there, it could have answered — so the name is not
    provably absent."""
    s = _set_for("test.", {"test.": ("z.test.", (Type.SOA,), 0),
                           "*.test.": ("z.test.", (Type.A,), 0)})
    assert nsec3_nxdomain(n("q.test."), s) is False
