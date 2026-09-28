"""Root trust anchors loaded from a file, in both formats an operator has."""
from __future__ import annotations

import base64

import pytest

from trench.config import Config
from trench.resolver.dnssec.anchors import load_anchors, parse_anchors
from trench.resolver.dnssec.chain import ROOT_ANCHORS
from trench.resolver.dnssec.keys import ds_digest, key_tag
from trench.wire import rdata as R
from trench.wire.name import Name

IANA_DS = (
    ". IN DS 20326 8 2 "
    "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n"
    ".\t86400\tIN\tDS\t38696 8 2 "
    "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16\n"
)


def test_presentation_ds_records_parse():
    anchors = parse_anchors(IANA_DS)
    assert [a.key_tag for a in anchors] == [20326, 38696]
    assert anchors[0].digest == ROOT_ANCHORS[0].digest   # same anchors as the pins


def test_bind_trust_anchors_block_parses():
    text = """
    trust-anchors {
      . initial-ds 20326 8 2 "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";
      . static-ds  38696 8 2 "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16";
    };
    """
    anchors = parse_anchors(text)
    assert [a.key_tag for a in anchors] == [20326, 38696]


def test_dnskey_anchor_is_converted_to_a_ds():
    """BIND's key-style anchors hold a DNSKEY; the validator compares DS."""
    key = R.DNSKEY(flags=257, protocol=3, algorithm=8,
                   public_key=b"\x01\x03" + b"\xab" * 128)
    b64 = base64.b64encode(key.public_key).decode()
    text = f'trust-anchors {{ . initial-key 257 3 8 "{b64}"; }};'
    (anchor,) = parse_anchors(text)
    assert anchor.key_tag == key_tag(key)
    assert anchor.digest == ds_digest(Name.from_text("."), key, 2)


def test_duplicates_collapse_and_junk_is_skipped():
    text = IANA_DS + IANA_DS + "\n; a comment\ngarbage line\n. IN DS not numbers here\n"
    assert len(parse_anchors(text)) == 2


def test_missing_or_empty_file_yields_nothing(tmp_path):
    assert load_anchors(tmp_path / "absent.key") == []
    empty = tmp_path / "root.key"
    empty.write_text("; nothing useful in here\n")
    assert load_anchors(empty) == []


def test_app_prefers_the_file_over_the_pins(tmp_path):
    from trench.app import App
    (tmp_path / "root.key").write_text(". IN DS 12345 8 2 " + "AA" * 32 + "\n")
    cfg = Config.load_dict({"data_dir": str(tmp_path),
                            "upstream": {"mode": "recursive", "dnssec": True}})
    app = App(cfg)
    anchors = app._trust_anchors()
    assert [a.key_tag for a in anchors] == [12345]
    # and with no file, the compiled pins stand
    cfg2 = Config.load_dict({"data_dir": str(tmp_path / "empty")})
    assert App(cfg2)._trust_anchors() is None


def test_a_ds_for_another_zone_is_never_installed_as_a_root_anchor():
    """Whoever holds the key for a stray DS could otherwise sign the root — and
    from the root, every name. An operator concatenating `dig DS` output is all
    it takes."""
    text = (". IN DS 20326 8 2 " + "AA" * 32 + "\n"
            "evil.example.com. IN DS 12345 8 2 " + "BB" * 32 + "\n"
            # An owner-less continuation line inherits the previous owner in a
            # zone file. Guessing that it "is probably still the root" is the
            # assumption this must not make, so it is skipped.
            "\tIN DS 999 8 2 " + "CC" * 32 + "\n")
    assert [a.key_tag for a in parse_anchors(text)] == [20326]


def test_bind_blocks_already_refused_other_zones_and_still_do():
    text = ('trust-anchors { evil.example.com. initial-ds 12345 8 2 "' + "BB" * 32
            + '"; };')
    assert parse_anchors(text) == []


def test_revoked_and_non_zone_keys_are_not_turned_into_anchors():
    key = R.DNSKEY(flags=257, protocol=3, algorithm=8,
                   public_key=b"\x01\x03" + b"\xcd" * 128)
    b64 = base64.b64encode(key.public_key).decode()
    revoked = f'trust-anchors {{ . initial-key 385 3 8 "{b64}"; }};'   # 257|REVOKE
    assert parse_anchors(revoked) == []
    not_a_zone_key = f'trust-anchors {{ . initial-key 1 3 8 "{b64}"; }};'
    assert parse_anchors(not_a_zone_key) == []
    assert len(parse_anchors(f'trust-anchors {{ . initial-key 257 3 8 "{b64}"; }};')) == 1


def test_a_corrupted_key_line_is_skipped_rather_than_guessed_at():
    text = 'trust-anchors { . initial-key 257 3 8 "not base64 at all!!"; };'
    assert parse_anchors(text) == []


def test_an_anchor_without_the_sep_bit_is_kept_but_noted(caplog):
    """The SEP bit is a hint, not a rule — an anchor without it is unusual
    enough to say so, and still usable."""
    import logging
    caplog.set_level(logging.INFO)
    key = R.DNSKEY(flags=256, protocol=3, algorithm=8,
                   public_key=b"\x01\x03" + b"\xab" * 128)
    b64 = base64.b64encode(key.public_key).decode()
    got = parse_anchors(f'trust-anchors {{ . initial-key 256 3 8 "{b64}"; }};')
    assert len(got) == 1
    assert any("no SEP bit" in r.getMessage() for r in caplog.records)


def test_a_ds_entry_with_an_empty_digest_is_skipped():
    assert parse_anchors('trust-anchors { . initial-ds 20326 8 2 ""; };') == []


def test_a_digest_that_is_not_hex_is_skipped(caplog):
    assert parse_anchors(". IN DS 20326 8 2 nothexatall\n") == []


def test_whitespace_inside_a_digest_is_stripped():
    """A BIND block wraps long digests across lines."""
    digest = "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
    wrapped = digest[:32] + "\n            " + digest[32:]
    got = parse_anchors(f'trust-anchors {{ . initial-ds 20326 8 2 "{wrapped}"; }};')
    assert len(got) == 1
    assert got[0].digest.hex().upper() == digest


def test_a_digest_of_the_wrong_length_is_refused(caplog):
    """Regression: a presentation line wrapped across two lines parsed as a
    *truncated* digest, which matches no real key — so every signed name under
    the root validated as BOGUS and the resolver SERVFAILed the internet, with
    nothing in the log to say why."""
    digest = "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
    assert parse_anchors(f". IN DS 20326 8 2 {digest[:32]}\n{digest[32:]}\n") == []
    assert any("digest is" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("dtype,length", [(1, 20), (2, 32), (4, 48)])
def test_each_digest_type_has_the_length_it_is_defined_to_have(dtype, length):
    good = "ab" * length
    assert len(parse_anchors(f". IN DS 20326 8 {dtype} {good}\n")) == 1
    short = "ab" * (length - 1)
    assert parse_anchors(f". IN DS 20326 8 {dtype} {short}\n") == []


def test_an_unknown_digest_type_is_not_length_checked():
    """We cannot know what length a type we do not implement should be."""
    assert len(parse_anchors(". IN DS 20326 8 99 abcdef\n")) == 1


def test_an_unreadable_file_yields_nothing(tmp_path, caplog):
    from trench.resolver.dnssec.anchors import load_anchors
    path = tmp_path / "root.key"
    path.write_bytes(b"\xff\xfe\x00binary")
    assert load_anchors(path) == []


def test_a_file_with_nothing_usable_is_reported(tmp_path, caplog):
    """So the caller can keep the built-in pins rather than validating against
    nothing."""
    from trench.resolver.dnssec.anchors import load_anchors
    path = tmp_path / "root.key"
    path.write_text("; only a comment\n")
    assert load_anchors(path) == []
    assert any("no usable trust anchors" in r.getMessage() for r in caplog.records)


def test_a_tilde_path_is_expanded():
    from trench.resolver.dnssec.anchors import load_anchors
    assert load_anchors("~/definitely-not-a-real-anchor-file") == []


def test_a_bind_block_and_a_presentation_line_can_coexist():
    text = ('trust-anchors {\n'
            '    . initial-ds 20326 8 2 "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";\n'
            '};\n'
            '. IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16\n')
    got = parse_anchors(text)
    tags = {ds.key_tag for ds in got}
    assert tags == {20326, 38696}


def test_a_line_already_taken_by_a_bind_block_is_not_read_twice():
    text = ('trust-anchors {\n'
            '    . initial-ds 20326 8 2 "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";\n'
            '};\n')
    assert len(parse_anchors(text)) == 1
