"""Root trust anchors loaded from a file, in both formats an operator has."""
from __future__ import annotations

import base64

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
