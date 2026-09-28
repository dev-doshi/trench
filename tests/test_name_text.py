"""Names in presentation format, and what a name that will not parse must do.

A label may carry any octet — the wire is length-prefixed — so the text form
has escapes: `\\.` for a dot inside a label, `\\\\` for a backslash, `\\DDD` for
anything else. `to_text` emits all three. `from_text` split on every dot before
unescaping, which cut a name in half at the escape that exists to say "this dot
is not a separator", and then read the length octet of a fragment ending in a
lone backslash.

Two consequences, both fixed here. `Name.from_text(n.to_text())` raised
IndexError for any name with a dot in a label, and `from_text` — whose callers
catch `WireError`, because that is what it documents — could also raise
IndexError, ValueError or UnicodeEncodeError, from input those callers do not
choose: a downloaded blocklist, a zone file, a DoH query parameter.
"""
from __future__ import annotations

import pytest

from trench.errors import WireError
from trench.wire.name import MAX_LABEL, Name


@pytest.mark.parametrize("labels", [
    (b"plain", b"example", b"com"),
    (b"ex.ample", b"com"),                      # a dot inside a label
    (b"a.b\\c", b"x"),                          # and a backslash beside it
    (b"sl\\ash", b"com"),
    (b"a b", b"com"),                           # space -> \032
    (bytes([0, 1, 255]), b"com"),               # the full octet range
    (bytes(range(1, 64)),),                     # a maximal label of everything
])
def test_a_name_survives_a_trip_through_its_own_text_form(labels):
    original = Name(labels)
    assert Name.from_text(original.to_text()).labels == original.labels


@pytest.mark.parametrize("text,expected", [
    ("example.com.", (b"example", b"com")),
    ("example.com", (b"example", b"com")),
    ("a\\.b.com.", (b"a.b", b"com")),
    ("a\\\\b.com.", (b"a\\b", b"com")),
    ("a\\032b.com.", (b"a b", b"com")),
    ("\\046.com.", (b".", b"com")),             # \DDD naming the separator itself
    (".", ()),
    ("", ()),
])
def test_presentation_format_is_read_as_rfc_1035_defines_it(text, expected):
    assert Name.from_text(text).labels == expected


@pytest.mark.parametrize("text", [
    "a\\",                    # trailing backslash: was IndexError
    "a\\999",                 # \DDD out of range: was ValueError
    "a\\€",              # escaped non-latin-1: was ValueError
    "ünicode.com",       # non-ASCII: was UnicodeEncodeError
    "a..b",
    ".com",
    "x" * (MAX_LABEL + 1) + ".com",
    ".".join(["label"] * 60),  # over 255 octets
])
def test_every_way_a_name_can_be_rejected_is_a_wire_error(text):
    with pytest.raises(WireError):
        Name.from_text(text)


def test_a_non_ascii_digit_is_not_a_ddd_escape():
    """`str.isdigit` is true for these and `int` accepts them, so `\\٣٣٣` was
    decoded as the octet 333 — which then failed as a bare ValueError."""
    with pytest.raises(WireError):
        Name.from_text("a\\٣٣٣.com")
