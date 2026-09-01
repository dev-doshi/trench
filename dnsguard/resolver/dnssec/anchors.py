"""Root trust anchors read from a file, instead of only the compiled-in pins.

`chain.ROOT_ANCHORS` holds the IANA KSKs known when this version was built, and
they are correct until the root key rolls. What a resolver cannot do is wait for
a software release at that moment: every operator with a package-managed
`root.key` — the file BIND and Unbound already maintain, and the one an offline
box gets by hand — should be able to point at it and be current.

Two formats are accepted, because those are the two an operator already has:

  * presentation-format DS records, as published by IANA and as `dig . DS`
    prints them:  `.  IN DS 20326 8 2 E06D...`
  * BIND's `trust-anchors` / `managed-keys` blocks, whose entries are
    `. initial-ds 20326 8 2 "E06D...";` or `. initial-key 257 3 8 "AwEAA...";`
    (`static-` variants likewise). A key entry is converted to a DS here, which
    is what the validator compares against.

Anything unparseable is skipped with a warning rather than failing the load: a
file with one bad line and three good anchors should start the resolver, and a
file with *no* usable anchors is reported to the caller so it can keep the pins
rather than validating against nothing.
"""
from __future__ import annotations

import base64
import re
from pathlib import Path

from ...log import get
from ...wire import rdata as R
from ...wire.name import Name
from .keys import ds_digest, key_tag

log = get("dnssec.anchors")

ROOT = Name.from_text(".")

#: Digest type used when converting a DNSKEY anchor to a DS. SHA-256 is what the
#: root's own DS uses and the only digest every validator here supports.
_DS_DIGEST_TYPE = 2

_DS_LINE = re.compile(
    r"""^\s*(?P<owner>\S*)\s*                   # owner: must be the root
        (?:\d+\s+)?                            # optional TTL
        (?:IN\s+)?DS\s+                        # class is optional in the wild
        (?P<tag>\d+)\s+(?P<alg>\d+)\s+(?P<dtype>\d+)\s+
        (?P<digest>[0-9A-Fa-f\s]+)$""",
    re.IGNORECASE | re.VERBOSE,
)

#: The only owner accepted. Anything else in an anchor file is an anchor for
#: some *other* zone, and installing it here would let whoever holds that key
#: sign the root — and from the root, every name. The BIND-block branch always
#: checked this; the presentation-format branch did not.
#:
#: Written out rather than inferred: a zone file lets a line with no owner
#: inherit the previous record's, and guessing that an unqualified line "is
#: probably still the root" is exactly the assumption that must not be made
#: here. IANA's published anchors and `dig . DS` both write the dot.
_ROOT_OWNERS = frozenset({"."})

_BIND_ENTRY = re.compile(
    r"""(?P<owner>\S+)\s+
        (?:initial|static)-(?P<kind>ds|key)\s+
        (?P<rest>[^;]+);""",
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)


def _ds_from_fields(tag: str, alg: str, dtype: str, digest_hex: str) -> R.DS | None:
    digest = bytes.fromhex(re.sub(r"[\s\"']", "", digest_hex))
    if not digest:
        return None
    return R.DS(key_tag=int(tag), algorithm=int(alg), digest_type=int(dtype),
                digest=digest)


#: DNSKEY flag bits (RFC 4034 §2.1.1, RFC 5011 §3).
_ZONE_KEY, _REVOKE, _SEP = 0x0100, 0x0080, 0x0001


def _ds_from_key(flags: str, protocol: str, alg: str, key_b64: str) -> R.DS | None:
    """A root DS derived from a DNSKEY anchor, or None if the key is unusable.

    The flags are not decoration. A revoked key (RFC 5011) is one the root has
    withdrawn, and a key without the zone bit cannot sign a zone at all — either
    one silently converted into a trust anchor is an anchor that should not
    exist. `validate=True` on the base64 for the same reason: a corrupted line
    would otherwise decode to different bytes and produce a confidently wrong
    anchor rather than the skip-with-warning this module promises.
    """
    raw = base64.b64decode(re.sub(r"[\s\"']", "", key_b64), validate=True)
    bits = int(flags)
    if bits & _REVOKE:
        log.warning("ignoring a revoked DNSKEY in the trust anchor file")
        return None
    if not bits & _ZONE_KEY:
        log.warning("ignoring a non-zone DNSKEY (flags %d) in the trust anchor "
                    "file", bits)
        return None
    if not bits & _SEP:
        # Not fatal — the SEP bit is a hint, not a rule — but an anchor that is
        # not a key-signing key is unusual enough to say so.
        log.info("trust anchor DNSKEY %d has no SEP bit set", bits)
    dnskey = R.DNSKEY(flags=bits, protocol=int(protocol),
                      algorithm=int(alg), public_key=raw)
    return R.DS(key_tag=key_tag(dnskey), algorithm=int(alg),
                digest_type=_DS_DIGEST_TYPE,
                digest=ds_digest(ROOT, dnskey, _DS_DIGEST_TYPE))


def parse_anchors(text: str) -> list[R.DS]:
    """Every root DS the text yields, in file order, deduplicated."""
    out: list[R.DS] = []
    seen: set[tuple] = set()

    def keep(ds: R.DS | None) -> None:
        if ds is None:
            return
        ident = (ds.key_tag, ds.algorithm, ds.digest_type, bytes(ds.digest))
        if ident not in seen:
            seen.add(ident)
            out.append(ds)

    # BIND blocks first: their bodies also contain the word DS, so running the
    # line matcher over them as well would double-count every anchor.
    consumed: list[tuple[int, int]] = []
    for m in _BIND_ENTRY.finditer(text):
        owner = m.group("owner").strip('"')
        if owner not in (".", ""):
            continue                      # anchors for other zones are not ours
        fields = m.group("rest").replace('"', " ").split()
        try:
            if m.group("kind").lower() == "ds" and len(fields) >= 4:
                keep(_ds_from_fields(fields[0], fields[1], fields[2],
                                     "".join(fields[3:])))
            elif len(fields) >= 4:
                keep(_ds_from_key(fields[0], fields[1], fields[2],
                                  "".join(fields[3:])))
        except Exception as e:
            log.warning("skipping unreadable trust anchor entry: %s", e)
        consumed.append(m.span())

    offset = 0
    for lineno, line in enumerate(text.splitlines(True), 1):
        start, offset = offset, offset + len(line)
        if any(a <= start < b for a, b in consumed):
            continue                      # already taken by a BIND block above
        line = line.split(";")[0].strip()
        if not line or line.startswith("#"):
            continue
        found = _DS_LINE.match(line)
        if not found:
            continue
        owner = found.group("owner").strip('"').lower()
        if owner not in _ROOT_OWNERS:
            log.warning("trust anchor file line %d is for %s, not the root; "
                        "ignoring it", lineno, owner)
            continue
        try:
            keep(_ds_from_fields(found.group("tag"), found.group("alg"),
                                 found.group("dtype"), found.group("digest")))
        except Exception as e:
            log.warning("trust anchor file line %d is unreadable: %s", lineno, e)
    return out


def load_anchors(path: str | Path) -> list[R.DS]:
    """Anchors from `path`, or an empty list if it is missing or yields none.

    Never raises: an unreadable anchor file must not stop the resolver from
    starting, because the compiled-in pins are still a correct answer. The
    caller logs which set it ended up using.
    """
    p = Path(path).expanduser()
    if not p.exists():
        return []
    try:
        anchors = parse_anchors(p.read_text())
    except Exception:
        log.exception("could not read trust anchors from %s", p)
        return []
    if not anchors:
        log.warning("no usable trust anchors in %s", p)
    return anchors
