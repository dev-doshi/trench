"""Domain names: case-insensitive comparison, compression on the wire,
canonical (lowercase) form for DNSSEC."""
from __future__ import annotations

from ..errors import WireError
from .reader import Reader
from .writer import Writer

MAX_NAME = 255
MAX_LABEL = 63
_MAX_POINTER_HOPS = 128


class Name:
    """A domain name as a tuple of label byte-strings (root = empty tuple).

    Equality and hashing are case-insensitive (DNS names are); the original
    label case is preserved for 0x20 query-name randomization.

    Everything below `labels` is a memoized derivation rather than state — a
    Name is immutable, so the first caller pays and the rest do not. Nothing is
    computed in `__init__`, because most names parsed out of a message are only
    ever carried: a response's records are copied around, and only a few of
    their names are ever hashed, compared or printed. Building the lowercase
    form for all of them up front was work done on speculation.

    `key` — the lowercased wire form — is the single notion of identity here.
    Equality, hashing and subdomain tests all reduce to it, which is both
    faster than comparing label tuples and exactly right: every label is
    length-prefixed, so one key can only occur inside another at a label
    boundary.
    """
    __slots__ = ("labels", "_low", "_text", "_key")

    def __init__(self, labels: tuple[bytes, ...]):
        self.labels = labels
        self._low: tuple[bytes, ...] | None = None
        self._text: str | None = None
        self._key: bytes | None = None

    @property
    def _lower(self) -> tuple[bytes, ...]:
        low = self._low
        if low is None:
            low = self._low = tuple(la.lower() for la in self.labels)
        return low

    # --- text ---
    @classmethod
    def from_text(cls, s: str) -> Name:
        """Parse presentation format (RFC 1035 §5.1). Raises WireError.

        Note the escapes: a label may contain any octet, and the text form
        spells the awkward ones `\\.`, `\\\\` and `\\DDD`. So the dots that
        separate labels are only the *unescaped* ones — splitting on every dot
        cut a name in half at the `\\.` that means a literal dot inside a
        label, which `to_text` emits and the wire carries perfectly legally, and
        then handed the unescaper a fragment ending in a lone backslash.
        `Name.from_text(name.to_text())` raised IndexError for any such name.
        """
        s = s.strip()
        if s in (".", ""):
            return cls(())
        if "\\" in s:
            labels = _labels_from_text(s)
        else:
            # No escapes: the overwhelming majority of names, and splitting is
            # then exactly equivalent.
            if s.endswith("."):
                s = s[:-1]
            try:
                labels = [part.encode("ascii", "strict") for part in s.split(".")]
            except UnicodeEncodeError as e:
                # An IDN has to reach here already punycoded. Raised bare, this
                # was the one failure of `from_text` that was not a WireError.
                raise WireError(f"non-ASCII character in {s!r}") from e
        for b in labels:
            if not 1 <= len(b) <= MAX_LABEL:
                raise WireError(f"bad label length in {s!r}")
        n = cls(tuple(labels))
        if n.wire_len() > MAX_NAME:
            raise WireError("name too long")
        return n

    def to_text(self, omit_root: bool = False) -> str:
        if omit_root:
            return "" if not self.labels else ".".join(_escape(la) for la in self.labels)
        text = self._text
        if text is None:
            text = self._text = (
                "." if not self.labels
                else ".".join(_escape(la) for la in self.labels) + ".")
        return text

    @property
    def key(self) -> bytes:
        """Lowercased wire form: the canonical identity of this name.

        What a cache key, a blocklist lookup or a filter match actually needs
        is a comparable token, not a human-readable string. This is that token
        without the per-byte escaping trip through Unicode — and because it is
        a single `bytes`, hashing it costs one hash rather than one per label.
        """
        k = self._key
        if k is None:
            buf = bytearray()
            for la in self.labels:
                buf.append(len(la))
                buf += la.lower()
            buf.append(0)
            k = self._key = bytes(buf)
        return k

    # --- relationships ---
    def is_root(self) -> bool:
        return len(self.labels) == 0

    def parent(self) -> Name:
        return Name(self.labels[1:])

    def is_subdomain_of(self, other: Name) -> bool:
        # Length-prefixed labels make a byte-suffix test exact: `ample.com`
        # cannot match inside `example.com`, because the octet preceding
        # "ample" there is 'x', not the length 5 the key would require.
        return self.key.endswith(other.key)

    def canonicalize(self) -> Name:
        """Lowercase form, used when computing/verifying DNSSEC signatures."""
        return Name(self._lower)

    def wire_len(self) -> int:
        return sum(len(la) + 1 for la in self.labels) + 1

    # --- dunder ---
    def __eq__(self, other: object) -> bool:
        return isinstance(other, Name) and self.key == other.key

    def __hash__(self) -> int:
        return hash(self.key)

    def __len__(self) -> int:
        return len(self.labels)

    def __repr__(self) -> str:
        return f"Name({self.to_text()!r})"


def wire_key(text: str) -> bytes:
    """The lowercased wire form of a name given as text — `Name.key` without
    building a Name. Suffix containment in this encoding is exact: every label
    is length-prefixed, so a shorter key can only match at a label boundary."""
    return Name.from_text(text).key


#: Every octet a label may carry verbatim: printable ASCII except `.` and `\`,
#: which have to be escaped. Used as a `bytes.translate` delete-set — see
#: `_escape`.
_SAFE_OCTETS = bytes(c for c in range(0x21, 0x7F) if c not in (0x2E, 0x5C))


def _escape(label: bytes) -> str:
    # Almost every label in real traffic is plain ASCII with nothing to escape,
    # and this is on the query path: `ctx.qname` renders the question name, and
    # the per-byte loop below was 15% of the whole object pipeline — a Python
    # list append and a `chr` call for each octet of each label. Deleting the
    # safe octets and asking whether anything is left answers "does this label
    # need escaping at all?" in one C call, and the decode is a second one.
    if not label.translate(None, _SAFE_OCTETS):
        return label.decode("ascii")
    out = []
    for c in label:
        if c in (0x2E, 0x5C):  # . \
            out.append("\\" + chr(c))
        elif 0x21 <= c <= 0x7E:
            out.append(chr(c))
        else:
            out.append(f"\\{c:03d}")
    return "".join(out)


def _labels_from_text(s: str) -> list[bytes]:
    """Split on unescaped dots and unescape, in one pass.

    One pass because the two steps are not separable: which dots are separators
    is itself a fact about the escaping. Every way out of here that is not a
    label is a `WireError`, because that is what `from_text` promises and its
    callers catch — a trailing backslash used to raise IndexError and `\\999`
    a bare ValueError, and both reached the blocklist parser, the zone-file
    parser and the DoH JSON endpoint from input none of them chose.
    """
    labels: list[bytes] = []
    cur = bytearray()
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == ".":
            labels.append(bytes(cur))
            cur.clear()
            i += 1
        elif c != "\\":
            o = ord(c)
            if o > 0xFF:
                raise WireError(f"non-latin-1 character in {s!r}")
            cur.append(o)
            i += 1
        elif i + 1 >= n:
            raise WireError(f"trailing backslash in {s!r}")
        elif _is_ddd(s, i + 1):
            v = int(s[i + 1:i + 4])
            if v > 0xFF:
                raise WireError(f"escape \\{s[i + 1:i + 4]} out of range in {s!r}")
            cur.append(v)
            i += 4
        else:
            o = ord(s[i + 1])
            if o > 0xFF:
                raise WireError(f"non-latin-1 character in {s!r}")
            cur.append(o)
            i += 2
    labels.append(bytes(cur))
    if len(labels) > 1 and labels[-1] == b"":
        labels.pop()                    # the root dot that ends a fully qualified name
    return labels


def _is_ddd(s: str, i: int) -> bool:
    """True for exactly three ASCII digits at `i` — the `\\DDD` escape.

    `str.isdigit` is not that test: it is true for non-ASCII digits too, and
    `int` accepts them, so `\\٣٣٣` decoded as the octet 333.
    """
    return i + 3 <= len(s) and all("0" <= ch <= "9" for ch in s[i:i + 3])


def read_name(r: Reader) -> Name:
    """Read a (possibly compressed) name, following pointers. Fuzz-safe:
    bounded hops, total-length cap, restores cursor after the first pointer."""
    labels: list[bytes] = []
    hops = 0
    total = 1  # the final root octet
    resume: int | None = None
    while True:
        length = r.u8()
        kind = length & 0xC0
        if length == 0:
            break
        if kind == 0x00:
            label = r.read(length)
            total += length + 1
            if total > MAX_NAME:
                raise WireError("name exceeds 255 octets")
            labels.append(label)
        elif kind == 0xC0:
            hops += 1
            if hops > _MAX_POINTER_HOPS:
                raise WireError("compression pointer loop")
            ptr = ((length & 0x3F) << 8) | r.u8()
            if resume is None:
                resume = r.tell()
            if ptr >= r.tell() - 2:
                # pointers must reference earlier data; forward/self ptr = loop bait
                raise WireError("forward compression pointer")
            r.seek(ptr)
        else:
            raise WireError("reserved label type")
    if resume is not None:
        r.seek(resume)
    return Name(tuple(labels))


def suffixes(qname: str) -> list[str]:
    """Every parent suffix of a name, longest first, lowercased and dot-free.

    `a.b.example` -> `["a.b.example", "b.example", "example"]`.

    Five places walked a name's suffixes and four of them hand-rolled the same
    `labels = name.split("."); ".".join(labels[i:])` loop — the filter engine,
    the upstream router, the blocked-services matcher, safe browsing and the
    silence ledger. `FilterEngine.suffixes` had already been extracted from
    three copies *inside one file*; this is that extraction finished. Slicing
    the string rather than joining label lists also skips a list build and a
    join per label, which matters on the query path.
    """
    name = qname.rstrip(".").lower()
    if not name:
        return []
    out = [name]
    cut = name.find(".")
    while cut != -1:
        out.append(name[cut + 1:])
        cut = name.find(".", cut + 1)
    return out


def write_name(w: Writer, name: Name, compress: bool = True) -> None:
    labels = name.labels
    # The compression table is keyed on suffixes of the lowercased wire form.
    # Slicing that one bytes object is cheaper than slicing a tuple of labels,
    # and a bytes hashes once instead of once per element.
    key = name.key if compress else b""
    pos = 0
    for label in labels:
        if compress:
            off = w.names.get(key[pos:])
            if off is not None:
                w.u16(0xC000 | off)
                return
            here = w.tell()
            if here <= 0x3FFF:
                w.names[key[pos:]] = here
            pos += len(label) + 1
        w.u8(len(label))
        w.raw(label)
    w.u8(0)
