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
        s = s.strip()
        if s in (".", ""):
            return cls(())
        if s.endswith("."):
            s = s[:-1]
        labels = []
        for part in s.split("."):
            b = _unescape(part)
            if not 1 <= len(b) <= MAX_LABEL:
                raise WireError(f"bad label length in {s!r}")
            labels.append(b)
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


def _escape(label: bytes) -> str:
    out = []
    for c in label:
        if c in (0x2E, 0x5C):  # . \
            out.append("\\" + chr(c))
        elif 0x21 <= c <= 0x7E:
            out.append(chr(c))
        else:
            out.append(f"\\{c:03d}")
    return "".join(out)


def _unescape(part: str) -> bytes:
    if "\\" not in part:
        return part.encode("ascii", "strict")
    out = bytearray()
    i = 0
    while i < len(part):
        c = part[i]
        if c == "\\":
            if i + 3 < len(part) + 1 and part[i + 1:i + 4].isdigit():
                out.append(int(part[i + 1:i + 4]))
                i += 4
            else:
                out.append(ord(part[i + 1]))
                i += 2
        else:
            out.append(ord(c))
            i += 1
    return bytes(out)


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
