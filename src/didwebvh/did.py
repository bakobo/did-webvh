"""didwebvh.did — the ``WebvhDid`` value type.

Parses ``did:webvh`` identifiers against the v1.0 spec's ``### Method-Specific Identifier`` ABNF
and derives the HTTPS locations defined in ``### The DID to HTTPS Transformation``. Pure value
type: no I/O, no network, no library state.

**Normalized versus raw.** :class:`WebvhDid` stores the normalized parse in its comparable fields
-- the domain as IDNA A-labels, lowercased; the port as an integer, so ``%3A`` and ``%3a`` stop
being different; path segments percent-decoded exactly once and case-sensitive as spec'd -- and
keeps the original input on :attr:`WebvhDid.raw` for diagnostics only, excluded from equality and
hashing. Never compare ``raw`` strings; compare :class:`WebvhDid` instances.

**Where the spec contradicts itself, and what this module does about it (~4lcd).** The ABNF says
``encoded-domain-label = 1*( ALPHA / DIGIT / "-" / pct-encoded )`` and ``webvh-path-segment =
1*idchar``, both of which are ASCII-only -- DID Core's ``idchar`` admits no character above
U+007F. The same section's worked example is ``did:webvh:{SCID}:jp納豆.例.jp:用户``, with raw
non-ASCII in both the domain and the path segment, and the transformation section gives its
expected HTTPS URL. The two cannot both be right. This module follows the example, because it is
the thing implementations are tested against and the thing the IDNA rules in step 3 presuppose:
raw non-ASCII is accepted in the domain and in path segments, and percent-encoded on the way into
a URL. The ABNF's ASCII-only productions are otherwise enforced exactly.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import quote, unquote

import idna

from didwebvh.errors import DID_INVALID

__all__ = ["WebvhDid", "parse"]

_PREFIX = "did:webvh:"

#: ``scid = 46(base58btc-char)``. The base58btc alphabet is the ASCII alphanumerics minus the four
#: characters that are confusable in print: ``0``, ``O``, ``I`` and ``l``.
_SCID_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{46}$")

#: ``encoded-domain-label``, before percent-decoding. Non-ASCII is admitted per the module note.
_DOMAIN_LABEL_RE = re.compile(r"^(?:[A-Za-z0-9\-]|%[0-9A-Fa-f]{2}|[^\x00-\x7F])+$")

#: DID Core's ``idchar``, before percent-decoding, plus non-ASCII per the module note.
_PATH_SEGMENT_RE = re.compile(r"^(?:[A-Za-z0-9._\-]|%[0-9A-Fa-f]{2}|[^\x00-\x7F])+$")

#: ``%3A`` or ``%3a`` followed by ``port-number = 1*5DIGIT`` at the very end of ``webvh-domain``.
_PORT_RE = re.compile(r"%3[Aa](\d{1,5})$")

#: Every spelling of the port separator, so "more than one" can be counted before parsing.
_PORT_SEPARATOR_RE = re.compile(r"%3[Aa]")

#: The characters that may appear unescaped in a URL path segment. Everything else, including the
#: ``%`` of an escape the DID itself carried, is percent-encoded with uppercase hex by ``quote``.
_PATH_SAFE = ""

@dataclass(frozen=True)
class WebvhDid:
    """One parsed ``did:webvh`` identifier.

    Attributes:
        scid: the self-certifying identifier, exactly as it appeared. base58btc is
            case-significant, so normalizing it would name a different DID.
        domain: the fully qualified domain, IDNA A-label encoded and lowercased.
        port: the port from a ``%3A`` separator, or None when the DID carried none.
        path: the method-specific deployment path, percent-decoded exactly once.
        raw: the input string. Diagnostics only -- excluded from equality and hashing.
    """

    scid: str
    domain: str
    port: int | None
    path: tuple[str, ...]
    raw: str = field(compare=False)

    @property
    def canonical(self) -> str:
        """This DID in the form a producer is required to emit.

        Differs from :attr:`raw` wherever the input was merely *acceptable*: a lowercase ``%3a``
        separator becomes ``%3A``, a mixed-case domain is lowercased, and an internationalized
        domain appears as A-labels.
        """
        domain = self.domain if self.port is None else f"{self.domain}%3A{self.port}"
        return ":".join((_PREFIX[:-1], self.scid, domain, *(_encode(s) for s in self.path)))

    @property
    def authority(self) -> str:
        """The HTTPS authority: the domain, and the port when one is present."""
        return self.domain if self.port is None else f"{self.domain}:{self.port}"

    def log_url(self) -> str:
        """Where this DID's ``did.jsonl`` is published and retrieved."""
        return f"https://{self.authority}/{'/'.join(self._url_parts())}/did.jsonl"

    def witness_url(self) -> str:
        """Where this DID's witness proofs live: the log URL, with the final file replaced."""
        return self.log_url().removesuffix("did.jsonl") + "did-witness.json"

    def artifact_parts(self) -> tuple[str, ...]:
        """The directories this DID's artifacts belong in, under a web root.

        The decoded segment rather than the encoded one, because a static file server
        percent-decodes a request path before it looks up a file. The domain and port address
        the server rather than the filesystem, so neither appears here.
        """
        return (".well-known",) if not self.path else self.path

    def _url_parts(self) -> tuple[str, ...]:
        return (".well-known",) if not self.path else tuple(_encode(s) for s in self.path)


def _encode(segment: str) -> str:
    """Percent-encode one path segment per RFC 3986, with uppercase hexadecimal digits."""
    return quote(segment, safe=_PATH_SAFE)


def _decode_once(text: str) -> str:
    """Percent-decode exactly once, refusing an escape whose bytes are not valid UTF-8.

    A *malformed* escape -- ``a%2``, ``a%ZZ`` -- cannot arrive here: ``_DOMAIN_LABEL_RE`` and
    ``_PATH_SEGMENT_RE`` both require every ``%`` to begin two hexadecimal digits, so the
    component is rejected before this is called. What can arrive is a well-formed escape for a
    byte sequence that is not UTF-8, such as ``a%FFb``, and ``errors="strict"`` is what refuses
    it rather than substituting a replacement character.
    """
    return unquote(text, errors="strict")


def _domain_and_port(component: str) -> tuple[str, int | None]:
    """Split ``webvh-domain`` into its validated domain and optional port."""
    separators = _PORT_SEPARATOR_RE.findall(component)
    if len(separators) > 1:
        raise ValueError("more than one percent-encoded port separator")

    port = None
    name = component
    if separators:
        match = _PORT_RE.search(component)
        if match is None:
            # A %3A that is not a port separator is a colon inside encoded-domain-name, which the
            # spec forbids outright -- so this is a refusal and not a name with a literal colon.
            raise ValueError("percent-encoded colon inside the domain name")
        port = int(match.group(1))
        if not 1 <= port <= 65535:
            raise ValueError(f"port {port} outside 1-65535")
        name = component[: match.start()]

    if not name:
        raise ValueError("empty domain")
    for label in name.split("."):
        if not _DOMAIN_LABEL_RE.match(label):
            raise ValueError(f"label {label!r} is not an encoded-domain-label")

    # "Validate all percent-encoding and percent-decode the component exactly once", then "apply
    # Unicode normalization and IDNA2008 processing" -- in that order, so an escape cannot smuggle
    # a character past the IDNA rules.
    decoded = unicodedata.normalize("NFC", _decode_once(name))
    domain = idna.encode(decoded, uts46=True).decode("ascii")

    if "." not in domain:
        raise ValueError("not a fully qualified domain name")
    _refuse_ip_address(domain)
    return domain, port


def _refuse_ip_address(domain: str) -> None:
    """Refuse anything a URL parser would read as an address rather than a name.

    Only the dotted-decimal form can reach this. An IPv6 literal cannot: its colons are the DID's
    own component delimiters, so ``[2001:db8::1]`` splits into a domain of ``[2001`` and path
    segments, and both ``[`` and ``]`` are outside ``encoded-domain-label`` anyway.

    For what does reach it, the test is the final label being all digits rather than a call to
    ``ipaddress``. ``ipaddress.ip_address`` *rejects* ``192.000.002.001`` as ambiguously
    zero-padded instead of parsing it, which is backwards here -- the spec names the
    non-canonical representation specifically. An all-digit final label catches both spellings,
    and cannot match a real TLD, which RFC 1123 forbids from being all-digit.
    """
    if domain.rsplit(".", 1)[-1].isdigit():
        raise ValueError("an IPv4 address, not a domain name")


def _path_segment(component: str) -> str:
    """Validate one ``webvh-path-segment`` and return its decoded value."""
    if not _PATH_SEGMENT_RE.match(component):
        raise ValueError(f"path segment {component!r} is not 1*idchar")
    decoded = _decode_once(component)
    if decoded in (".", ".."):
        raise ValueError("path segment is `.` or `..`")
    if {"/", "\\", "\x00"} & set(decoded):
        raise ValueError("path segment contains `/`, a backslash, or U+0000")
    if decoded != decoded.strip():
        raise ValueError("path segment begins or ends with whitespace")
    return decoded


def parse(raw: str) -> WebvhDid:
    """Parse ``raw`` into a :class:`WebvhDid`.

    Args:
        raw: the candidate identifier.

    Returns:
        The parsed, normalized DID.

    Raises:
        bakobo.errors.BakoboError: carrying :data:`~didwebvh.errors.DID_INVALID`, for every way a
            string can fail to be a ``did:webvh`` DID. One code, deliberately: an operator acts on
            "this is not a valid identifier", and the specific rule is in the message.
    """
    if not isinstance(raw, str) or not raw.startswith(_PREFIX):
        raise DID_INVALID(did=raw)

    try:
        # A DID URL's path, query and fragment "MUST be separated from the DID before this
        # transformation is applied" -- so a DID carrying one is not a DID, and this is the only
        # place their delimiters can appear unescaped.
        if set("/?#") & set(raw):
            raise ValueError("a DID URL path, query or fragment is not part of the DID")

        components = raw[len(_PREFIX) :].split(":")
        if len(components) < 2:
            raise ValueError("expected at least an scid and a domain")

        scid, domain_component, *path_components = components
        if not _SCID_RE.match(scid):
            raise ValueError(f"scid {scid!r} is not 46 base58btc characters")

        domain, port = _domain_and_port(domain_component)
        path = tuple(_path_segment(component) for component in path_components)
    except (ValueError, UnicodeError, idna.IDNAError) as exc:
        raise DID_INVALID(did=raw) from exc

    return WebvhDid(scid=scid, domain=domain, port=port, path=path, raw=raw)
