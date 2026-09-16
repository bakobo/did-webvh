"""The ``did:webvh`` identifier, and the HTTPS location it transforms to.

Every case here cites a rule in the v1.0 spec's ``### Method-Specific Identifier`` or
``### The DID to HTTPS Transformation``. Where the spec gives a worked example, the example is
the test -- including the internationalized one, which is the only place the IDNA and
percent-encoding rules are exercised together against an answer somebody else computed.
"""

from __future__ import annotations

import pytest
from bakobo.errors import BakoboError

from webvh_gate import did as did_module
from webvh_gate.did import WebvhDid, parse

# A conforming SCID: exactly 46 base58btc characters. This one was minted by the pinned
# didwebvh-py during recon, so it is a real SHA-256 multihash and not a plausible-looking string.
SCID = "QmaigaGjpv2GNnN5D2tyd1XZLY8PnRTDtgHYCiV964ooMn"


def test_the_scid_constant_is_what_the_abnf_describes():
    """Guards the fixture itself: a wrong-length SCID would make every case below vacuous."""
    assert len(SCID) == 46
    assert not set(SCID) & set("0OIl")


class TestAccepts:
    """The four conforming forms the spec lists, plus the internationalized example."""

    def test_bare_domain(self):
        parsed = parse(f"did:webvh:{SCID}:example.com")
        assert parsed.scid == SCID
        assert parsed.domain == "example.com"
        assert parsed.port is None
        assert parsed.path == ()

    def test_subdomain(self):
        assert parse(f"did:webvh:{SCID}:issuer.example.com").domain == "issuer.example.com"

    def test_path_segments(self):
        parsed = parse(f"did:webvh:{SCID}:example.com:dids:issuer")
        assert parsed.domain == "example.com"
        assert parsed.path == ("dids", "issuer")

    def test_percent_encoded_port(self):
        parsed = parse(f"did:webvh:{SCID}:example.com%3A3000:dids:issuer")
        assert parsed.domain == "example.com"
        assert parsed.port == 3000
        assert parsed.path == ("dids", "issuer")

    def test_lowercase_percent_encoded_port_is_accepted(self):
        """ABNF strings are case-insensitive, so %3a parses; only *producing* it is forbidden."""
        assert parse(f"did:webvh:{SCID}:example.com%3a3000").port == 3000

    def test_port_bounds(self):
        assert parse(f"did:webvh:{SCID}:example.com%3A1").port == 1
        assert parse(f"did:webvh:{SCID}:example.com%3A65535").port == 65535

    def test_internationalized_domain_and_path(self):
        """The spec's own worked example, IDNA A-labels and all."""
        parsed = parse(f"did:webvh:{SCID}:jp納豆.例.jp:用户")
        assert parsed.domain == "xn--jp-cd2fp15c.xn--fsq.jp"
        assert parsed.path == ("用户",)

    def test_percent_encoded_path_segment_is_decoded_exactly_once(self):
        """`%25` decodes to a literal `%`, and is not decoded again into something else."""
        assert parse(f"did:webvh:{SCID}:example.com:a%2525b").path == ("a%25b",)


class TestRejects:
    """Every refusal carries the DID_INVALID code; the message names the identifier."""

    @pytest.mark.parametrize(
        ("bad", "because"),
        [
            ("", "empty string"),
            ("did:web:example.com", "a different method"),
            ("did:webvh:", "no method-specific id at all"),
            (f"did:webvh:{SCID}", "scid but no domain"),
            (f"did:webvh:{SCID}:", "empty domain component"),
            (f"did:webvh:{'Q' * 45}:example.com", "scid one character short"),
            (f"did:webvh:{'Q' * 47}:example.com", "scid one character long"),
            (f"did:webvh:{'0' * 46}:example.com", "scid outside the base58btc alphabet"),
            ("did:webvh:{SCID}:example.com", "the literal placeholder, never a conforming scid"),
            (f"did:webvh:{SCID}:example.com:", "trailing empty path segment"),
            (f"did:webvh:{SCID}:example.com::a", "empty interior path segment"),
            (f"did:webvh:{SCID}:example.com:.", "path segment `.`"),
            (f"did:webvh:{SCID}:example.com:..", "path segment `..`"),
            (f"did:webvh:{SCID}:example.com:%2E%2E", "`..` hidden behind percent-encoding"),
            (f"did:webvh:{SCID}:example.com:a%2Fb", "decoded path segment containing `/`"),
            (f"did:webvh:{SCID}:example.com:a%5Cb", "decoded path segment containing a backslash"),
            (f"did:webvh:{SCID}:example.com:a%00b", "decoded path segment containing U+0000"),
            (f"did:webvh:{SCID}:example.com:%20a", "path segment with leading whitespace"),
            (f"did:webvh:{SCID}:example.com:a%20", "path segment with trailing whitespace"),
            (f"did:webvh:{SCID}:example.com:a%2", "truncated percent-escape in a path segment"),
            (f"did:webvh:{SCID}:example.com:a%ZZ", "non-hex percent-escape in a path segment"),
            (f"did:webvh:{SCID}:example.com:a%FFb", "a well-formed escape whose bytes are not UTF-8"),
            (f"did:webvh:{SCID}:exa%FFmple.com", "the same, in the domain component"),
            (f"did:webvh:{SCID}:exa%3Ample.com", "percent-encoded colon inside the domain"),
            (f"did:webvh:{SCID}:example.com%3A0", "port zero"),
            (f"did:webvh:{SCID}:example.com%3A65536", "port above 65535"),
            (f"did:webvh:{SCID}:example.com%3A123456", "port of six digits"),
            (f"did:webvh:{SCID}:example.com%3A", "port separator with no number"),
            (f"did:webvh:{SCID}:example.com%3A80%3A81", "two port separators"),
            (f"did:webvh:{SCID}:192.0.2.1", "an IPv4 address"),
            (f"did:webvh:{SCID}:192.000.002.001", "an IPv4 address in non-canonical form"),
            (f"did:webvh:{SCID}:[2001:db8::1]", "an IPv6 address"),
            (f"did:webvh:{SCID}:localhost", "a single-label name, not fully qualified"),
            (f"did:webvh:{SCID}:exa_mple.com", "an underscore, outside encoded-domain-label"),
            (f"did:webvh:{SCID}:-example.com", "a label beginning with a hyphen"),
            (f"did:webvh:{SCID}:example-.com", "a label ending with a hyphen"),
            (f"did:webvh:{SCID}:example..com", "an empty label"),
            (f"did:webvh:{SCID}:{'a' * 64}.com", "a label of 64 octets"),
            (f"did:webvh:{SCID}:{('a' * 63 + '.') * 5}com", "a name past the DNS length limit"),
            (f"did:webvh:{SCID}:example.com/whois", "a DID URL path, which is not part of the DID"),
            (f"did:webvh:{SCID}:example.com?x=1", "a DID URL query"),
            (f"did:webvh:{SCID}:example.com#key-1", "a DID URL fragment"),
        ],
    )
    def test_refused(self, bad, because):
        with pytest.raises(BakoboError) as raised:
            parse(bad)
        assert raised.value.code == "e.input.format.did-webvh.f", because

    def test_a_label_of_exactly_63_octets_is_accepted(self):
        """The boundary the case above sits one octet past, so the limit is proven, not assumed."""
        assert parse(f"did:webvh:{SCID}:{'a' * 63}.com").domain == f"{'a' * 63}.com"


class TestNormalization:
    """What is compared, and what is only kept for the error message."""

    def test_domain_case_is_normalized(self):
        assert parse(f"did:webvh:{SCID}:EXAMPLE.COM").domain == "example.com"

    def test_path_segments_stay_case_sensitive(self):
        assert parse(f"did:webvh:{SCID}:example.com:Dids").path == ("Dids",)

    def test_scid_stays_case_sensitive(self):
        """base58btc is case-significant; lowercasing an SCID would change which DID this is."""
        assert parse(f"did:webvh:{SCID}:example.com").scid == SCID

    def test_raw_is_preserved_but_excluded_from_equality(self):
        upper = parse(f"did:webvh:{SCID}:EXAMPLE.com%3a3000")
        lower = parse(f"did:webvh:{SCID}:example.com%3A3000")
        assert upper == lower
        assert hash(upper) == hash(lower)
        assert upper.raw != lower.raw
        assert upper.raw == f"did:webvh:{SCID}:EXAMPLE.com%3a3000"

    def test_canonical_uses_the_uppercase_port_separator(self):
        """Producers MUST use %3A; we accepted %3a on the way in and emit %3A on the way out."""
        assert parse(f"did:webvh:{SCID}:example.com%3a3000").canonical == (
            f"did:webvh:{SCID}:example.com%3A3000"
        )

    def test_canonical_round_trips(self):
        for text in (
            f"did:webvh:{SCID}:example.com",
            f"did:webvh:{SCID}:example.com%3A3000",
            f"did:webvh:{SCID}:example.com:dids:issuer",
            f"did:webvh:{SCID}:example.com%3A3000:dids:issuer",
        ):
            assert parse(parse(text).canonical).canonical == text


class TestHttpsTransformation:
    """The spec's worked examples, verbatim."""

    @pytest.mark.parametrize(
        ("did", "url"),
        [
            (f"did:webvh:{SCID}:example.com", "https://example.com/.well-known/did.jsonl"),
            (
                f"did:webvh:{SCID}:issuer.example.com",
                "https://issuer.example.com/.well-known/did.jsonl",
            ),
            (
                f"did:webvh:{SCID}:example.com:dids:issuer",
                "https://example.com/dids/issuer/did.jsonl",
            ),
            (
                f"did:webvh:{SCID}:example.com%3A3000:dids:issuer",
                "https://example.com:3000/dids/issuer/did.jsonl",
            ),
            (
                f"did:webvh:{SCID}:jp納豆.例.jp:用户",
                "https://xn--jp-cd2fp15c.xn--fsq.jp/%E7%94%A8%E6%88%B7/did.jsonl",
            ),
        ],
    )
    def test_log_url(self, did, url):
        assert parse(did).log_url() == url

    def test_well_known_appears_only_when_there_is_no_path(self):
        assert ".well-known" not in parse(f"did:webvh:{SCID}:example.com:dids").log_url()

    def test_witness_url_replaces_the_final_file(self):
        parsed = parse(f"did:webvh:{SCID}:example.com:dids")
        assert parsed.witness_url() == "https://example.com/dids/did-witness.json"
        assert parsed.log_url().removesuffix("did.jsonl") == parsed.witness_url().removesuffix(
            "did-witness.json"
        )

    def test_percent_encoding_uses_uppercase_hex(self):
        """RFC 3986 permits either case; the transformation step pins uppercase."""
        assert "%E7%94%A8" in parse(f"did:webvh:{SCID}:example.com:用户").log_url()


class TestBaseUrl:
    """What the implicit services hang off, which is not where the log lives."""

    @pytest.mark.parametrize(
        ("did", "base"),
        [
            (f"did:webvh:{SCID}:example.com", "https://example.com/"),
            (f"did:webvh:{SCID}:example.com%3A3000", "https://example.com:3000/"),
            (f"did:webvh:{SCID}:example.com:dids:issuer", "https://example.com/dids/issuer/"),
            (f"did:webvh:{SCID}:jp\u7d0d\u8c46.\u4f8b.jp:\u7528\u6237", "https://xn--jp-cd2fp15c.xn--fsq.jp/%E7%94%A8%E6%88%B7/"),
        ],
    )
    def test_base_url(self, did, base):
        assert parse(did).base_url() == base

    def test_well_known_never_appears_in_the_base(self):
        """The log is under .well-known for a bare-domain DID; its files are not."""
        parsed = parse(f"did:webvh:{SCID}:example.com")
        assert ".well-known" in parsed.log_url()
        assert ".well-known" not in parsed.base_url()

    def test_the_base_always_ends_in_a_slash(self):
        for did in (f"did:webvh:{SCID}:example.com", f"did:webvh:{SCID}:example.com:a:b"):
            assert parse(did).base_url().endswith("/")


class TestArtifactLocation:
    """Where the files land under the directory an operator names, as opposed to in a URL."""

    def test_no_path_means_well_known(self):
        assert parse(f"did:webvh:{SCID}:example.com").artifact_parts() == (".well-known",)

    def test_path_segments_become_directories(self):
        assert parse(f"did:webvh:{SCID}:example.com:dids:issuer").artifact_parts() == (
            "dids",
            "issuer",
        )

    def test_the_host_and_port_address_the_server_not_the_filesystem(self):
        with_port = parse(f"did:webvh:{SCID}:example.com%3A3000:dids")
        without = parse(f"did:webvh:{SCID}:other.example.org:dids")
        assert with_port.artifact_parts() == without.artifact_parts() == ("dids",)

    def test_directories_are_the_decoded_segment_not_the_encoded_one(self):
        """A static server percent-decodes the request path before it looks up a file."""
        assert parse(f"did:webvh:{SCID}:example.com:用户").artifact_parts() == (
            "用户",
        )


class TestModuleSurface:
    def test_exports_are_what_the_module_says_they_are(self):
        assert set(did_module.__all__) == {"WebvhDid", "parse"}

    def test_parse_returns_the_value_type(self):
        assert isinstance(parse(f"did:webvh:{SCID}:example.com"), WebvhDid)
