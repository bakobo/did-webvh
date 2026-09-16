"""The conformance oracle: logs this stack did not mint, verified by this stack.

Every other test in this suite mints with `did_webvh` and verifies with `did_webvh`. That is a
closed round-trip — it proves the pinned library agrees with itself, and would keep passing if its
canonicalization drifted away from every other implementation (this.i cx2fyuyz, panel finding
ARC-F1). SCIDs, entry hashes and proof hashes are all computed over JCS output, so a drift there
does not raise an error; it mints DIDs nobody else can read.

These vectors close that loop. They come from DIF's `didwebvh-test-suite`, pinned by commit in
`vectors/MANIFEST.json`, and carry per-implementation artifacts from **Rust, TypeScript, Java and
Dart** alongside Python. Each positive case asserts that a log minted by one of those independent
implementations verifies here and resolves to the document that implementation recorded. If our
canonicalization ever stops matching theirs, their SCIDs stop recomputing under our hashing and
these tests go red — which is the entire point, and is what a pin bump needs to run against.

**The Python artifacts are used but prove less**, and are marked so. They come from the very
library this package depends on, so they are a regression check rather than an oracle. The
independence claim rests on `_INDEPENDENT`, and a test below fails if that set ever empties.

Fixtures are checked in rather than fetched, so CI needs no network, no Node and no JVM.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest
from bakobo.errors import BakoboError

from webvh_gate import clamp, publish, verify
from webvh_gate.did import parse

VECTORS = pathlib.Path(__file__).parent / "vectors"
MANIFEST = json.loads((VECTORS / "MANIFEST.json").read_text())

#: Implementations that are not the library we depend on. Only these make a vector an oracle.
_INDEPENDENT = ("rust", "ts", "java", "java-eecc", "dart")


#: A conforming SCID, substituted into the suite's DID-syntax vectors. Theirs are `Qm000...`,
#: which is not base58btc (`0` is outside the alphabet), so our parser would refuse every one of
#: them on the SCID alone and never reach the rule the vector is actually about. Swapping in a
#: real SCID is what stops that test passing vacuously.
_REAL_SCID = "QmaigaGjpv2GNnN5D2tyd1XZLY8PnRTDtgHYCiV964ooMn"


def adversarial_dids() -> list[str]:
    """Every DID the suite's negative vectors say must be rejected, with a usable SCID."""
    found = set()
    for script in sorted(VECTORS.glob("negative-*/script.yaml")):
        for did in re.findall(r'did:\s*"([^"]+)"', script.read_text()):
            found.add(re.sub(r"(?<=did:webvh:)[^:]+", _REAL_SCID, did, count=1))
    return sorted(found)


def has_log(case: str, impl: str) -> bool:
    """Some negative vectors are about DID syntax and ship a placeholder log."""
    path = VECTORS / case / impl / "did.jsonl"
    return path.exists() and len(path.read_bytes().strip()) > 0


def cases(*, negative: bool) -> list[tuple[str, str]]:
    """Every (case, implementation) pair of the requested polarity."""
    return [
        (name, impl)
        for name, case in sorted(MANIFEST["cases"].items())
        if case["negative"] is negative
        for impl in case["implementations"]
        if has_log(name, impl)
    ]


def load(case: str, impl: str) -> bytes:
    return (VECTORS / case / impl / "did.jsonl").read_bytes()


def witness_proofs(case: str, impl: str) -> bytes | None:
    """The vector's did-witness.json, where the case has witnesses. Fourteen of them do."""
    path = VECTORS / case / impl / "did-witness.json"
    return path.read_bytes() if path.exists() else None


def expected(case: str, impl: str) -> dict | None:
    path = VECTORS / case / impl / "resolutionResult.json"
    return json.loads(path.read_text()) if path.exists() else None


def run(log: bytes, witness: bytes | None = None):
    """Our whole read-side pipeline, as the CLI sequences it."""
    entries = tuple(json.loads(line) for line in log.decode().splitlines() if line.strip())
    did = parse(entries[-1]["state"]["id"])
    clamp.clamp(entries, did)
    if witness is not None:
        clamp.clamp_witness(tuple(json.loads(witness.decode())), did)
    verified = verify.verify(log, did, witness=witness)
    publish.refuse_foreign_alias(verified.document, did)
    return did, verified


#: Vectors where an implementation disagrees with the rest of the field, each with the reason it
#: is tolerated rather than fixed. An entry here is a claim somebody can disagree with -- that is
#: what it is for, and the test below refuses a token reason. Never add one to make a red test
#: green without establishing which side is right.
KNOWN_DIVERGENCES = {
    ("deactivate", "java"): (
        "java records no services at all for a deactivated DID, while ts, dart, rust, java-eecc "
        "and python all keep the implicit #files and #whois. The specification defines those "
        "services for a did:webvh DID without carving out deactivation, so the majority reading "
        "is ours; one implementation of six is not evidence enough to change behaviour, and not "
        "little enough to hide. Raise with DIF if the suite ever pins it."
    ),
}


#: The two service types the specification defines implicitly for every did:webvh DID.
_IMPLICIT = ("relativeRef", "LinkedVerifiablePresentation")


def _implicit(document: dict) -> dict[str, str]:
    """The implicit services as ``{type: endpoint}``, normalised for what the spec leaves open.

    A trailing slash on the endpoint is not pinned, and neither is whether the id is relative or
    absolute, so neither is compared. What is compared is that both services exist and point at
    the same place.
    """
    return {
        service["type"]: str(service.get("serviceEndpoint", "")).rstrip("/")
        for service in document.get("service", [])
        if isinstance(service, dict) and service.get("type") in _IMPLICIT
    }


def _without_implicit(document: dict) -> dict:
    """The document minus the implicit services, which are compared separately."""
    stripped = dict(document)
    rest = [
        service
        for service in stripped.get("service", [])
        if not (isinstance(service, dict) and service.get("type") in _IMPLICIT)
    ]
    if rest:
        stripped["service"] = rest
    else:
        stripped.pop("service", None)
    return stripped


def run_case(case: str, impl: str):
    return run(load(case, impl), witness_proofs(case, impl))


class TestTheOracleIsRealTest:
    """Guards against the whole file passing vacuously."""

    def test_vectors_are_vendored(self):
        assert MANIFEST["cases"], "no vectors vendored"
        assert MANIFEST["commit"], "vectors must record the commit they came from"

    def test_at_least_one_independent_implementation_is_exercised(self):
        exercised = {impl for _, impl in cases(negative=False) if impl in _INDEPENDENT}
        assert exercised, (
            "every positive vector came from the library this package depends on, so this file "
            "proves nothing it does not already assume"
        )

    def test_more_than_one_independent_implementation(self):
        """Two implementations agreeing is evidence; one is a second opinion from the same room."""
        exercised = {impl for _, impl in cases(negative=False) if impl in _INDEPENDENT}
        assert len(exercised) >= 2, sorted(exercised)

    def test_every_divergence_carries_a_real_reason(self):
        """A one-word excuse is worse than no exception list, because it looks like a decision."""
        for pair, reason in KNOWN_DIVERGENCES.items():
            assert len(reason.split()) >= 20, f"{pair}: {reason!r}"

    def test_divergences_name_vectors_that_exist(self):
        """A stale entry silently stops asserting anything the day a vector is renamed."""
        known = set(cases(negative=False)) | set(cases(negative=True))
        assert set(KNOWN_DIVERGENCES) <= known, set(KNOWN_DIVERGENCES) - known

    def test_negatives_are_present(self):
        assert cases(negative=True), "without negatives this only proves we accept things"


class TestPositiveVectors:
    """A log minted elsewhere must verify here, and resolve to what its minter recorded."""

    @pytest.mark.parametrize(("case", "impl"), cases(negative=False), ids=lambda v: str(v))
    def test_it_verifies(self, case, impl):
        did, verified = run_case(case, impl)
        assert verified.document["id"] == did.canonical

    @pytest.mark.parametrize(("case", "impl"), cases(negative=False), ids=lambda v: str(v))
    def test_the_scid_recomputes_under_our_hashing(self, case, impl):
        """The canonicalization check. Their SCID is a hash of their genesis entry; it only
        reproduces here if our JCS output matches theirs byte for byte."""
        did, verified = run_case(case, impl)
        assert verified.metadata["scid"] == did.scid

    @pytest.mark.parametrize(("case", "impl"), cases(negative=False), ids=lambda v: str(v))
    def test_we_resolve_to_the_document_they_recorded(self, case, impl):
        """Everything the specification pins must match exactly.

        The implicit services are excluded and checked separately below, because the
        specification deliberately leaves their shape open: step 2 of the parallel-did:web
        procedure permits `id: "#files"` *or* `id: "<did>#files"`, and says only that the
        endpoint is "derived from the DID-to-HTTPS transformation" without fixing a trailing
        slash. The vectors exercise that latitude -- java-eecc emits the relative id form and rust
        omits the trailing slash, while ts, dart, java and python agree with us. Asserting our
        choice here would be asserting a preference as a rule, and would go red on a conformant
        implementation. Everything else -- verification methods, authentication, alsoKnownAs,
        controller, contexts -- is compared exactly.
        """
        want = expected(case, impl)
        if want is None or not want.get("didDocument"):
            pytest.skip("this vector records no resolution result")
        _, verified = run_case(case, impl)
        assert _without_implicit(verified.document) == _without_implicit(want["didDocument"])

    @pytest.mark.parametrize(("case", "impl"), cases(negative=False), ids=lambda v: str(v))
    def test_we_emit_the_same_implicit_services_they_do(self, case, impl):
        """The part of the services that *is* pinned: which ones exist, and where they point
        once the two permitted latitudes are normalised away."""
        if (case, impl) in KNOWN_DIVERGENCES:
            pytest.skip(KNOWN_DIVERGENCES[(case, impl)])
        want = expected(case, impl)
        if want is None or not want.get("didDocument"):
            pytest.skip("this vector records no resolution result")
        _, verified = run_case(case, impl)
        assert _implicit(verified.document) == _implicit(want["didDocument"])


class TestAdversarialIdentifiers:
    """The suite's DID-syntax vectors, aimed straight at webvh_gate.did.

    These are chosen adversarially rather than by us: percent-encoded IPv4 literals in both cases,
    the cloud metadata address reached the same way, path traversal plain and percent-encoded, a
    fragment leaking into the domain, and a port smuggled past the separator rules.
    """

    def test_there_are_some(self):
        assert len(adversarial_dids()) >= 5, "the extraction found nothing to test against"

    @pytest.mark.parametrize("did", adversarial_dids())
    def test_it_is_refused(self, did):
        with pytest.raises(BakoboError) as raised:
            parse(did)
        assert raised.value.code == "e.input.format.did-webvh.f"

    def test_the_substituted_scid_is_itself_valid(self):
        """Guards the substitution: if _REAL_SCID were malformed, every case above would pass for
        the wrong reason and this file would assert nothing about domains at all."""
        assert parse(f"did:webvh:{_REAL_SCID}:example.com").scid == _REAL_SCID


class TestNegativeVectors:
    """A log the suite marks invalid must be refused, by some named rule, not by accident."""

    @pytest.mark.parametrize(("case", "impl"), cases(negative=True), ids=lambda v: str(v))
    def test_it_is_refused(self, case, impl):
        with pytest.raises(BakoboError) as raised:
            run_case(case, impl)
        assert raised.value.code, f"{case} was refused without a code"
