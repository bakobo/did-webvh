"""The AID binding: a claimed did:webs sibling has to be proven, not repeated.

This is the piece no other did:webvh host has (this.i k6fiebmm). A did:webvh document may name a
did:webs DID in ``alsoKnownAs``; that assertion is signed by the update key, which proves the
controller said it and nothing about whether they control the AID. Bakobo publishes it only when
the submitted KEL shows the log's active update key *is* that AID's current signing key.

Fixtures mint real KERI AIDs with keripy and real did:webvh logs with didwebvh-py, so a passing
binding test means two independent cryptographic stacks agreed about one key.
"""

from __future__ import annotations

import shutil
from contextlib import contextmanager

import base58
import pytest
from bakobo.errors import BakoboError
from keri.app import habbing
from keri.kering import Vrsn_1_0 as V1
from test_verify import mint

from didwebvh import binding
from didwebvh.verify import Verified


def as_multikey(raw: bytes) -> str:
    """Encoded here independently of binding.multikey, so a bug in that one cannot make these
    fixtures agree with it by construction."""
    return "z" + base58.b58encode(bytes([0xED, 0x01]) + raw).decode()


@contextmanager
def scratch():
    """A keripy stack that removes the temp roots keripy's own close leaves behind.

    The fixtures need this as much as the module does: without it every AID minted here strands
    three directories, the suite accumulates them, and the leak assertions below start reporting
    on each other instead of on the code under test.
    """
    hby = habbing.Habery(name="fixture", base="", temp=True, version=V1)
    roots = binding._temp_roots(hby)
    try:
        yield hby
    finally:
        hby.close(clear=True)
        for root in roots:
            shutil.rmtree(root, ignore_errors=True)


def aid_with_key():
    """A fresh KERI AID: returns (aid, kel bytes, its current signing key as a multikey)."""
    with scratch() as hby:
        hab = hby.makeHab(name="controller", version=V1)
        kel = bytes(hab.replay(pre=hab.pre, gvrsn=V1))
        raw = hab.kever.verfers[0].raw
        return hab.pre, kel, as_multikey(raw)


def rotated_aid():
    """An AID that has rotated: returns (aid, kel, prior multikey, current multikey)."""
    with scratch() as hby:
        hab = hby.makeHab(name="controller", version=V1)
        prior = hab.kever.verfers[0].raw
        hab.rotate(version=V1)
        current = hab.kever.verfers[0].raw
        kel = bytes(hab.replay(pre=hab.pre, gvrsn=V1))
        return hab.pre, kel, as_multikey(prior), as_multikey(current)


def verified(*aliases: str, update_keys: tuple[str, ...] = ("z6Mkwhatever",)) -> Verified:
    """A stand-in for what verify() produced. The binding never re-reads the log."""
    did, _, _ = mint()
    document = {"id": did.canonical}
    if aliases:
        document["alsoKnownAs"] = list(aliases)
    return did, Verified(document=document, metadata={}, update_keys=update_keys)


class TestNoClaimNoEvidence:
    def test_a_document_with_no_sibling_and_no_stream_passes(self):
        """A did:webvh DID with no KERI sibling is a legitimate thing to host."""
        did, result = verified()
        binding.bind(result, did, None)

    def test_a_non_webs_alias_neither_requires_evidence_nor_blocks(self):
        did, result = verified("did:web:example.com", "https://example.com/about")
        binding.bind(result, did, None)

    def test_a_stream_with_no_claim_is_refused(self):
        """Unused evidence is a mistake: an operator who supplied it believed it mattered."""
        _, kel, _ = aid_with_key()
        did, result = verified()
        with pytest.raises(BakoboError) as raised:
            binding.bind(result, did, kel)
        assert raised.value.code == "e.rule.binding.unused-evidence.f"


class TestTheBindingHolds:
    def test_a_sibling_whose_aid_key_is_the_update_key_publishes(self):
        aid, kel, multikey = aid_with_key()
        did, result = verified(f"did:webs:example.com:{aid}", update_keys=(multikey,))
        binding.bind(result, did, kel)

    def test_it_holds_when_the_update_key_is_one_of_several(self):
        aid, kel, multikey = aid_with_key()
        did, result = verified(
            f"did:webs:example.com:{aid}", update_keys=("z6Mkother", multikey)
        )
        binding.bind(result, did, kel)

    def test_a_sibling_on_a_different_domain_still_binds(self):
        """The binding is about key control, not about where either DID is hosted."""
        aid, kel, multikey = aid_with_key()
        did, result = verified(f"did:webs:elsewhere.example:x:{aid}", update_keys=(multikey,))
        binding.bind(result, did, kel)

    def test_every_sibling_must_bind_not_merely_one(self):
        first, first_kel, first_key = aid_with_key()
        second, _, _ = aid_with_key()
        did, result = verified(
            f"did:webs:example.com:{first}",
            f"did:webs:example.com:{second}",
            update_keys=(first_key,),
        )
        with pytest.raises(BakoboError) as raised:
            binding.bind(result, did, first_kel)
        assert raised.value.code == "e.proof.binding.aid.f"


class TestTheBindingFails:
    def test_a_claim_with_no_stream_is_refused(self):
        aid, _, multikey = aid_with_key()
        did, result = verified(f"did:webs:example.com:{aid}", update_keys=(multikey,))
        with pytest.raises(BakoboError) as raised:
            binding.bind(result, did, None)
        assert raised.value.code == "e.input.missing.binding-evidence.f"

    def test_a_stream_for_a_different_aid_is_refused(self):
        claimed, _, _ = aid_with_key()
        _, other_kel, other_key = aid_with_key()
        did, result = verified(f"did:webs:example.com:{claimed}", update_keys=(other_key,))
        with pytest.raises(BakoboError) as raised:
            binding.bind(result, did, other_kel)
        assert raised.value.code == "e.proof.binding.aid.f"

    def test_a_stream_that_is_not_cesr_is_refused(self):
        aid, _, multikey = aid_with_key()
        did, result = verified(f"did:webs:example.com:{aid}", update_keys=(multikey,))
        with pytest.raises(BakoboError) as raised:
            binding.bind(result, did, b"this is not a key event log")
        assert raised.value.code == "e.proof.binding.aid.f"

    def test_a_truncated_stream_is_refused(self):
        aid, kel, multikey = aid_with_key()
        did, result = verified(f"did:webs:example.com:{aid}", update_keys=(multikey,))
        with pytest.raises(BakoboError) as raised:
            binding.bind(result, did, kel[: len(kel) // 2])
        assert raised.value.code == "e.proof.binding.aid.f"

    def test_an_update_key_that_is_not_the_aids_key_is_refused(self):
        aid, kel, _ = aid_with_key()
        _, _, stranger = aid_with_key()
        did, result = verified(f"did:webs:example.com:{aid}", update_keys=(stranger,))
        with pytest.raises(BakoboError) as raised:
            binding.bind(result, did, kel)
        assert raised.value.code == "e.proof.binding.key.f"

    def test_the_prior_key_of_a_rotated_aid_does_not_bind(self):
        """Current key state, never historical. A rotated-away key proves nothing today."""
        aid, kel, prior, _ = rotated_aid()
        did, result = verified(f"did:webs:example.com:{aid}", update_keys=(prior,))
        with pytest.raises(BakoboError) as raised:
            binding.bind(result, did, kel)
        assert raised.value.code == "e.proof.binding.key.f"

    def test_the_current_key_of_a_rotated_aid_does_bind(self):
        aid, kel, _, current = rotated_aid()
        did, result = verified(f"did:webs:example.com:{aid}", update_keys=(current,))
        binding.bind(result, did, kel)


class TestMalformedClaims:
    @pytest.mark.parametrize(
        ("alias", "because"),
        [
            ("did:webs:", "no AID at all"),
            ("did:webs:example.com", "a host and nothing that could be an AID"),
            ("did:webs:example.com:not-an-aid", "a final segment that is not a SAID"),
        ],
    )
    def test_a_malformed_sibling_is_refused_rather_than_ignored(self, alias, because):
        _, kel, multikey = aid_with_key()
        did, result = verified(alias, update_keys=(multikey,))
        with pytest.raises(BakoboError) as raised:
            binding.bind(result, did, kel)
        assert raised.value.code == "e.proof.binding.aid.f", because

    def test_an_alsoknownas_that_is_not_a_list_is_refused(self):
        did, result = verified()
        result.document["alsoKnownAs"] = "did:webs:example.com:EAbc"
        with pytest.raises(BakoboError) as raised:
            binding.bind(result, did, None)
        assert raised.value.code == "e.proof.binding.aid.f"

    def test_an_alias_that_is_not_a_string_is_ignored_not_crashed_on(self):
        did, result = verified()
        result.document["alsoKnownAs"] = [7, {"id": "x"}]
        binding.bind(result, did, None)


class TestModuleSurface:
    def test_multikey_encoding_round_trips_against_keripy(self):
        """The one piece of bit-twiddling here, checked against a key keripy generated."""
        _, _, multikey = aid_with_key()
        assert multikey.startswith("z6Mk")
        decoded = base58.b58decode(multikey[1:])
        assert decoded[:2] == bytes([0xED, 0x01])
        assert len(decoded) == 34


class TestItLeavesNothingBehind:
    """did-webs strands 32,000 /tmp/keri_* directories because nothing asserted this. Here it is
    asserted at authoring time, where the leak is one line to fix rather than an archaeology
    problem across an accumulated suite."""

    def test_binding_strands_no_keri_temp_directories(self):
        import glob

        aid, kel, multikey_value = aid_with_key()
        did, result = verified(f"did:webs:example.com:{aid}", update_keys=(multikey_value,))
        before = set(glob.glob("/tmp/keri_*"))
        binding.bind(result, did, kel)
        assert set(glob.glob("/tmp/keri_*")) == before

    def test_a_refused_binding_strands_nothing_either(self):
        """The failing path is the one that skips a cleanup, so it gets its own assertion."""
        import glob

        aid, kel, _ = aid_with_key()
        _, _, stranger = aid_with_key()
        did, result = verified(f"did:webs:example.com:{aid}", update_keys=(stranger,))
        before = set(glob.glob("/tmp/keri_*"))
        with pytest.raises(BakoboError):
            binding.bind(result, did, kel)
        assert set(glob.glob("/tmp/keri_*")) == before


class TestTheDefensiveEdges:
    """Two guards that no input found so far can reach, kept anyway and said so."""

    def test_a_parser_that_raises_yields_no_keys_rather_than_a_traceback(self, monkeypatch):
        """keripy's parse swallowed every hostile input tried -- random bytes, bare counter
        codes, a lone version string, nulls -- so this path is reached by forcing it rather
        than by a fixture. It is kept because parse is third-party code across a version
        boundary: if it ever does raise, the gate must refuse rather than report a fault."""
        aid, kel, multikey_value = aid_with_key()
        did, result = verified(f"did:webs:example.com:{aid}", update_keys=(multikey_value,))

        real = habbing.Habery.__init__

        def explode(self, *args, **kwargs):
            real(self, *args, **kwargs)
            monkeypatch.setattr(
                self.psr, "parse", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
            )

        monkeypatch.setattr(habbing.Habery, "__init__", explode)
        with pytest.raises(BakoboError) as raised:
            binding.bind(result, did, kel)
        assert raised.value.code == "e.proof.binding.aid.f"

    def test_a_store_outside_the_temp_directory_is_never_removed(self):
        """The guard on the rmtree. A walk that fell off its assumption must return None rather
        than hand shutil something very much larger than a scratch keystore."""
        assert binding._temp_root("/usr/lib/python3.14/something") is None
        assert binding._temp_root("/") is None
