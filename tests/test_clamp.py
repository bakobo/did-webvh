"""The conformance clamp: what `did:webvh:1.0` forbids, refused before the library sees it.

This is the module that makes this repo more than a wrapper (this.i tvv6dvyn, t2jkfguj), so it
gets the densest matrix. The lead case is not hypothetical: the pinned reference implementation
mints a P-256 log, declares it `did:webvh:1.0`, and resolves it happily, while didwebvh-ts
refuses it. A DID like that is resolvable only by the tool that made it.
"""

from __future__ import annotations

import base58
import pytest
from bakobo.errors import BakoboError

from didwebvh import clamp
from didwebvh.did import parse

DID = parse("did:webvh:QmaigaGjpv2GNnN5D2tyd1XZLY8PnRTDtgHYCiV964ooMn:example.com")
SCID = DID.scid


def hashed(payload: bytes = b"entry", code: int = 0x12, size: int = 32) -> str:
    """A base58btc multihash, so a test can put a real one or a deliberately wrong one in a log."""
    return base58.b58encode(bytes([code, size]) + payload.ljust(size, b"\0")[:size]).decode()


def proof(cryptosuite: str = clamp.CRYPTOSUITE, **overrides) -> dict:
    base = {
        "type": "DataIntegrityProof",
        "cryptosuite": cryptosuite,
        "verificationMethod": "did:key:z6Mkabc#z6Mkabc",
        "proofPurpose": "assertionMethod",
        "proofValue": "z3sig",
    }
    base.update(overrides)
    return base


def entry(number: int = 1, parameters: dict | None = None, **overrides) -> dict:
    base = {
        "versionId": f"{number}-{hashed(f'v{number}'.encode())}",
        "versionTime": "2026-09-14T19:35:54Z",
        "parameters": {"method": "did:webvh:1.0", "scid": SCID} if number == 1 else {},
        "state": {"id": DID.canonical},
        "proof": [proof()],
    }
    if parameters is not None:
        base["parameters"] = parameters
    base.update(overrides)
    return base


def log(*entries: dict) -> tuple[dict, ...]:
    return entries or (entry(1),)


class TestAcceptsWhatTheVersionAllows:
    def test_a_conformant_single_entry_log(self):
        clamp.clamp(log(), DID)

    def test_a_conformant_multi_entry_log(self):
        clamp.clamp(log(entry(1), entry(2), entry(3)), DID)

    def test_method_may_be_omitted_after_the_first_entry(self):
        clamp.clamp(log(entry(1), entry(2, parameters={"updateKeys": ["z6Mkabc"]})))

    def test_method_may_be_restated_identically(self):
        clamp.clamp(log(entry(1), entry(2, parameters={"method": "did:webvh:1.0"})), DID)

    def test_a_single_proof_object_is_clamped_like_a_list_of_one(self):
        clamp.clamp(log(entry(1, proof=proof())), DID)

    def test_every_v1_parameter_is_allowed(self):
        params = {
            "method": "did:webvh:1.0",
            "scid": SCID,
            "updateKeys": ["z6Mkabc"],
            "nextKeyHashes": [hashed(b"next")],
            "witness": {"threshold": 1, "witnesses": [{"id": "did:key:z6Mkwit"}]},
            "watchers": ["https://watcher.example"],
            "portable": False,
            "deactivated": False,
            "ttl": 3600,
        }
        clamp.clamp(log(entry(1, parameters=params)), DID)


class TestCryptosuite:
    """The headline rule, and the one the reference implementation gets wrong."""

    def test_the_reference_implementations_p256_log_is_refused(self):
        """Exactly what `did_webvh.provision --algorithm p256` emits: v1.0, ecdsa-jcs-2019."""
        bad = entry(1, proof=[proof(cryptosuite="ecdsa-jcs-2019")])
        with pytest.raises(BakoboError) as raised:
            clamp.clamp(log(bad), DID)
        assert raised.value.code == "e.rule.conformance.cryptosuite.f"
        assert "ecdsa-jcs-2019" in str(raised.value)

    def test_an_absent_cryptosuite_is_refused(self):
        bare = proof()
        del bare["cryptosuite"]
        with pytest.raises(BakoboError) as raised:
            clamp.clamp(log(entry(1, proof=[bare])), DID)
        assert raised.value.code == "e.rule.conformance.cryptosuite.f"

    def test_checking_proof_purpose_alone_is_insufficient(self):
        """The spec says so in as many words, so a proof that looks right but is not is refused."""
        with pytest.raises(BakoboError):
            clamp.clamp(log(entry(1, proof=[proof(cryptosuite="eddsa-rdfc-2022")])), DID)

    def test_a_non_data_integrity_proof_type_is_refused(self):
        with pytest.raises(BakoboError) as raised:
            clamp.clamp(log(entry(1, proof=[proof(type="Ed25519Signature2020")])), DID)
        assert raised.value.code == "e.rule.conformance.cryptosuite.f"

    def test_a_later_entry_is_clamped_too(self):
        """A log conformant at genesis and not at entry three is still refused."""
        with pytest.raises(BakoboError):
            clamp.clamp(log(entry(1), entry(2), entry(3, proof=[proof("ecdsa-jcs-2019")])), DID)

    def test_a_proof_that_is_not_an_object_is_refused(self):
        with pytest.raises(BakoboError) as raised:
            clamp.clamp(log(entry(1, proof=["not a proof"])), DID)
        assert raised.value.code == "e.rule.conformance.cryptosuite.f"


class TestMethodVersion:
    def test_missing_from_the_first_entry_is_refused(self):
        with pytest.raises(BakoboError) as raised:
            clamp.clamp(log(entry(1, parameters={"scid": SCID})), DID)
        assert raised.value.code == "e.rule.conformance.method.f"

    @pytest.mark.parametrize(
        "value",
        ["did:webvh:0.5", "did:webvh:1.1", "did:webvh:2.0", "did:webvh:1.0 ", "DID:WEBVH:1.0", ""],
    )
    def test_an_unacceptable_value_is_refused(self, value):
        """Not downgraded, not defaulted, not ignored -- the spec forbids all three."""
        with pytest.raises(BakoboError) as raised:
            clamp.clamp(log(entry(1, parameters={"method": value, "scid": SCID})), DID)
        assert raised.value.code == "e.rule.conformance.method.f"

    def test_a_non_string_value_is_refused(self):
        with pytest.raises(BakoboError) as raised:
            clamp.clamp(log(entry(1, parameters={"method": 1.0, "scid": SCID})), DID)
        assert raised.value.code == "e.rule.conformance.method.f"

    def test_a_later_entry_may_not_change_to_an_unacceptable_version(self):
        with pytest.raises(BakoboError) as raised:
            clamp.clamp(log(entry(1), entry(2, parameters={"method": "did:webvh:0.5"})), DID)
        assert raised.value.code == "e.rule.conformance.method.f"


class TestScidPlacement:
    def test_missing_from_the_first_entry_is_refused(self):
        with pytest.raises(BakoboError) as raised:
            clamp.clamp(log(entry(1, parameters={"method": "did:webvh:1.0"})), DID)
        assert raised.value.code == "e.rule.conformance.parameter.f"

    def test_present_in_a_later_entry_is_refused(self):
        later = entry(2, parameters={"scid": SCID})
        with pytest.raises(BakoboError) as raised:
            clamp.clamp(log(entry(1), later), DID)
        assert raised.value.code == "e.rule.conformance.parameter.f"

    def test_an_scid_that_is_not_the_dids_own_is_refused(self):
        other = "Qm" + "b" * 44
        with pytest.raises(BakoboError) as raised:
            clamp.clamp(log(entry(1, parameters={"method": "did:webvh:1.0", "scid": other})), DID)
        assert raised.value.code == "e.rule.conformance.parameter.f"


class TestParameterHygiene:
    def test_an_unknown_parameter_is_refused(self):
        """"MUST only include properties defined in the version being used"."""
        params = {"method": "did:webvh:1.0", "scid": SCID, "prerotation": True}
        with pytest.raises(BakoboError) as raised:
            clamp.clamp(log(entry(1, parameters=params)), DID)
        assert raised.value.code == "e.rule.conformance.parameter.f"
        assert "prerotation" in str(raised.value)

    @pytest.mark.parametrize("parameter", ["witness", "watchers", "nextKeyHashes", "ttl"])
    def test_a_null_value_is_refused(self, parameter):
        """Deprecated but widely emitted. We publish verbatim, so we cannot normalise it away."""
        params = {"method": "did:webvh:1.0", "scid": SCID, parameter: None}
        with pytest.raises(BakoboError) as raised:
            clamp.clamp(log(entry(1, parameters=params)), DID)
        assert raised.value.code == "e.rule.conformance.parameter.f"

    def test_the_null_refusal_says_the_log_is_publishable_elsewhere(self):
        """A customer with an older log needs to know this is our gate, not a broken log."""
        params = {"method": "did:webvh:1.0", "scid": SCID, "witness": None}
        with pytest.raises(BakoboError) as raised:
            clamp.clamp(log(entry(1, parameters=params)), DID)
        assert "null" in str(raised.value).lower()

    def test_an_empty_array_is_the_conformant_way_to_say_off(self):
        params = {"method": "did:webvh:1.0", "scid": SCID, "nextKeyHashes": []}
        clamp.clamp(log(entry(1, parameters=params)), DID)


class TestHashAlgorithm:
    def test_a_non_sha256_scid_multihash_is_refused(self):
        """0x16 is sha3-256: the right length, the wrong algorithm."""
        params = {"method": "did:webvh:1.0", "scid": hashed(b"x", code=0x16)}
        with pytest.raises(BakoboError) as raised:
            clamp.clamp(log(entry(1, parameters=params)), DID)
        assert raised.value.code == "e.rule.conformance.hash.f"

    def test_a_non_sha256_entry_hash_is_refused(self):
        bad = entry(1, versionId=f"1-{hashed(b'x', code=0x16)}")
        with pytest.raises(BakoboError) as raised:
            clamp.clamp(log(bad), DID)
        assert raised.value.code == "e.rule.conformance.hash.f"

    def test_a_non_sha256_next_key_hash_is_refused(self):
        params = {
            "method": "did:webvh:1.0",
            "scid": SCID,
            "nextKeyHashes": [hashed(b"ok"), hashed(b"bad", code=0x16)],
        }
        with pytest.raises(BakoboError) as raised:
            clamp.clamp(log(entry(1, parameters=params)), DID)
        assert raised.value.code == "e.rule.conformance.hash.f"

    @pytest.mark.parametrize(
        ("version_id", "because"),
        [
            ("1", "no dash, so no entry hash at all"),
            ("-Qmabc", "an empty version number"),
            ("x-Qmabc", "a version number that is not an integer"),
            ("1-not!base58", "an entry hash outside the base58btc alphabet"),
            ("1-", "an empty entry hash"),
        ],
    )
    def test_a_malformed_version_id_is_refused(self, version_id, because):
        with pytest.raises(BakoboError) as raised:
            clamp.clamp(log(entry(1, versionId=version_id)), DID)
        assert raised.value.code == "e.rule.conformance.hash.f", because

    def test_a_multihash_whose_declared_length_disagrees_is_refused(self):
        wrong = base58.b58encode(bytes([0x12, 0x20]) + b"\0" * 16).decode()
        params = {"method": "did:webvh:1.0", "scid": wrong}
        with pytest.raises(BakoboError) as raised:
            clamp.clamp(log(entry(1, parameters=params)), DID)
        assert raised.value.code == "e.rule.conformance.hash.f"


class TestWitnessProofs:
    """The spec says the cryptosuite rule covers witness proofs too, in as many words."""

    def witnessed(self, cryptosuite: str = clamp.CRYPTOSUITE) -> tuple[dict, ...]:
        return ({"versionId": f"1-{hashed(b'v1')}", "proof": [proof(cryptosuite)]},)

    def test_accepts_conformant_witness_proofs(self):
        clamp.clamp_witness(self.witnessed(), DID)

    def test_refuses_a_witness_proof_with_the_wrong_cryptosuite(self):
        with pytest.raises(BakoboError) as raised:
            clamp.clamp_witness(self.witnessed("ecdsa-jcs-2019"), DID)
        assert raised.value.code == "e.rule.conformance.cryptosuite.f"

    def test_refuses_a_witness_proof_with_no_cryptosuite(self):
        bare = proof()
        del bare["cryptosuite"]
        proofs = ({"versionId": f"1-{hashed(b'v1')}", "proof": [bare]},)
        with pytest.raises(BakoboError):
            clamp.clamp_witness(proofs, DID)

    def test_refuses_a_witness_entry_whose_version_id_is_malformed(self):
        proofs = ({"versionId": "not-a-version", "proof": [proof()]},)
        with pytest.raises(BakoboError) as raised:
            clamp.clamp_witness(proofs, DID)
        assert raised.value.code == "e.rule.conformance.hash.f"

    def test_an_empty_witness_file_is_conformant(self):
        clamp.clamp_witness((), DID)


class TestWitnessKeys:
    """"witness did:key identifiers MUST use a key compliant with eddsa-jcs-2022"."""

    def witness_param(self, wid: str) -> dict:
        return {
            "method": "did:webvh:1.0",
            "scid": SCID,
            "witness": {"threshold": 1, "witnesses": [{"id": wid}]},
        }

    def test_an_ed25519_did_key_is_accepted(self):
        clamp.clamp(log(entry(1, parameters=self.witness_param("did:key:z6MkabcDEF"))), DID)

    def test_a_p256_did_key_witness_is_refused(self):
        """z Dn... is the P-256 multicodec, which this cryptosuite cannot verify."""
        with pytest.raises(BakoboError) as raised:
            clamp.clamp(log(entry(1, parameters=self.witness_param("did:key:zDnaeXYZ"))), DID)
        assert raised.value.code == "e.rule.conformance.cryptosuite.f"

    def test_a_witness_that_is_not_a_did_key_is_refused(self):
        with pytest.raises(BakoboError) as raised:
            clamp.clamp(log(entry(1, parameters=self.witness_param("did:web:example.com"))), DID)
        assert raised.value.code == "e.rule.conformance.cryptosuite.f"


class TestModuleSurface:
    def test_the_acceptable_method_set_is_exactly_one_version(self):
        """If this ever grows, every rule keyed off it has to be revisited deliberately."""
        assert clamp.ACCEPTABLE_METHODS == frozenset({"did:webvh:1.0"})

    def test_the_parameter_set_matches_the_specification(self):
        assert clamp.PARAMETERS == frozenset(
            {
                "method",
                "scid",
                "updateKeys",
                "nextKeyHashes",
                "witness",
                "watchers",
                "portable",
                "deactivated",
                "ttl",
            }
        )


class TestWitnessParameterShape:
    """The clamp has to be total on a witness parameter that is the wrong shape entirely."""

    def params(self, witness) -> dict:
        return {"method": "did:webvh:1.0", "scid": SCID, "witness": witness}

    @pytest.mark.parametrize(
        ("witness", "because"),
        [
            ("did:key:z6Mkabc", "a string where the object belongs"),
            ({"threshold": 1}, "an object carrying no witnesses array"),
            ({"witnesses": "did:key:z6Mkabc"}, "a witnesses value that is not an array"),
            ({"witnesses": ["did:key:z6Mkabc"]}, "a witness that is a bare string"),
            ({"witnesses": [{"url": "x"}]}, "a witness entry with no id"),
            ({"witnesses": [{"id": 7}]}, "an id that is not a string"),
        ],
    )
    def test_a_malformed_witness_parameter_is_refused(self, witness, because):
        with pytest.raises(BakoboError) as raised:
            clamp.clamp(log(entry(1, parameters=self.params(witness))), DID)
        assert raised.value.code == "e.rule.conformance.parameter.f", because
