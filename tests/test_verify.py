"""Driving the library's walk, and the mapping that must stay total across a pin bump.

Fixtures are minted with the pinned library's own signing primitives, so the happy path is a log
with real Ed25519 signatures over real JCS canonicalization rather than a shape that looks like
one. Every negative case is that same log with one thing broken.
"""

from __future__ import annotations

import ast
import json
import pathlib

import pytest
from bakobo.errors import BakoboError
from did_webvh.askar import AskarSigningKey
from did_webvh.core.proof import di_jcs_sign
from did_webvh.core.state import DocumentState

from didwebvh import verify
from didwebvh.did import parse


def mint(entries: int = 1, **params):
    """A genuinely valid log, signed for real. Returns (WebvhDid, log bytes, signing key)."""
    key = AskarSigningKey.generate("ed25519")
    base = {"updateKeys": [key.multikey], "method": "did:webvh:1.0"}
    base.update(params)
    document = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": "did:webvh:{SCID}:example.com",
    }
    state = DocumentState.initial(base, document)
    state.sign(key)
    lines = [state.history_line()]
    for _ in range(entries - 1):
        state = state.create_next()
        state.sign(key)
        lines.append(state.history_line())
    log = ("\n".join(json.dumps(line) for line in lines) + "\n").encode()
    return parse(state.document_id), log, key


def witness_key() -> AskarSigningKey:
    """A witness key, with the kid shape the library's own witness tests use."""
    key = AskarSigningKey.generate("ed25519")
    key.kid = f"did:key:{key.multikey}#{key.multikey}"
    return key


def witnessed(*keys: AskarSigningKey, signed_by: tuple[AskarSigningKey, ...] | None = None):
    """A log naming ``keys`` as witnesses, and the witness file ``signed_by`` produced."""
    listed = [{"id": f"did:key:{k.multikey}"} for k in keys]
    did, log, _ = mint(witness={"threshold": 1, "witnesses": listed})
    first = relines(log)[0]["versionId"]
    container = {"versionId": first}
    container["proof"] = [di_jcs_sign(container, k) for k in (signed_by or keys)]
    return did, log, json.dumps([container]).encode()


def relines(log: bytes) -> list[dict]:
    return [json.loads(line) for line in log.decode().splitlines()]


def rebuild(lines: list[dict]) -> bytes:
    return ("\n".join(json.dumps(line) for line in lines) + "\n").encode()


class TestTheHappyPath:
    def test_a_genuine_single_entry_log_verifies(self):
        did, log, key = mint()
        verified = verify.verify(log, did)
        assert verified.update_keys == (key.multikey,)
        assert verified.document["id"] == did.canonical
        assert verified.metadata["scid"] == did.scid
        assert verified.metadata["versionNumber"] == 1
        assert verified.metadata["deactivated"] is False

    def test_a_genuine_multi_entry_log_verifies_to_its_last_version(self):
        did, log, _ = mint(entries=3)
        verified = verify.verify(log, did)
        assert verified.metadata["versionNumber"] == 3

    def test_the_whole_log_is_walked_from_genesis_every_time(self):
        """Breaking entry 1 must fail a three-entry log, not be skipped as already published."""
        did, log, _ = mint(entries=3)
        lines = relines(log)
        lines[0]["versionTime"] = "2020-01-01T00:00:00Z"
        with pytest.raises(BakoboError):
            verify.verify(rebuild(lines), did)


class TestRefusals:
    def test_tampering_the_genesis_document_breaks_the_scid_derivation(self):
        """The SCID is a hash of the genesis entry, so editing that entry fails the hash check
        before anything looks at a signature. The earlier check wins, and it should."""
        did, log, _ = mint()
        lines = relines(log)
        lines[0]["state"]["alsoKnownAs"] = ["did:web:attacker.example"]
        with pytest.raises(BakoboError) as raised:
            verify.verify(rebuild(lines), did)
        assert raised.value.code == "e.proof.log.hash.f"

    def test_tampering_a_later_document_fails_its_proof(self):
        """Past genesis there is no SCID to contradict, so the signature is what catches it."""
        did, log, _ = mint(entries=2)
        lines = relines(log)
        lines[1]["state"]["alsoKnownAs"] = ["did:web:attacker.example"]
        with pytest.raises(BakoboError) as raised:
            verify.verify(rebuild(lines), did)
        assert raised.value.code in {"e.proof.log.signature.f", "e.proof.log.hash.f"}

    def test_a_tampered_entry_hash_is_caught(self):
        """The check that only DidResolver's own loop makes, and a hand-rolled walk would miss."""
        did, log, _ = mint(entries=2)
        lines = relines(log)
        number, _, digest = lines[1]["versionId"].partition("-")
        swapped = digest[:-4] + ("aaaa" if not digest.endswith("aaaa") else "bbbb")
        lines[1]["versionId"] = f"{number}-{swapped}"
        with pytest.raises(BakoboError) as raised:
            verify.verify(rebuild(lines), did)
        assert raised.value.code in {"e.proof.log.hash.f", "e.proof.log.signature.f"}

    def test_a_log_for_another_did_is_refused(self):
        _, log, _ = mint()
        other, _, _ = mint()
        with pytest.raises(BakoboError) as raised:
            verify.verify(log, other)
        assert raised.value.code == "e.rule.conformance.did-mismatch.f"

    def test_a_proof_from_an_unauthorized_key_is_refused(self):
        did, log, _ = mint()
        stranger = AskarSigningKey.generate("ed25519")
        state = DocumentState.load_history_line(relines(log)[0], None)
        state.proofs = []
        state.sign(stranger)
        with pytest.raises(BakoboError) as raised:
            verify.verify(rebuild([state.history_line()]), did)
        assert raised.value.code == "e.proof.log.signature.f"

    @pytest.mark.parametrize("empty", [b"", b"\n", b"   \n\n"])
    def test_an_empty_log_is_refused_before_the_library_sees_it(self, empty):
        """The pinned library hangs forever on this rather than refusing it -- see tick ~2qhs.

        The assertion that matters is not just the code but that this returns at all.
        """
        did, _, _ = mint()
        with pytest.raises(BakoboError) as raised:
            verify.verify(empty, did)
        assert raised.value.code == "e.input.missing.log.f"

    def test_a_witnessed_log_verifies_when_the_threshold_is_met(self):
        key = witness_key()
        did, log, proofs = witnessed(key)
        assert verify.verify(log, did, witness=proofs).metadata["versionNumber"] == 1

    def test_a_witnessed_log_is_refused_when_only_a_stranger_signed(self):
        """A proof from a did:key that is not in the witness list counts for nothing."""
        listed, stranger = witness_key(), witness_key()
        did, log, proofs = witnessed(listed, signed_by=(stranger,))
        with pytest.raises(BakoboError) as raised:
            verify.verify(log, did, witness=proofs)
        assert raised.value.code == "e.proof.log.witness.f"

    def test_a_log_naming_witnesses_with_no_witness_file_is_refused(self):
        witness = AskarSigningKey.generate("ed25519")
        did, log, _ = mint(
            witness={
                "threshold": 1,
                "witnesses": [{"id": f"did:key:{witness.multikey}"}],
            }
        )
        with pytest.raises(BakoboError) as raised:
            verify.verify(log, did)
        assert raised.value.code in {"e.input.missing.log.f", "e.proof.log.witness.f"}


class TestActiveUpdateKeys:
    def test_blank_lines_are_skipped_when_reading_the_update_keys(self):
        """The doors refuse a log with blank lines, so this projection is only ever handed a
        clean one -- but it is a separate pass over the bytes and does not get to assume that."""
        _, log, key = mint(entries=2)
        padded = log.replace(b"\n", b"\n\n")
        assert verify._active_update_keys(padded) == (key.multikey,)


class TestTheMappingIsTotal:
    """The test that earns its keep on a pin bump."""

    def library_problem_types(self) -> set[str]:
        """Every problem type the *installed* did_webvh can emit, read from its source."""
        import did_webvh

        root = pathlib.Path(did_webvh.__file__).parent
        found = set()
        for path in sorted(root.rglob("*.py")):
            if "tests" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                for keyword in node.keywords:
                    if (
                        keyword.arg == "type"
                        and isinstance(keyword.value, ast.Constant)
                        and isinstance(keyword.value.value, str)
                        and keyword.value.value.startswith("#")
                    ):
                        found.add(keyword.value.value)
        return found

    def test_the_walk_finds_the_problem_types(self):
        """Guards the walker: an empty set would make the totality test vacuous."""
        assert len(self.library_problem_types()) >= 10

    def test_every_problem_the_library_can_report_has_a_code(self):
        unmapped = self.library_problem_types() - set(verify.PROBLEMS)
        assert not unmapped, (
            "the pinned did_webvh can report problems this package would surface as an internal "
            f"fault. Add them to didwebvh.verify.PROBLEMS: {sorted(unmapped)}"
        )

    def test_no_mapping_is_dead(self):
        """A key for a problem the library cannot emit is a mapping nobody will ever read."""
        stale = set(verify.PROBLEMS) - self.library_problem_types()
        assert not stale, f"PROBLEMS maps types the pinned library never emits: {sorted(stale)}"

    def test_every_mapped_code_is_a_real_error_code(self):
        from bakobo.errors import ErrorCode

        for kind, code in verify.PROBLEMS.items():
            assert isinstance(code, ErrorCode), kind


class TestUnmappedProblems:
    """What happens for a problem type the mapping has never heard of."""

    def test_it_is_reported_as_our_fault_not_the_submitters(self):
        did, _, _ = mint()
        refusal = verify._refusal(
            {"error": "invalidDid", "problemDetails": {"type": "#brand-new-in-1.1"}}, did
        )
        assert refusal.code == "e.self.unknown.f"
        assert "#brand-new-in-1.1" in str(refusal)

    def test_a_refusal_with_no_problem_details_still_attributes(self):
        did, _, _ = mint()
        refusal = verify._refusal({"error": "invalidDid"}, did)
        assert refusal.code == "e.self.unknown.f"

    def test_a_list_of_problem_details_uses_the_first(self):
        did, _, _ = mint()
        refusal = verify._refusal(
            {
                "error": "invalidDid",
                "problemDetails": [{"type": "#proof-verification-failed", "detail": "nope"}],
            },
            did,
        )
        assert refusal.code == "e.proof.log.signature.f"

    def test_an_empty_list_of_problem_details_still_attributes(self):
        did, _, _ = mint()
        refusal = verify._refusal({"error": "invalidDid", "problemDetails": []}, did)
        assert refusal.code == "e.self.unknown.f"

    def test_a_problem_type_that_is_not_a_string_still_attributes(self):
        did, _, _ = mint()
        refusal = verify._refusal(
            {"error": "invalidDid", "problemDetails": {"type": 7}}, did
        )
        assert refusal.code == "e.self.unknown.f"

    def test_a_type_with_no_fragment_is_passed_through(self):
        did, _, _ = mint()
        refusal = verify._refusal(
            {"error": "invalidDid", "problemDetails": {"type": "urn:something-else"}}, did
        )
        assert refusal.code == "e.self.unknown.f"
        assert "urn:something-else" in str(refusal)
