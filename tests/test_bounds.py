"""The three doors everything crosses through, and the numbers on them.

Grades each door against the rubric in dev/standards/input-handling.md: the bound is named and
enforced before anything is parsed, the validator is total on hostile input, a refusal leaves
nothing behind, and the message carries the bound rather than the reader's own payload back.
"""

from __future__ import annotations

import io
import json

import pytest
from bakobo.errors import BakoboError

from didwebvh import bounds
from didwebvh.did import parse

DID = parse("did:webvh:QmaigaGjpv2GNnN5D2tyd1XZLY8PnRTDtgHYCiV964ooMn:example.com")


def entry(version: int = 1, **overrides) -> dict:
    """A shape-valid log entry. Meaning is the clamp's problem, not the door's."""
    base = {
        "versionId": f"{version}-QmWJSj8i4YkbDqj8mScsMBmboJsGkcDEoHdTfzCKrKguZ2",
        "versionTime": "2026-09-14T19:35:54Z",
        "parameters": {"method": "did:webvh:1.0"},
        "state": {"id": DID.canonical},
        "proof": [{"type": "DataIntegrityProof"}],
    }
    base.update(overrides)
    return base


def log_bytes(*entries: dict) -> bytes:
    return ("\n".join(json.dumps(e) for e in entries) + "\n").encode()


def write(tmp_path, name: str, payload: bytes):
    path = tmp_path / name
    path.write_bytes(payload)
    return path


class TestTheDoorSet:
    """The set of doors is the thing that has to stay complete."""

    def test_every_door_names_a_kind_and_a_limit(self):
        assert bounds.DOORS
        for door in bounds.DOORS:
            assert door.kind
            assert door.limit > 0

    def test_kinds_are_unique(self):
        kinds = [d.kind for d in bounds.DOORS]
        assert len(kinds) == len(set(kinds))

    def test_there_is_a_door_for_each_of_the_three_submitted_artifacts(self):
        assert {d.kind for d in bounds.DOORS} == {"log", "stream", "witness"}

    def test_every_door_has_an_opener_named_after_it(self):
        for door in bounds.DOORS:
            assert callable(getattr(bounds, f"open_{door.kind}"))


class TestBoundedReading:
    """Rubric 1 and 3: the bound is enforced by not reading past it, not by measuring after."""

    def test_a_refusal_never_reads_more_than_the_bound_plus_one_byte(self):
        handle = io.BytesIO(b"x" * (bounds.LOG.limit * 2))
        with pytest.raises(BakoboError):
            bounds.read_bounded(handle, bounds.LOG, DID)
        assert handle.tell() <= bounds.LOG.limit + 1

    def test_exactly_the_bound_is_accepted(self):
        handle = io.BytesIO(b"x" * bounds.LOG.limit)
        assert len(bounds.read_bounded(handle, bounds.LOG, DID)) == bounds.LOG.limit

    def test_one_byte_past_the_bound_is_refused(self):
        handle = io.BytesIO(b"x" * (bounds.LOG.limit + 1))
        with pytest.raises(BakoboError) as raised:
            bounds.read_bounded(handle, bounds.LOG, DID)
        assert raised.value.code == "e.input.range.log.f"

    def test_the_refusal_carries_the_bound_and_not_the_payload(self):
        handle = io.BytesIO(b"SECRETPAYLOAD" * bounds.LOG.limit)
        with pytest.raises(BakoboError) as raised:
            bounds.read_bounded(handle, bounds.LOG, DID)
        message = str(raised.value)
        assert str(bounds.LOG.limit) in message
        assert "SECRETPAYLOAD" not in message


class TestLogDoor:
    def test_accepts_a_well_shaped_log(self, tmp_path):
        path = write(tmp_path, "did.jsonl", log_bytes(entry(1), entry(2)))
        admitted = bounds.open_log(path, DID)
        assert admitted.raw == path.read_bytes()
        assert len(admitted.parsed) == 2
        assert admitted.parsed[0]["versionId"].startswith("1-")

    def test_a_log_without_a_trailing_newline_is_fine(self, tmp_path):
        path = write(tmp_path, "did.jsonl", json.dumps(entry()).encode())
        assert len(bounds.open_log(path, DID).parsed) == 1

    @pytest.mark.parametrize(
        ("payload", "because"),
        [
            (b"", "an empty file is not a log"),
            (b"\n\n", "a file of only newlines has no entries"),
            (b'{"a": 1}\n\n{"b": 2}\n', "a blank interior line is not JSON Lines"),
            (b"not json\n", "a line that is not JSON"),
            (b"[1, 2]\n", "a line that is JSON but not an object"),
            (b'"a string"\n', "a line that is a bare JSON string"),
            (b"null\n", "a line that is JSON null"),
        ],
    )
    def test_refuses_malformed_lines(self, tmp_path, payload, because):
        path = write(tmp_path, "did.jsonl", payload)
        with pytest.raises(BakoboError) as raised:
            bounds.open_log(path, DID)
        assert raised.value.code == "e.input.format.log.f", because

    @pytest.mark.parametrize(
        "missing", ["versionId", "versionTime", "parameters", "state", "proof"]
    )
    def test_refuses_an_entry_missing_a_required_key(self, tmp_path, missing):
        incomplete = entry()
        del incomplete[missing]
        path = write(tmp_path, "did.jsonl", log_bytes(incomplete))
        with pytest.raises(BakoboError) as raised:
            bounds.open_log(path, DID)
        assert raised.value.code == "e.input.format.log.f"
        assert missing in str(raised.value)

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("versionId", 1),
            ("versionTime", []),
            ("parameters", "method"),
            ("state", []),
            ("proof", "a proof"),
        ],
    )
    def test_refuses_a_required_key_of_the_wrong_type(self, tmp_path, key, value):
        path = write(tmp_path, "did.jsonl", log_bytes(entry(**{key: value})))
        with pytest.raises(BakoboError) as raised:
            bounds.open_log(path, DID)
        assert raised.value.code == "e.input.format.log.f"

    def test_a_single_proof_object_is_as_acceptable_as_a_list(self, tmp_path):
        """Data Integrity permits either, and the spec's own examples use both."""
        path = write(tmp_path, "did.jsonl", log_bytes(entry(proof={"type": "DataIntegrityProof"})))
        assert bounds.open_log(path, DID).parsed[0]["proof"] == {"type": "DataIntegrityProof"}

    def test_refuses_an_entry_over_the_per_entry_bound(self, tmp_path):
        fat = entry(state={"id": DID.canonical, "padding": "x" * bounds.MAX_ENTRY_BYTES})
        path = write(tmp_path, "did.jsonl", log_bytes(fat))
        with pytest.raises(BakoboError) as raised:
            bounds.open_log(path, DID)
        assert raised.value.code == "e.input.range.log.f"

    def test_refuses_more_entries_than_the_bound(self, tmp_path, monkeypatch):
        monkeypatch.setattr(bounds, "MAX_ENTRIES", 2)
        path = write(tmp_path, "did.jsonl", log_bytes(entry(1), entry(2), entry(3)))
        with pytest.raises(BakoboError) as raised:
            bounds.open_log(path, DID)
        assert raised.value.code == "e.input.range.log.f"
        assert "2" in str(raised.value)

    def test_refuses_a_file_over_the_door_bound(self, tmp_path, monkeypatch):
        monkeypatch.setattr(bounds, "LOG", bounds.Door("log", 64))
        path = write(tmp_path, "did.jsonl", log_bytes(entry()))
        with pytest.raises(BakoboError) as raised:
            bounds.open_log(path, DID)
        assert raised.value.code == "e.input.range.log.f"


class TestStreamDoor:
    def test_returns_the_bytes_unexamined(self, tmp_path):
        """CESR's meaning is keripy's to judge; this door only decides how many bytes."""
        payload = b"-FABE" + b"x" * 100
        path = write(tmp_path, "keri.cesr", payload)
        assert bounds.open_stream(path, DID) == payload

    def test_refuses_an_empty_stream(self, tmp_path):
        path = write(tmp_path, "keri.cesr", b"")
        with pytest.raises(BakoboError) as raised:
            bounds.open_stream(path, DID)
        assert raised.value.code == "e.input.missing.stream.f"

    def test_refuses_a_stream_over_the_bound(self, tmp_path, monkeypatch):
        monkeypatch.setattr(bounds, "STREAM", bounds.Door("stream", 8))
        path = write(tmp_path, "keri.cesr", b"x" * 9)
        with pytest.raises(BakoboError) as raised:
            bounds.open_stream(path, DID)
        assert raised.value.code == "e.input.range.stream.f"


class TestWitnessDoor:
    def proofs(self, version: int = 1) -> dict:
        return {
            "versionId": f"{version}-QmWJSj8i4YkbDqj8mScsMBmboJsGkcDEoHdTfzCKrKguZ2",
            "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022"}],
        }

    def test_accepts_the_spec_data_model(self, tmp_path):
        path = write(tmp_path, "did-witness.json", json.dumps([self.proofs(1), self.proofs(2)]).encode())
        found = bounds.open_witness(path, DID)
        assert found.raw == path.read_bytes()
        assert len(found.parsed) == 2
        assert found.parsed[0]["versionId"].startswith("1-")

    def test_accepts_an_empty_array(self, tmp_path):
        """A controller may publish the file before any proofs exist for a new entry."""
        path = write(tmp_path, "did-witness.json", b"[]")
        assert bounds.open_witness(path, DID).parsed == ()

    @pytest.mark.parametrize(
        ("payload", "because"),
        [
            (b"", "an empty file is not JSON"),
            (b"not json", "not JSON at all"),
            (b"{}", "an object, where the data model is an array"),
            (b"[1]", "an element that is not an object"),
            (b'[{"proof": []}]', "an element with no versionId"),
            (b'[{"versionId": "1-Qm"}]', "an element with no proof"),
            (b'[{"versionId": 1, "proof": []}]', "a versionId that is not a string"),
            (b'[{"versionId": "1-Qm", "proof": {}}]', "a proof that is not an array"),
        ],
    )
    def test_refuses_anything_off_the_data_model(self, tmp_path, payload, because):
        path = write(tmp_path, "did-witness.json", payload)
        with pytest.raises(BakoboError) as raised:
            bounds.open_witness(path, DID)
        assert raised.value.code == "e.input.format.witness.f", because

    def test_refuses_a_file_over_the_bound(self, tmp_path, monkeypatch):
        monkeypatch.setattr(bounds, "WITNESS", bounds.Door("witness", 8))
        path = write(tmp_path, "did-witness.json", b"[" + b"x" * 20 + b"]")
        with pytest.raises(BakoboError) as raised:
            bounds.open_witness(path, DID)
        assert raised.value.code == "e.input.range.witness.f"


class TestFailsClean:
    """Rubric 4: a refusal leaves nothing behind, so a retry is honest."""

    def test_a_refused_submission_writes_nothing(self, tmp_path):
        path = write(tmp_path, "did.jsonl", b"not json\n")
        before = sorted(p.name for p in tmp_path.iterdir())
        with pytest.raises(BakoboError):
            bounds.open_log(path, DID)
        assert sorted(p.name for p in tmp_path.iterdir()) == before


class TestDeeplyNestedJson:
    """Panel finding SEC-F2. json.loads raises RecursionError, not ValueError, so this used to
    escape the door and reach an operator as "please report it" instead of a refusal."""

    def nested(self, depth: int = 40_000) -> bytes:
        return (b"[" * depth) + (b"]" * depth)

    def test_a_deeply_nested_log_line_is_refused_as_malformed_input(self, tmp_path):
        path = write(tmp_path, "did.jsonl", self.nested() + b"\n")
        with pytest.raises(BakoboError) as raised:
            bounds.open_log(path, DID)
        assert raised.value.code == "e.input.format.log.f"

    def test_a_deeply_nested_witness_file_is_refused_as_malformed_input(self, tmp_path):
        path = write(tmp_path, "did-witness.json", self.nested())
        with pytest.raises(BakoboError) as raised:
            bounds.open_witness(path, DID)
        assert raised.value.code == "e.input.format.witness.f"

    def test_it_stays_under_the_size_bound(self):
        """If the payload were over the bound the range check would catch it first, and this
        would prove nothing about the parse."""
        assert len(self.nested()) < bounds.LOG.limit
