"""Writing the artifacts: verbatim where it must be, derived where it must be, all or none.

Three rules under test, each from a different place. The log is published byte-for-byte because a
Data Integrity proof covers exact bytes (this.i gzvt7mpn). did.json is the parallel did:web
document and appears only when the log commits to one (this.i whgskdbb). And did-witness.json is
written *before* the log, because the specification says so to kill a publication race.
"""

from __future__ import annotations

import json

import pytest
from bakobo.errors import BakoboError

from didwebvh import publish
from didwebvh.did import parse
from didwebvh.verify import Verified

SCID = "QmaigaGjpv2GNnN5D2tyd1XZLY8PnRTDtgHYCiV964ooMn"
DID = parse(f"did:webvh:{SCID}:example.com")
PATHED = parse(f"did:webvh:{SCID}:example.com:dids:issuer")

LOG = b'{"versionId": "1-Qm"}\n'
WITNESS = b'[{"versionId": "1-Qm", "proof": []}]'


def result(did=DID, *, aliases=None, services=True) -> Verified:
    document = {"@context": ["https://www.w3.org/ns/did/v1"], "id": did.canonical}
    if aliases is not None:
        document["alsoKnownAs"] = aliases
    if services:
        document["service"] = [
            {
                "id": f"{did.canonical}#files",
                "type": "relativeRef",
                "serviceEndpoint": did.base_url(),
            },
            {
                "@context": "https://identity.foundation/linked-vp/contexts/v1",
                "id": f"{did.canonical}#whois",
                "type": "LinkedVerifiablePresentation",
                "serviceEndpoint": f"{did.base_url()}whois.vp",
            },
        ]
    return Verified(document=document, metadata={}, update_keys=("z6Mk",))


def web_form(did) -> str:
    return "did:web:" + did.canonical.removeprefix(f"did:webvh:{did.scid}:")


class TestWhereTheArtifactsLand:
    def test_a_bare_domain_publishes_under_well_known(self, tmp_path):
        directory = publish.publish(tmp_path, DID, result(), LOG, None)
        assert directory == tmp_path / ".well-known"
        assert (directory / "did.jsonl").exists()

    def test_path_segments_become_directories(self, tmp_path):
        directory = publish.publish(tmp_path, PATHED, result(PATHED), LOG, None)
        assert directory == tmp_path / "dids" / "issuer"

    def test_the_host_and_port_address_the_server_not_the_filesystem(self, tmp_path):
        ported = parse(f"did:webvh:{SCID}:example.com%3A3000:dids:issuer")
        directory = publish.publish(tmp_path, ported, result(ported), LOG, None)
        assert directory == tmp_path / "dids" / "issuer"


class TestTheLogIsVerbatim:
    def test_did_jsonl_is_byte_identical_to_what_was_submitted(self, tmp_path):
        """Asserted on bytes rather than on a reparse, because that is the whole claim."""
        odd = b'{"versionId":"1-Qm",  "extra":   1}\n\n'
        directory = publish.publish(tmp_path, DID, result(), odd, None)
        assert (directory / "did.jsonl").read_bytes() == odd

    def test_the_witness_file_is_verbatim_too(self, tmp_path):
        directory = publish.publish(tmp_path, DID, result(), LOG, WITNESS)
        assert (directory / "did-witness.json").read_bytes() == WITNESS

    def test_no_witness_file_appears_when_none_was_submitted(self, tmp_path):
        directory = publish.publish(tmp_path, DID, result(), LOG, None)
        assert not (directory / "did-witness.json").exists()


class TestTheParallelDidWeb:
    """this.i whgskdbb: did.json is the did:web form, and only when the log asks for it."""

    def test_no_did_json_without_a_commitment(self, tmp_path):
        directory = publish.publish(tmp_path, DID, result(), LOG, None)
        assert not (directory / "did.json").exists()

    def test_no_did_json_when_alsoknownas_names_something_else(self, tmp_path):
        verified = result(aliases=["did:web:elsewhere.example", "https://example.com/about"])
        directory = publish.publish(tmp_path, DID, verified, LOG, None)
        assert not (directory / "did.json").exists()

    def test_did_json_appears_when_the_log_commits_to_it(self, tmp_path):
        verified = result(aliases=[web_form(DID)])
        directory = publish.publish(tmp_path, DID, verified, LOG, None)
        assert (directory / "did.json").exists()

    def test_the_published_document_is_the_did_web_form(self, tmp_path):
        verified = result(aliases=[web_form(DID)])
        directory = publish.publish(tmp_path, DID, verified, LOG, None)
        document = json.loads((directory / "did.json").read_text())
        assert document["id"] == "did:web:example.com"
        assert DID.canonical in document["alsoKnownAs"]

    def test_the_scid_segment_is_replaced_everywhere_it_appears(self, tmp_path):
        verified = result(PATHED, aliases=[web_form(PATHED)])
        directory = publish.publish(tmp_path, PATHED, verified, LOG, None)
        document = json.loads((directory / "did.json").read_text())
        assert SCID not in json.dumps(document).replace(PATHED.canonical, "")
        assert document["service"][0]["id"] == "did:web:example.com:dids:issuer#files"

    def test_the_webvh_did_is_not_duplicated_in_alsoknownas(self, tmp_path):
        verified = result(aliases=[web_form(DID), DID.canonical])
        directory = publish.publish(tmp_path, DID, verified, LOG, None)
        aliases = json.loads((directory / "did.json").read_text())["alsoKnownAs"]
        assert aliases.count(DID.canonical) == 1

    def test_the_did_web_did_does_not_list_itself(self, tmp_path):
        verified = result(aliases=[web_form(DID)])
        directory = publish.publish(tmp_path, DID, verified, LOG, None)
        aliases = json.loads((directory / "did.json").read_text())["alsoKnownAs"]
        assert "did:web:example.com" not in aliases

    def test_implicit_services_are_added_when_the_document_lacks_them(self, tmp_path):
        verified = result(aliases=[web_form(DID)], services=False)
        directory = publish.publish(tmp_path, DID, verified, LOG, None)
        document = json.loads((directory / "did.json").read_text())
        kinds = {service["type"] for service in document["service"]}
        assert kinds == {"relativeRef", "LinkedVerifiablePresentation"}
        assert document["service"][0]["serviceEndpoint"] == "https://example.com/"

    def test_existing_services_are_not_duplicated(self, tmp_path):
        verified = result(aliases=[web_form(DID)])
        directory = publish.publish(tmp_path, DID, verified, LOG, None)
        document = json.loads((directory / "did.json").read_text())
        assert len(document["service"]) == 2

    def test_an_unrelated_service_survives_alongside_the_implicit_ones(self, tmp_path):
        verified = result(aliases=[web_form(DID)])
        verified.document["service"].append(
            {"id": f"{DID.canonical}#hub", "type": "Hub", "serviceEndpoint": "https://hub"}
        )
        directory = publish.publish(tmp_path, DID, verified, LOG, None)
        document = json.loads((directory / "did.json").read_text())
        assert {s["type"] for s in document["service"]} == {
            "relativeRef",
            "LinkedVerifiablePresentation",
            "Hub",
        }

    def test_the_verified_document_is_not_mutated(self, tmp_path):
        verified = result(aliases=[web_form(DID)], services=False)
        before = json.dumps(verified.document, sort_keys=True)
        publish.publish(tmp_path, DID, verified, LOG, None)
        assert json.dumps(verified.document, sort_keys=True) == before


class TestOrdering:
    """The specification requires the witness file to land before the log entry it covers."""

    def test_the_witness_file_is_written_before_the_log(self, tmp_path, monkeypatch):
        written: list[str] = []
        real = publish._place

        def spy(directory, name, payload):
            written.append(name)
            return real(directory, name, payload)

        monkeypatch.setattr(publish, "_place", spy)
        publish.publish(tmp_path, DID, result(aliases=[web_form(DID)]), LOG, WITNESS)
        assert written.index("did-witness.json") < written.index("did.jsonl")


class TestAllOrNone:
    def test_a_failure_after_an_earlier_artifact_landed_still_leaves_nothing(
        self, tmp_path, monkeypatch
    ):
        """The witness file lands first, so this is the mixture the ordering has to survive."""
        real = publish._place

        def explode(directory, name, payload):
            if name == "did.jsonl":
                raise OSError("disk full")
            return real(directory, name, payload)

        monkeypatch.setattr(publish, "_place", explode)
        with pytest.raises(BakoboError):
            publish.publish(tmp_path, DID, result(), LOG, WITNESS)
        assert list(tmp_path.iterdir()) == []

    def test_a_failure_leaves_no_artifact_tree(self, tmp_path, monkeypatch):
        real = publish._place

        def explode(directory, name, payload):
            if name == "did.jsonl":
                raise OSError("disk full")
            return real(directory, name, payload)

        monkeypatch.setattr(publish, "_place", explode)
        with pytest.raises(BakoboError) as raised:
            publish.publish(tmp_path, DID, result(), LOG, None)
        assert raised.value.code == "e.self.resource.publish.f"
        assert list(tmp_path.iterdir()) == []

    def test_a_failure_leaves_an_earlier_publication_intact(self, tmp_path, monkeypatch):
        directory = publish.publish(tmp_path, DID, result(), LOG, None)
        assert (directory / "did.jsonl").read_bytes() == LOG

        def explode(d, name, payload):
            raise OSError("disk full")

        monkeypatch.setattr(publish, "_place", explode)
        with pytest.raises(BakoboError):
            publish.publish(tmp_path, DID, result(), b"newer\n", None)
        assert (directory / "did.jsonl").read_bytes() == LOG

    def test_republishing_overwrites_in_place(self, tmp_path):
        publish.publish(tmp_path, DID, result(), LOG, None)
        directory = publish.publish(tmp_path, DID, result(), b'{"versionId": "2-Qm"}\n', None)
        assert (directory / "did.jsonl").read_bytes() == b'{"versionId": "2-Qm"}\n'

    def test_nothing_is_removed_on_republication(self, tmp_path):
        """The spec forbids making a published DID's resources unavailable."""
        publish.publish(tmp_path, DID, result(aliases=[web_form(DID)]), LOG, WITNESS)
        directory = publish.publish(tmp_path, DID, result(aliases=[web_form(DID)]), LOG, WITNESS)
        assert {p.name for p in directory.iterdir()} >= {
            "did.jsonl",
            "did.json",
            "did-witness.json",
        }

    def test_no_temporary_files_survive_a_successful_publication(self, tmp_path):
        directory = publish.publish(tmp_path, DID, result(aliases=[web_form(DID)]), LOG, WITNESS)
        assert {p.name for p in directory.iterdir()} == {
            "did.jsonl",
            "did.json",
            "did-witness.json",
        }


class TestTheEdgesOfAtomicity:
    def test_a_rename_failure_leaves_no_temporary_file(self, tmp_path, monkeypatch):
        """The temp file is written before the rename, so the rename failing is the one moment a
        stray .did.jsonl.XXXX.tmp could survive under a customer's web root."""
        def explode(src, dst):
            raise OSError("cross-device link")

        monkeypatch.setattr(publish.os, "replace", explode)
        with pytest.raises(BakoboError):
            publish.publish(tmp_path, DID, result(), LOG, None)
        assert list(tmp_path.rglob("*.tmp")) == []
        assert list(tmp_path.iterdir()) == []

    def test_unwinding_stops_at_a_directory_that_is_not_ours(self, tmp_path, monkeypatch):
        """A failed first publication must not take a sibling DID's directory with it."""
        neighbour = tmp_path / "dids" / "other"
        neighbour.mkdir(parents=True)
        (neighbour / "did.jsonl").write_bytes(b"someone else\n")

        def explode(src, dst):
            raise OSError("disk full")

        monkeypatch.setattr(publish.os, "replace", explode)
        with pytest.raises(BakoboError):
            publish.publish(tmp_path, PATHED, result(PATHED), LOG, None)
        assert (neighbour / "did.jsonl").read_bytes() == b"someone else\n"
        assert not (tmp_path / "dids" / "issuer").exists()
