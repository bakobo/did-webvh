"""The operator contract, and the negative matrix swept once more at the outermost edge.

Every refusal has already been tested against the module that raises it. What this file adds is
the promise an operator actually relies on: the exit status, one line on stderr carrying a stable
code, and -- for every way a submission can be refused -- no artifact tree left behind.
"""

from __future__ import annotations

import json

import pytest
from did_webvh.askar import AskarSigningKey
from did_webvh.core.proof import di_jcs_sign
from did_webvh.core.state import DocumentState
from test_verify import mint, rebuild, relines

from didwebvh import cli


def write(tmp_path, name: str, payload: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(payload)
    return str(path)


def invoke(tmp_path, *, log: bytes, did=None, witness=None, out=None):
    """Run `didwebvh publish`, returning its exit status."""
    argv = ["publish", "--log", write(tmp_path, "did.jsonl", log)]
    argv += ["--did", did]
    argv += ["--out", str(out if out is not None else tmp_path / "www")]
    if witness is not None:
        argv += ["--witness", write(tmp_path, "did-witness.json", witness)]
    return cli.main(argv)


def artifacts(root) -> set[str]:
    return {p.name for p in root.rglob("*") if p.is_file()}


class TestTheHappyPath:
    def test_a_good_submission_publishes_and_exits_zero(self, tmp_path, capsys):
        did, log, _ = mint()
        out = tmp_path / "www"
        assert invoke(tmp_path, log=log, did=did.canonical, out=out) == 0
        assert artifacts(out) == {"did.jsonl"}
        assert (out / ".well-known" / "did.jsonl").read_bytes() == log

    def test_it_prints_the_path_of_every_artifact_written(self, tmp_path, capsys):
        did, log, _ = mint()
        out = tmp_path / "www"
        invoke(tmp_path, log=log, did=did.canonical, out=out)
        printed = capsys.readouterr().out.splitlines()
        assert printed == [str(out / ".well-known" / "did.jsonl")]


class TestUsageErrors:
    """Exit 64: the invocation was wrong and no submission was read."""

    def test_an_unknown_verb(self, tmp_path, capsys):
        assert cli.main(["mint"]) == cli.EX_USAGE

    def test_no_verb_at_all(self):
        assert cli.main([]) == cli.EX_USAGE

    def test_a_missing_required_flag(self, tmp_path):
        assert cli.main(["publish", "--out", str(tmp_path)]) == cli.EX_USAGE

    def test_an_unreadable_log(self, tmp_path, capsys):
        did, _, _ = mint()
        status = cli.main(
            ["publish", "--did", did.canonical, "--log",
             str(tmp_path / "nope.jsonl"), "--out", str(tmp_path)]
        )
        assert status == cli.EX_USAGE
        assert "could not be read" in capsys.readouterr().err

    def test_an_unreadable_witness_file(self, tmp_path, capsys):
        did, log, _ = mint()
        status = cli.main(
            ["publish", "--did", did.canonical, "--log", write(tmp_path, "did.jsonl", log),
             "--witness", str(tmp_path / "nope.json"), "--out", str(tmp_path / "www")]
        )
        assert status == cli.EX_USAGE
        assert "--witness" in capsys.readouterr().err

    def test_a_usage_error_publishes_nothing(self, tmp_path):
        did, _, _ = mint()
        out = tmp_path / "www"
        cli.main(["publish", "--did", did.canonical, "--log",
                  str(tmp_path / "nope.jsonl"), "--out", str(out)])
        assert not out.exists()


class TestTheNegativeMatrix:
    """Exit 1, a stable code on stderr, and no artifact tree. Once per refusing module."""

    def refuse(self, tmp_path, **kwargs) -> tuple[int, str]:
        out = tmp_path / "www"
        status = invoke(tmp_path, out=out, **kwargs)
        return status, out

    def test_an_unparseable_did(self, tmp_path, capsys):
        _, log, _ = mint()
        status, out = self.refuse(tmp_path, log=log, did="did:webvh:nope")
        assert status == cli.EX_FAILURE
        assert "e.input.format.did-webvh.f" in capsys.readouterr().err
        assert not out.exists()

    def test_a_log_that_is_not_json_lines(self, tmp_path, capsys):
        did, _, _ = mint()
        status, out = self.refuse(tmp_path, log=b"not json\n", did=did.canonical)
        assert status == cli.EX_FAILURE
        assert "e.input.format.log.f" in capsys.readouterr().err
        assert not out.exists()

    def test_a_log_the_clamp_refuses(self, tmp_path, capsys):
        """A P-256 log: minted and resolved by the reference implementation, refused here."""
        did, log, _ = mint()
        lines = relines(log)
        lines[0]["proof"][0]["cryptosuite"] = "ecdsa-jcs-2019"
        status, out = self.refuse(tmp_path, log=rebuild(lines), did=did.canonical)
        assert status == cli.EX_FAILURE
        assert "e.rule.conformance.cryptosuite.f" in capsys.readouterr().err
        assert not out.exists()

    def test_a_log_whose_proof_does_not_verify(self, tmp_path, capsys):
        did, log, _ = mint(entries=2)
        lines = relines(log)
        lines[1]["state"]["alsoKnownAs"] = ["did:web:attacker.example"]
        status, out = self.refuse(tmp_path, log=rebuild(lines), did=did.canonical)
        assert status == cli.EX_FAILURE
        assert "e.proof.log." in capsys.readouterr().err
        assert not out.exists()

    def test_a_log_for_a_different_did(self, tmp_path, capsys):
        """The clamp catches this before the walk does, because the SCID in the log is not the
        SCID in the DID being published -- an earlier and cheaper check than resolving the whole
        log and comparing document ids. Either refusal is correct; this asserts which one wins,
        so that the ordering is a decision rather than an accident."""
        _, log, _ = mint()
        other, _, _ = mint()
        status, out = self.refuse(tmp_path, log=log, did=other.canonical)
        assert status == cli.EX_FAILURE
        assert "e.rule.conformance.parameter.f" in capsys.readouterr().err
        assert not out.exists()

    def test_a_witness_file_off_the_data_model(self, tmp_path, capsys):
        did, log, _ = mint()
        status, out = self.refuse(tmp_path, log=log, did=did.canonical, witness=b"{}")
        assert status == cli.EX_FAILURE
        assert "e.input.format.witness.f" in capsys.readouterr().err
        assert not out.exists()

    def test_every_refusal_prints_exactly_one_line(self, tmp_path, capsys):
        did, _, _ = mint()
        self.refuse(tmp_path, log=b"not json\n", did=did.canonical)
        assert len(capsys.readouterr().err.strip().splitlines()) == 1


class TestInternalFaults:
    def test_an_unexpected_exception_is_reported_as_ours(self, tmp_path, capsys, monkeypatch):
        """A traceback must never reach an operator looking like a bad submission."""
        did, log, _ = mint()

        def explode(*args, **kwargs):
            raise RuntimeError("something we did not anticipate")

        monkeypatch.setattr(cli.clamp, "clamp", explode)
        status = invoke(tmp_path, log=log, did=did.canonical)
        assert status == cli.EX_FAILURE
        captured = capsys.readouterr().err
        assert "e.self.unknown.f" in captured
        assert "the resolver" not in captured, "a disk-full fault must not blame the resolver"
        assert "Traceback" not in captured


class TestWitnessedSubmissions:
    def test_a_witnessed_log_publishes_all_three_files(self, tmp_path):
        witness = AskarSigningKey.generate("ed25519")
        witness.kid = f"did:key:{witness.multikey}#{witness.multikey}"
        did, log, _ = mint(
            witness={"threshold": 1, "witnesses": [{"id": f"did:key:{witness.multikey}"}]}
        )
        container = {"versionId": relines(log)[0]["versionId"]}
        container["proof"] = [di_jcs_sign(container, witness)]
        out = tmp_path / "www"
        status = invoke(
            tmp_path,
            log=log,
            did=did.canonical,
            witness=json.dumps([container]).encode(),
            out=out,
        )
        assert status == 0
        assert artifacts(out) == {"did.jsonl", "did-witness.json"}


class TestEvidenceMustMatchClaims:
    """Both evidence arguments obey one rule: supplied without a claim is refused, not ignored."""

    def test_a_witness_file_for_a_log_naming_no_witnesses_is_refused(self, tmp_path, capsys):
        """Panel finding CON-F1: this used to exit 0 and publish did-witness.json under the
        customer's domain -- a file no resolver has a rule for reading."""
        did, log, _ = mint()
        container = {"versionId": relines(log)[0]["versionId"], "proof": []}
        out = tmp_path / "www"
        status = invoke(
            tmp_path, log=log, did=did.canonical, witness=json.dumps([container]).encode(), out=out
        )
        assert status == cli.EX_FAILURE
        assert "e.rule.witness.unused-evidence.f" in capsys.readouterr().err
        assert not out.exists()

    def test_a_witnessed_log_with_proofs_from_a_stranger_is_refused(self, tmp_path, capsys):
        """Panel finding TST-F3: the operator contract at the CLI for a failing witness threshold."""
        listed, stranger = AskarSigningKey.generate("ed25519"), AskarSigningKey.generate("ed25519")
        stranger.kid = f"did:key:{stranger.multikey}#{stranger.multikey}"
        did, log, _ = mint(
            witness={"threshold": 1, "witnesses": [{"id": f"did:key:{listed.multikey}"}]}
        )
        container = {"versionId": relines(log)[0]["versionId"]}
        container["proof"] = [di_jcs_sign(container, stranger)]
        out = tmp_path / "www"
        status = invoke(
            tmp_path, log=log, did=did.canonical, witness=json.dumps([container]).encode(), out=out
        )
        assert status == cli.EX_FAILURE
        assert "e.proof.log.witness.f" in capsys.readouterr().err
        assert not out.exists()


class TestTheHostingStance:
    """this.i plhyphrk: a document claiming another party's identity is refused, not republished.

    Not a verification failure. Nothing is checked, because nothing in either method makes such a
    claim checkable and a did:webvh artifact has nowhere to record that a host tried.
    """

    def claiming(self, alias: str):
        key = AskarSigningKey.generate("ed25519")
        document = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:{SCID}:example.com",
            "alsoKnownAs": [alias],
        }
        state = DocumentState.initial(
            {"updateKeys": [key.multikey], "method": "did:webvh:1.0"}, document
        )
        state.sign(key)
        return state.document_id, (json.dumps(state.history_line()) + "\n").encode()

    def test_a_did_webs_alias_is_refused(self, tmp_path, capsys):
        did, log = self.claiming("did:webs:example.com:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe")
        out = tmp_path / "www"
        assert invoke(tmp_path, log=log, did=did, out=out) == cli.EX_FAILURE
        assert "e.rule.hosting.foreign-alias.f" in capsys.readouterr().err
        assert not out.exists()

    def test_the_refusal_says_it_is_our_policy_not_the_method(self, tmp_path, capsys):
        """A customer whose log is fine elsewhere must not read this as 'your log is broken'."""
        did, log = self.claiming("did:webs:example.com:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe")
        invoke(tmp_path, log=log, did=did)
        message = capsys.readouterr().err
        assert "hosting policy" in message
        assert "another host may well publish it" in message

    @pytest.mark.parametrize(
        "alias",
        [
            "did:web:example.com",
            "https://example.com/about",
            "did:key:z6MkabcDEF",
            "did:webvh:QmaigaGjpv2GNnN5D2tyd1XZLY8PnRTDtgHYCiV964ooMn:other.example",
        ],
    )
    def test_every_other_kind_of_alias_publishes_untouched(self, tmp_path, alias):
        """The refusal is narrow. An ordinary URL, a did:web, a key, even another did:webvh --
        none of them is a claim about a KERI-identified third party."""
        did, log = self.claiming(alias)
        out = tmp_path / "www"
        assert invoke(tmp_path, log=log, did=did, out=out) == 0
        assert (out / ".well-known" / "did.jsonl").exists()
