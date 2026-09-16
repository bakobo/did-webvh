"""didwebvh.publish — writing the artifacts where the DID says they live.

Three files, three different relationships to the truth. ``did.jsonl`` is the submitted bytes,
unchanged, because a Data Integrity proof covers exact bytes and anything re-serialized would
stop verifying (this.i gzvt7mpn). ``did-witness.json`` is likewise the submitted bytes, for the
same reason. ``did.json`` is *computed*, and appears only when the log commits to it
(this.i whgskdbb).

**Why the temporary file.** A resolver may fetch any of these at any moment, including while a
publication is being written. Writing in place would serve a truncated document to whoever asked
during the write; writing beside the target and renaming means a reader sees the old artifact or
the new one and never a prefix of either.

**Why the witness file goes first.** The specification is explicit: witness proofs "MUST be added
to the ``did-witness.json`` file and that file published **BEFORE** publishing the DID Log file
containing the new DID Log entry", so a resolver never meets an entry whose proofs have not
arrived. The consequence it names -- a witness file may carry proofs for entries that are not
published yet -- is ordinary, and resolvers are told to ignore them.

**Where the guarantee stops.** Three files cannot be renamed in one atomic step on a POSIX
filesystem. Each artifact is wholly old or wholly new; a crash between renames leaves a mixture.
The order is chosen so the mixture is the harmless one: witness proofs ahead of the log they
cover, and the derived document last, since a stale did.json beside a fresh log is a document a
did:web resolver reads as merely out of date, while the reverse would be a log whose witness
proofs had not landed.
"""

from __future__ import annotations

import json
import os
import tempfile
from copy import deepcopy
from pathlib import Path

from didwebvh import errors
from didwebvh.did import WebvhDid
from didwebvh.verify import Verified

__all__ = ["DID_JSON", "DID_JSONL", "DID_WITNESS", "WEBS", "publish", "refuse_foreign_alias", "to_did_web"]

#: The did:webs method prefix. An alsoKnownAs entry beginning with it names a KERI AID, which is
#: another party's identity as far as this document is concerned.
WEBS = "did:webs:"

DID_JSONL = "did.jsonl"
DID_JSON = "did.json"
DID_WITNESS = "did-witness.json"

def refuse_foreign_alias(document: dict, did: WebvhDid) -> None:
    """Refuse a document that claims another party's identity (this.i plhyphrk).

    Not a verification failure -- nothing is checked here, and nothing could be. Neither did:webvh
    nor did:webs defines a verifiable link between a did:webvh DID and a foreign identity, and a
    did:webvh artifact has nowhere to record that a host checked one, so any assurance would be
    invisible to every party that reads the published document. Rather than republish an unchecked
    assertion about a third party under a customer's domain and over Bakobo's name, this refuses.

    A hosting policy, stated as one. The method permits the alias and another host may publish it.
    The sibling repo reached the same position from the other side: did-webs drops an alias whose
    AID binding it cannot check, "because publishing an unverifiable alias under Bakobo's domain
    would fail open".

    Everything else in ``alsoKnownAs`` is untouched -- an ordinary URL, a did:web, the DID's own
    prior string after a move. Only a foreign *identity* claim is refused.

    Raises:
        bakobo.errors.BakoboError: ``e.rule.hosting.foreign-alias.f``.
    """
    aliases = document.get("alsoKnownAs", [])
    if not isinstance(aliases, list):
        return  # shape is the door's business; a non-list carries no alias to refuse
    for alias in aliases:
        if isinstance(alias, str) and alias.startswith(WEBS):
            raise errors.FOREIGN_ALIAS_REFUSED(did=did.canonical, alias=alias)


def publish(
    out: Path | str,
    did: WebvhDid,
    verified: Verified,
    log: bytes,
    witness: bytes | None,
) -> Path:
    """Write this DID's artifacts under ``out``, or write nothing at all.

    Args:
        out: the directory the DID's host serves from.
        did: the DID being published, which decides the subdirectory.
        verified: the resolved document, for deriving ``did.json``.
        log: the submitted ``did.jsonl``, published unchanged.
        witness: the submitted ``did-witness.json``, published unchanged, or None.

    Returns:
        The directory the artifacts were written to.

    Raises:
        bakobo.errors.BakoboError: ``e.self.resource.publish.f`` if any artifact cannot be
            written. A DID published here for the first time leaves nothing behind at all. A
            *re*-publication cannot be rolled back, because a rename over an existing artifact
            destroys it -- what survives is the mixture the write order makes harmless. See
            :func:`_unwind`.
    """
    directory = Path(out).joinpath(*did.artifact_parts())
    web = to_did_web(verified.document, did)

    created = not directory.exists()
    written: list[Path] = []
    try:
        directory.mkdir(parents=True, exist_ok=True)
        if witness is not None:
            written.append(_place(directory, DID_WITNESS, witness))
        written.append(_place(directory, DID_JSONL, log))
        if web is not None:
            written.append(_place(directory, DID_JSON, json.dumps(web, indent=2).encode() + b"\n"))
    except OSError as exc:
        _unwind(written, directory, Path(out), created)
        raise errors.PUBLISH_FAILED(did=did.canonical, problem=str(exc)) from exc
    return directory


def to_did_web(document: dict, did: WebvhDid) -> dict | None:
    """The parallel ``did:web`` document, or None when the log does not ask for one.

    The trigger is the resolved document naming the corresponding ``did:web`` DID in
    ``alsoKnownAs``. That array is inside the signed state, so it is the controller's own
    commitment -- the same role the designated-aliases ACDC plays in did:webs, where the host
    likewise publishes a second identifier only because the controller authorized it.

    Follows the specification's steps in order. Step 2 -- adding the implicit services when
    absent -- has already happened by the time this runs: :func:`didwebvh.verify.verify` puts them
    in the resolved document, because that is where every other implementation puts them. What is
    left here is the prefix replacement, the ``alsoKnownAs`` entry, and the deduplication.
    """
    web_did = f"did:web:{did.canonical.removeprefix(f'did:webvh:{did.scid}:')}"
    if web_did not in document.get("alsoKnownAs", []):
        return None

    # The string replacement is deliberate and a structural walk would be wrong. The specification
    # says to "execute a text replacement across the DIDDoc", because the prefix appears inside
    # longer strings -- verification-method ids, controller fields, service ids and endpoints --
    # not only as whole values. A recursive dict walk that rewrote values would leave those
    # embedded occurrences pointing at did:webvh, producing a mixed-prefix document that a did:web
    # resolver rejects (panel finding MNT-F3).
    working = deepcopy(document)
    transformed = json.loads(
        json.dumps(working).replace(f"did:webvh:{did.scid}:", "did:web:")
    )
    aliases = [*transformed.get("alsoKnownAs", []), did.canonical]
    transformed["alsoKnownAs"] = [
        alias
        for position, alias in enumerate(aliases)
        if alias != web_did and alias not in aliases[:position]
    ]
    return transformed


def _place(directory: Path, name: str, payload: bytes) -> Path:
    """Write one artifact, atomically, by rename within the destination directory.

    The temporary file is created in the destination rather than the system temp directory,
    because a rename is only atomic within one filesystem. It is flushed and fsynced before the
    rename, so a crash cannot leave the new name pointing at bytes that never reached the disk.
    """
    handle, temporary = tempfile.mkstemp(dir=directory, prefix=f".{name}.", suffix=".tmp")
    try:
        with os.fdopen(handle, "wb") as file:
            file.write(payload)
            file.flush()
            os.fsync(file.fileno())
        target = directory / name
        os.replace(temporary, target)
        return target
    except OSError:
        Path(temporary).unlink(missing_ok=True)
        raise


def _unwind(written: list[Path], directory: Path, root: Path, created: bool) -> None:
    """Undo a failed publication, as far as it is honest to.

    **A first publication leaves nothing.** Artifacts that landed before the failure are removed
    and the directories this call created are pruned, so "either every artifact appears or none
    does" holds for a DID that was not published here before. Without this the witness file --
    which lands first, deliberately -- would survive a failure on the log, leaving proofs for an
    entry nobody can read.

    **A republication is not rolled back, because it cannot be.** ``os.replace`` over an existing
    artifact destroys the previous one, so there is nothing to restore and pretending otherwise
    by deleting what is there would turn a partial update into an outage. What survives is the
    mixture the write order was chosen to make harmless: witness proofs ahead of the log they
    cover, which is the direction the specification asks for anyway, and a did.json that is
    merely stale. Saying this plainly matters more than the code: an operator retrying a failed
    republication is retrying over a live DID, not a clean slate.
    """
    if not created:
        return
    for artifact in written:
        artifact.unlink(missing_ok=True)
    walked = directory
    while walked != root:
        try:
            walked.rmdir()
        except OSError:
            return
        walked = walked.parent
