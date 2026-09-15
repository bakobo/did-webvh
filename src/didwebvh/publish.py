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

__all__ = ["DID_JSON", "DID_JSONL", "DID_WITNESS", "publish", "to_did_web"]

DID_JSONL = "did.jsonl"
DID_JSON = "did.json"
DID_WITNESS = "did-witness.json"

#: The implicit services every did:webvh DID has, whether or not its document lists them. Both
#: are added to the parallel did:web document when absent, because a did:web resolver has no
#: did:webvh rules to derive them from and would otherwise lose the DID's files and whois.
_FILES = "relativeRef"
_WHOIS = "LinkedVerifiablePresentation"


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

    Follows the specification's steps in order: add the implicit services if absent, replace the
    ``did:webvh:<scid>:`` prefix throughout, put the did:webvh DID in ``alsoKnownAs``, and drop
    duplicates including the did:web DID itself.
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
    _ensure_services(working, did)
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


def _ensure_services(document: dict, did: WebvhDid) -> None:
    """Add whichever implicit service the document is missing, leaving any other service alone."""
    services = document.setdefault("service", [])
    present = {service.get("type") for service in services if isinstance(service, dict)}
    if _FILES not in present:
        services.insert(
            0,
            {
                "id": f"{did.canonical}#files",
                "type": _FILES,
                "serviceEndpoint": did.base_url(),
            },
        )
    if _WHOIS not in present:
        services.append(
            {
                "@context": "https://identity.foundation/linked-vp/contexts/v1",
                "id": f"{did.canonical}#whois",
                "type": _WHOIS,
                "serviceEndpoint": f"{did.base_url()}whois.vp",
            }
        )


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
