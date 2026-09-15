"""didwebvh.verify — driving the library's walk, and owning what it says when it refuses.

didwebvh-py verifies the hash chain, the entry hashes, the SCID derivation, the Data Integrity
proofs against the active update keys, pre-rotation, and witness thresholds. This module drives
that (this.i 327yhyvd) and translates its refusals into Bakobo error codes. It does not
re-implement any of it: a partial second verifier is a weaker verifier that drifts.

**Why ``DidResolver`` and not the pieces.** Assembling ``load_history_line`` and
``HistoryVerifier.verify_state`` by hand looks equivalent and is not. ``check_version_id()`` --
the entry-hash check, which is most of what makes a log a chain rather than a list -- is invoked
only from ``DidResolver``'s own loop (``core/resolver.py:381``), and witness verification only
from ``resolve_state``. A hand-rolled walk would verify proofs and silently skip the chain, which
is the failure this module most needs to avoid.

**Why an in-memory history source.** ``LocalHistoryResolver`` takes a path and reads it, which
would be a second read of a file our doors already bounded, unbounded and after the fact
(this.i 43ukbqca). ``HistoryResolver`` is the library's own extension point, so
:class:`_Submitted` hands over the text we already hold. No file, no socket, no second read.

**The mapping is proven total, not maintained by hand.** ``tests/test_verify.py`` walks the
installed ``did_webvh`` package for every problem type it can emit and fails if one has no entry
in :data:`PROBLEMS`. That is the test that earns its keep on a pin bump: a new failure mode
upstream becomes a failing build here rather than an internal-fault message in production.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

from did_webvh.core.file_utils import AsyncTextReadError, read_str
from did_webvh.core.resolver import DidResolver, HistoryResolver, HistoryVerifier
from did_webvh.core.state import DocumentState

from didwebvh import errors
from didwebvh.did import WebvhDid

__all__ = ["PROBLEMS", "Verified", "verify"]

#: Every problem type the pinned library can report, and the Bakobo code it becomes. Grouped by
#: what the submitter would have to *do*, which is what an error code is for -- several upstream
#: types share a code because they share a remedy.
PROBLEMS = {
    # The log is not authentic: cryptography disagreed with the bytes.
    "#proof-verification-failed": errors.LOG_SIGNATURE_FAILED,
    "#witness-verification-failed": errors.LOG_WITNESS_FAILED,
    "#hash-chain-broken": errors.LOG_HASH_FAILED,
    "#scid-verification-failed": errors.LOG_HASH_FAILED,
    "#version-mismatch": errors.LOG_HASH_FAILED,
    # The log is well-signed but structurally wrong.
    "#invalid-log-entry": errors.LOG_MALFORMED_DEEP,
    "#invalid-parameter": errors.LOG_MALFORMED_DEEP,
    "#invalid-document": errors.LOG_MALFORMED_DEEP,
    "#invalid-did-document": errors.LOG_MALFORMED_DEEP,
    # The log is fine but is not this DID's, or moved without permission to.
    "#did-log-id-mismatch": errors.LOG_DID_MISMATCH,
    "#portability-disabled": errors.LOG_NOT_PORTABLE,
    # Nothing to read.
    "#missing-log": errors.LOG_UNREADABLE,
    # We drove the library wrongly. Not the submitter's problem, and it must not read like one.
    "#invalid-resolution-parameter": errors.RESOLUTION_MISDRIVEN,
}


@dataclass(frozen=True)
class Verified:
    """What survived the walk.

    Attributes:
        document: the resolved DID document, computed from the verified log.
        metadata: the DID document metadata -- created, updated, deactivated, scid, versionId,
            portable, witness and watchers.
        update_keys: the multikeys authorized to sign the log's next entry, after the
            specification's parameter inheritance has been applied across the whole log. The AID
            binding (this.i k6fiebmm) is a claim about exactly this set.
    """

    document: dict
    metadata: dict
    update_keys: tuple[str, ...]


class _Submitted(HistoryResolver):
    """A history source over text this package has already read and bounded."""

    def __init__(self, log: str, witness: str | None = None):
        self._log = log
        self._witness = witness

    def resolve_entry_log(self, _document_id: str | None):
        """Hand the library the log we already hold."""
        return read_str(self._log)

    def resolve_witness_log(self, _document_id: str | None):
        """Hand over the witness file, or report its absence the way a file source would.

        Raising ``AsyncTextReadError`` rather than a Bakobo error is deliberate: the library
        catches it and turns it into ``#missing-log``, which :data:`PROBLEMS` maps like every
        other refusal. Raising our own here would be a second refusal path that the totality
        test cannot see.
        """
        if self._witness is None:
            raise AsyncTextReadError("No witness proofs were submitted")
        return read_str(self._witness)


def verify(log: bytes, did: WebvhDid, witness: bytes | None = None) -> Verified:
    """Verify a DID log from genesis and return what it resolves to.

    The whole log, every time, rather than incrementally from the published tail: Bakobo's own
    prior output is not an input to this decision (this.i gzvt7mpn).

    Args:
        log: the submitted ``did.jsonl``, exactly as it crossed the door.
        did: the DID being published. The resolved document must claim to be this DID.
        witness: the submitted ``did-witness.json``, when one was supplied.

    Returns:
        The resolved document and its metadata.

    Raises:
        bakobo.errors.BakoboError: whichever code :data:`PROBLEMS` maps the library's refusal to.
    """
    if not log.strip():
        # ~2qhs The pinned library hangs forever on an empty log rather than reporting
        # #missing-log: DidResolver.resolve over read_str("") never returns, with no didwebvh
        # code involved. bounds.open_log already refuses an empty file, so nothing reaches here
        # through the CLI -- this is the second lock on the same door, because a hang is the one
        # failure mode that cannot be caught downstream.
        raise errors.LOG_UNREADABLE(did=did.canonical, detail="the log is empty")
    result = asyncio.run(_resolve(log, did, witness))
    if result.resolution_metadata:
        raise _refusal(result.resolution_metadata, did)
    return Verified(
        document=result.document,
        metadata=result.document_metadata,
        update_keys=_active_update_keys(log),
    )


def _active_update_keys(log: bytes) -> tuple[str, ...]:
    """Replay an already-verified log to read off the update keys it ends with.

    A second pass, deliberately. `DidResolver` does not surface the final `DocumentState`, and
    `updateKeys` is inherited across entries rather than restated, so reading the last line's
    parameters would be wrong whenever the log did not restate them. Re-deriving the inheritance
    here would be reimplementing `_update_params`, which is exactly what this package does not do.

    This carries no security weight and could not: it runs only after the library has accepted
    the log, and re-reads the same bytes with the same parser. It is a projection, not a check.
    """
    state = None
    for line in log.decode("utf-8").splitlines():
        if line.strip():
            state = DocumentState.load_history_line(json.loads(line), state)
    return tuple(state.update_keys)


async def _resolve(log: bytes, did: WebvhDid, witness: bytes | None):
    source = _Submitted(
        log.decode("utf-8"), witness.decode("utf-8") if witness is not None else None
    )
    return await DidResolver(HistoryVerifier()).resolve(did.canonical, source)


def _refusal(metadata: dict, did: WebvhDid):
    """Turn the library's resolution metadata into the error this package raises.

    An unmapped problem type is reported as our fault rather than the submitter's. That is the
    honest attribution -- the submission may be perfectly good and the gap is in our mapping --
    and ``tests/test_verify.py`` is what stops it ever happening for a type the pinned library
    can actually emit.
    """
    details = metadata.get("problemDetails")
    if isinstance(details, list):
        details = details[0] if details else None
    kind = _kind(details)
    detail = (details or {}).get("detail") or (details or {}).get("title") or metadata["error"]
    code = PROBLEMS.get(kind)
    if code is None:
        return errors.RESOLUTION_UNMAPPED(did=did.canonical, kind=kind or "an unnamed problem")
    return code(did=did.canonical, detail=detail)


def _kind(details: dict | None) -> str | None:
    """The problem type, as the fragment the library names it by.

    ``ProblemDetails`` prefixes a leading-``#`` type with its spec URI on construction, so what
    arrives is a full URL and what :data:`PROBLEMS` is keyed by is the fragment.
    """
    if not details or not isinstance(details.get("type"), str):
        return None
    _, separator, fragment = details["type"].partition("#")
    return f"#{fragment}" if separator else details["type"]
