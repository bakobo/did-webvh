"""didwebvh.bounds — the three doors everything crosses through.

Every byte this process reads from outside arrives through one of the openers here, and is
bounded before it is parsed (this.i constraint 43ukbqca; dev/standards/input-handling.md). Size
first, then shape, then meaning: the clamp, the library's walk and the AID binding are all
judgments about what bytes *mean*, and none of them starts if the submission is simply too large.

**The doors decide how many and what shape, never what it means.** :func:`open_log` will accept a
log whose proofs are forged and whose hashes are wrong, so long as it is JSON Lines of objects
carrying the five required members. That is deliberate: a door that also judged meaning would be
a second, weaker verifier that could drift from the real one.

**The numbers are flood guards.** They are not opinions about what a legitimate payload weighs and
should not be tuned as though they were. A did:webvh entry carries a whole DID document and runs a
few kilobytes; a DID rotating weekly for two centuries would not reach :data:`MAX_ENTRIES`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from didwebvh import errors
from didwebvh.did import WebvhDid

__all__ = [
    "DOORS",
    "LOG",
    "MAX_ENTRIES",
    "MAX_ENTRY_BYTES",
    "STREAM",
    "WITNESS",
    "Admitted",
    "Door",
    "open_log",
    "open_stream",
    "open_witness",
    "read_bounded",
]

_MIB = 1024 * 1024


@dataclass(frozen=True)
class Admitted:
    """One artifact that got through its door: the exact bytes, and the parsed view of them.

    Both halves travel together because both are needed and they must not drift. did.jsonl is
    published byte-for-byte (this.i gzvt7mpn) while the clamp and the library reason over the
    parse, so re-reading the file to get the bytes back would mean a second, unbounded read of
    something that could have changed underneath.

    Attributes:
        raw: exactly what crossed the door.
        parsed: the objects ``raw`` decodes to, in file order.
    """

    raw: bytes
    parsed: tuple[dict, ...]


@dataclass(frozen=True)
class Door:
    """One named entrance, for one kind of input, carrying that kind's bound.

    Attributes:
        kind: the artifact this door admits. Also names the opener (``open_<kind>``) and the
            trailing token of the range code the door raises.
        limit: the most bytes that may cross, in bytes.
    """

    kind: str
    limit: int


#: The DID log. Large enough for a decade of daily rotations carrying full DID documents.
LOG = Door("log", 8 * _MIB)

#: The KEL stream backing the AID binding: a KEL, its TELs, and the designated-aliases ACDC.
STREAM = Door("stream", 8 * _MIB)

#: The witness proof file, which holds one proof set per log entry.
WITNESS = Door("witness", 4 * _MIB)

#: Every door. The census test and the completeness tests both read this rather than a list kept
#: by hand, so adding a door is one edit and forgetting to register one is a failure.
DOORS = (LOG, STREAM, WITNESS)

#: The most bytes one log entry may occupy. A whole DID document is a few kilobytes; this is three
#: orders of magnitude above that, and stops one entry consuming the entire file bound.
MAX_ENTRY_BYTES = 1 * _MIB

#: The most entries one log may carry.
MAX_ENTRIES = 10_000

#: The members every log entry carries, and the JSON types each must have. ``proof`` may be a
#: single object or an array; Data Integrity permits either and the spec's examples use both.
_REQUIRED = {
    "versionId": str,
    "versionTime": str,
    "parameters": dict,
    "state": dict,
    "proof": (dict, list),
}

#: The members every ``did-witness.json`` element carries.
_REQUIRED_WITNESS = {"versionId": str, "proof": list}


def read_bounded(handle: BinaryIO, door: Door, did: WebvhDid) -> bytes:
    """Read at most ``door.limit`` bytes from ``handle``, refusing anything longer.

    Reads one byte past the bound and refuses on the overage, so the process never holds more
    than ``limit + 1`` however much the far end has. A length check that first reads the whole
    thing is not a bound (dev/standards/input-handling.md, rubric 1).

    Args:
        handle: an open binary stream.
        door: the door whose bound applies.
        did: the DID being published, for the refusal message.

    Returns:
        The bytes read.

    Raises:
        bakobo.errors.BakoboError: ``e.input.range.<kind>.f`` when the input exceeds the bound.
    """
    payload = handle.read(door.limit + 1)
    if len(payload) > door.limit:
        raise errors.TOO_LARGE[door.kind](
            did=did.canonical, bound="the file", limit=door.limit
        )
    return payload


def _read(path: Path | str, door: Door, did: WebvhDid) -> bytes:
    with open(path, "rb") as handle:  # door: the only read for this kind
        return read_bounded(handle, door, did)


def open_log(path: Path | str, did: WebvhDid) -> Admitted:
    """Admit a DID log: JSON Lines, one object per line, each carrying the required members.

    Args:
        path: the submitted ``did.jsonl``.
        did: the DID being published, for refusal messages.

    Returns:
        The submitted bytes, and the entries they decode to in file order. Their *meaning* is
        unexamined -- see the module docstring.

    Raises:
        bakobo.errors.BakoboError: ``e.input.range.log.f`` past a bound, or
            ``e.input.format.log.f`` off the JSON Lines shape.
    """
    payload = _read(path, LOG, did)
    lines = payload.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()  # one trailing newline is ordinary, not an empty final entry
    if not lines:
        raise errors.LOG_MALFORMED(did=did.canonical, line=0, problem="the log is empty")
    if len(lines) > MAX_ENTRIES:
        raise errors.LOG_TOO_LARGE(did=did.canonical, bound="the entry count", limit=MAX_ENTRIES)

    entries = tuple(_entry(line, number, did) for number, line in enumerate(lines, start=1))
    return Admitted(raw=payload, parsed=entries)


def _entry(line: bytes, number: int, did: WebvhDid) -> dict:
    """Validate one log line's size and shape, and return it parsed."""
    if len(line) > MAX_ENTRY_BYTES:
        raise errors.LOG_TOO_LARGE(
            did=did.canonical, bound=f"entry {number}", limit=MAX_ENTRY_BYTES
        )
    try:
        entry = json.loads(line)
    except ValueError as exc:
        raise errors.LOG_MALFORMED(
            did=did.canonical, line=number, problem="the line is not JSON"
        ) from exc
    if not isinstance(entry, dict):
        raise errors.LOG_MALFORMED(
            did=did.canonical, line=number, problem="the line is JSON but not an object"
        )
    for member, kinds in _REQUIRED.items():
        if member not in entry:
            raise errors.LOG_MALFORMED(
                did=did.canonical, line=number, problem=f"{member} is missing"
            )
        if not isinstance(entry[member], kinds):
            raise errors.LOG_MALFORMED(
                did=did.canonical, line=number, problem=f"{member} is the wrong JSON type"
            )
    return entry


def open_stream(path: Path | str, did: WebvhDid) -> bytes:
    """Admit a KERI event stream, bounding it and nothing else.

    What the bytes mean is keripy's judgment, made later against the AID's key state. This door
    exists so that judgment is reached with a bounded amount of memory in hand.

    Raises:
        bakobo.errors.BakoboError: ``e.input.range.stream.f`` past the bound, or
            ``e.input.missing.stream.f`` when the stream is empty.
    """
    payload = _read(path, STREAM, did)
    if not payload:
        raise errors.STREAM_EMPTY(did=did.canonical)
    return payload


def open_witness(path: Path | str, did: WebvhDid) -> Admitted:
    """Admit a ``did-witness.json``: an array of ``{versionId, proof}`` objects.

    An empty array is accepted. The spec requires the witness file to be published *before* the
    log entry its proofs cover, so a file carrying proofs for entries that do not exist yet is
    ordinary rather than an error -- and so is one carrying none at all.

    Raises:
        bakobo.errors.BakoboError: ``e.input.range.witness.f`` past the bound, or
            ``e.input.format.witness.f`` off the data model.
    """
    payload = _read(path, WITNESS, did)
    try:
        proofs = json.loads(payload)
    except ValueError as exc:
        raise errors.WITNESS_MALFORMED(did=did.canonical, problem="the file is not JSON") from exc
    if not isinstance(proofs, list):
        raise errors.WITNESS_MALFORMED(
            did=did.canonical, problem="the data model is an array of objects"
        )
    for position, element in enumerate(proofs, start=1):
        if not isinstance(element, dict):
            raise errors.WITNESS_MALFORMED(
                did=did.canonical, problem=f"element {position} is not an object"
            )
        for member, kind in _REQUIRED_WITNESS.items():
            if member not in element:
                raise errors.WITNESS_MALFORMED(
                    did=did.canonical, problem=f"element {position} has no {member}"
                )
            if not isinstance(element[member], kind):
                raise errors.WITNESS_MALFORMED(
                    did=did.canonical, problem=f"element {position}'s {member} is the wrong type"
                )
    return Admitted(raw=payload, parsed=tuple(proofs))
