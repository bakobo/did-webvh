"""The didwebvh error registry.

Every error this package raises is a module-scope :class:`~bakobo.errors.ErrorCode` literal --
never assembled from variables, f-strings, or a factory (dev/standards/error-codes.md, "The
registry") -- so a catalog can be extracted by static analysis and an illegal code is refused at
import time rather than described in prose. Codes classify by *meaning*, never by which module
raised them: no `didwebvh`-specific component name appears in any code.

**Boundaries against did-webs.** The sibling repo publishes a different method over the same
transport, so several codes here are the near-neighbour of one there and must not reuse its
string. Where that is true it is called out as a comment on the declaration. Two methods that
both refuse a malformed identifier need two codes, because a caller prefix-matching
`e.input.format.did` has to be able to tell which method's syntax it failed.

``tests/test_errors.py`` reads the count below back from this docstring and compares it against
what the module actually declares, having found the registry by type rather than by a hand-kept
list -- so the sentence is a gate, not decoration.

Codes declared here: 7.
"""

from __future__ import annotations

from bakobo.errors import ErrorCode

__all__ = [
    "DID_INVALID",
    "LOG_MALFORMED",
    "LOG_TOO_LARGE",
    "STREAM_EMPTY",
    "STREAM_TOO_LARGE",
    "TOO_LARGE",
    "WITNESS_MALFORMED",
    "WITNESS_TOO_LARGE",
]

DID_INVALID = ErrorCode(
    "e.input.format.did-webvh.f",
    "The string is not a valid did:webvh identifier.",
    detail='"{did}" does not parse as a did:webvh identifier.',
    args=("did",),
    hint="Check the did:webvh method-specific-id ABNF: a 46-character base58btc SCID, then the "
    "domain, then zero or more path segments, all colon-delimited.",
)
# Boundary against did-webs' e.input.format.did.f, which is the same refusal for the other
# method. Distinct strings deliberately: an operator publishing both methods needs to know which
# syntax an identifier failed, and a shared code would make the two indistinguishable.

LOG_TOO_LARGE = ErrorCode(
    "e.input.range.log.f",
    "The submitted DID log is larger than this service will read.",
    detail="The log submitted for {did} exceeds the bound on {bound}, which is {limit}.",
    args=("did", "bound", "limit"),
    hint="The bound is a flood guard, far above any real log. A submission near it is a sign "
    "something is wrong with the log rather than with the limit.",
)

STREAM_TOO_LARGE = ErrorCode(
    "e.input.range.stream.f",
    "The submitted KERI event stream is larger than this service will read.",
    detail="The stream submitted for {did} exceeds the bound on {bound}, which is {limit}.",
    args=("did", "bound", "limit"),
    hint="Submit only the AID's own key event log and the events the binding needs, not an "
    "agent's entire database.",
)

WITNESS_TOO_LARGE = ErrorCode(
    "e.input.range.witness.f",
    "The submitted witness proof file is larger than this service will read.",
    detail="The witness file submitted for {did} exceeds the bound on {bound}, which is {limit}.",
    args=("did", "bound", "limit"),
    hint="The specification recommends keeping only the latest proof per witness for published "
    "entries; a file near this bound is usually one that never dropped the old ones.",
)

#: Each door's range code, by kind, so :func:`didwebvh.bounds.read_bounded` can raise the right
#: one without assembling a code string. The literals above are what a catalog extractor sees;
#: this only points at them.
TOO_LARGE = {
    "log": LOG_TOO_LARGE,
    "stream": STREAM_TOO_LARGE,
    "witness": WITNESS_TOO_LARGE,
}

LOG_MALFORMED = ErrorCode(
    "e.input.format.log.f",
    "The submitted DID log is not well-formed JSON Lines.",
    detail="Line {line} of the log submitted for {did} is unusable: {problem}.",
    args=("did", "line", "problem"),
    hint="A DID log is one JSON object per line, each carrying versionId, versionTime, "
    "parameters, state and proof. No blank lines.",
)

STREAM_EMPTY = ErrorCode(
    "e.input.missing.stream.f",
    "The submitted KERI event stream is empty.",
    detail="The stream submitted for {did} contains no bytes.",
    args=("did",),
    hint="Submit the AID's key event log. A DID whose document claims no did:webs sibling needs "
    "no stream at all -- omit the argument rather than submitting an empty file.",
)
# Boundary against did-webs' e.input.format.stream.f, which is a walkability failure in a CESR
# stream that does have content. This one is the emptier case and takes the `missing` descriptor:
# nothing arrived, so there is nothing whose format could be judged.

WITNESS_MALFORMED = ErrorCode(
    "e.input.format.witness.f",
    "The submitted witness proof file does not match the specification's data model.",
    detail="The witness file submitted for {did} is unusable: {problem}.",
    args=("did", "problem"),
    hint="did-witness.json is a JSON array of objects, each with a versionId string and a proof "
    "array.",
)
