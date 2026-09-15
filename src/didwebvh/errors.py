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

Codes declared here: 11.
"""

from __future__ import annotations

from bakobo.errors import ErrorCode

__all__ = [
    "CRYPTOSUITE_FORBIDDEN",
    "DID_INVALID",
    "HASH_FORBIDDEN",
    "LOG_MALFORMED",
    "LOG_TOO_LARGE",
    "METHOD_UNACCEPTABLE",
    "PARAMETER_REFUSED",
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


# --- The conformance clamp (this.i tvv6dvyn, t2jkfguj). One family, e.rule.conformance.*, so an
# operator can prefix-match "your log does not conform to the method version it declares" without
# branching on which rule caught it. `rule` and not `feature`: these are not capabilities we chose
# not to build, they are norms the specification states and this gate enforces.

METHOD_UNACCEPTABLE = ErrorCode(
    "e.rule.conformance.method.f",
    "The log declares a did:webvh specification version this service will not publish.",
    detail="Entry {entry} of the log for {did} declares method {found}; the only acceptable "
    "value is did:webvh:1.0.",
    args=("did", "entry", "found"),
    hint="An unrecognized method value is never downgraded, defaulted or ignored -- the "
    "specification requires resolution to terminate, so publication does too.",
)

CRYPTOSUITE_FORBIDDEN = ErrorCode(
    "e.rule.conformance.cryptosuite.f",
    "A proof uses a cryptosuite this did:webvh version forbids.",
    detail="In the log for {did}, {where} carries {found}; did:webvh:1.0 permits exactly "
    "eddsa-jcs-2022, for log entry proofs and witness proofs alike.",
    args=("did", "where", "found"),
    hint="The reference Python implementation will mint an ecdsa-jcs-2019 log and resolve it, "
    "but no other implementation will read it. Re-mint with an Ed25519 key.",
)

HASH_FORBIDDEN = ErrorCode(
    "e.rule.conformance.hash.f",
    "A hash in the log is not the SHA-256 multihash this did:webvh version requires.",
    detail="In the log for {did}, {where} is unusable: {problem}.",
    args=("did", "where", "problem"),
    hint="did:webvh:1.0 permits SHA-256 only, as a base58btc-encoded multihash with the 0x12 "
    "0x20 prefix. Any other algorithm terminates resolution.",
)

PARAMETER_REFUSED = ErrorCode(
    "e.rule.conformance.parameter.f",
    "A log parameter is one this did:webvh version does not permit.",
    detail="Entry {entry} of the log for {did} is unpublishable: {problem}.",
    args=("did", "entry", "problem"),
    hint="The parameters object may carry only the properties this specification version "
    "defines, each with a real value rather than the deprecated JSON null.",
)
