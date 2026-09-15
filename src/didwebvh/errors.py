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

This module grows one code at a time, alongside the module that raises it. ``tests/test_errors.py``
reads the count back from this docstring and compares it against what the module actually
declares, having found the registry by type rather than by a hand-kept list -- so the sentence
below is a gate, not decoration.

Codes declared here: 1.
"""

from __future__ import annotations

from bakobo.errors import ErrorCode

__all__ = ["DID_INVALID"]

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
