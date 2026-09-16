"""webvh_gate — publish did:webvh DIDs on Bakobo infrastructure.

Takes a controller-signed DID log and, where the DID claims a KERI sibling, that AID's key event
log; verifies both; and hosts ``did.jsonl``, ``did.json`` and ``did-witness.json``. Bakobo holds no
key in the DID's trust path (this.i decision 7ca6mlrg), publishes the log verbatim or not at all
while always deriving the document (constraint gzvt7mpn), and refuses anything ``did:webvh:1.0``
forbids even when the reference implementation produced it (constraint tvv6dvyn).

Phase 1 is publish-only, host-side, with no network I/O; see this.i (goal b2ag3wmp).
"""

from __future__ import annotations

__version__ = "0.0.0"
