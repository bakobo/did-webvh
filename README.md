[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

# did-webvh

Publish [`did:webvh`](https://github.com/decentralized-identity/didwebvh) DIDs on Bakobo
infrastructure for customers who already control a [KERI](https://github.com/WebOfTrust/keripy)
AID. A controller-signed DID log goes in, alongside the AID's key event log; verified artifacts —
`did.jsonl`, `did.json`, and `did-witness.json` where the log names witnesses — come out. Bakobo
holds no key anywhere in the DID's trust path, and hosts nothing it did not verify itself.

One thing here is not in the [DIF reference implementation](https://github.com/decentralized-identity/didwebvh-py)
this depends on: the publication gate refuses log entries that the `did:webvh:1.0` method version
forbids, including when the reference implementation is what produced them.

A second was intended -- proving that a DID claiming a `did:webs` sibling really is under that AID's
key, rather than republishing an `alsoKnownAs` entry on faith -- and does not yet work. See Status.

## Status

**Phase 1 is implemented: a publication gate, run from the command line.** It bounds and shapes a
submission, refuses what `did:webvh:1.0` forbids, verifies the log with didwebvh-py, and writes the
artifacts atomically or not at all. 498 tests, 100% branch coverage.

Not yet: resolving, HTTP serving, minting, or anything network-facing.

**The `did:webs` binding described above does not yet do what it says.** An adversarial review on
2026-09-15 established that it accepts a claimed sibling when the AID's *public* key merely appears
in the log's `updateKeys` -- a value the log's own controller sets, requiring no consent and no
signature from the AID. It is being reworked to require evidence from the AID itself. Until then,
treat a published `alsoKnownAs` here as a controller's assertion, exactly as you would from any
other host.

`this.i` is plain YAML and its `why` fields are prose. It is the fastest way to see why this repo
exists beside [`bakobo/did-webs`](https://github.com/bakobo/did-webs), which implements the other
web-based DID method Bakobo supports, and why the two are not one codebase.

## License

Apache-2.0.
