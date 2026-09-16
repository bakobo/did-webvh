[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

# did-webvh

Publish [`did:webvh`](https://github.com/decentralized-identity/webvh_gate) DIDs on Bakobo
infrastructure for customers who already control a [KERI](https://github.com/WebOfTrust/keripy)
AID. A controller-signed DID log goes in, alongside the AID's key event log; verified artifacts —
`did.jsonl`, `did.json`, and `did-witness.json` where the log names witnesses — come out. Bakobo
holds no key anywhere in the DID's trust path, and hosts nothing it did not verify itself.

One thing here is not in the [DIF reference implementation](https://github.com/decentralized-identity/didwebvh-py)
this depends on: the publication gate refuses log entries that the `did:webvh:1.0` method version
forbids, including when the reference implementation is what produced them.

It also declines to publish a document whose `alsoKnownAs` names a `did:webs` DID. That is a
hosting policy rather than a rule of the method: no specification makes such a claim verifiable,
and a `did:webvh` artifact has nowhere to record that a host tried, so republishing one would put
an unchecked assertion about a third party under your domain over ours. Another host may publish
it; we would rather say why we don't.

## Status

**Phase 1 is implemented: a publication gate, run from the command line.** It bounds and shapes a
submission, refuses what `did:webvh:1.0` forbids, verifies the log with didwebvh-py, and writes the
artifacts atomically or not at all. 498 tests, 100% branch coverage.

Not yet: resolving, HTTP serving, minting, or anything network-facing.

This repo briefly claimed to verify that a `did:webvh` DID and a KERI AID were under one key. An
adversarial review on 2026-09-15 showed the check was satisfiable with the victim's *public* key
alone, and the subsequent question -- whether any correct version would be worth having -- answered
itself: there is nowhere in a `did:webvh` artifact to record that a host verified anything, so the
guarantee would have been invisible to everyone who reads the document. The feature was withdrawn
rather than repaired. `this.i` node `plhyphrk` has the reasoning.

`this.i` is plain YAML and its `why` fields are prose. It is the fastest way to see why this repo
exists beside [`bakobo/did-webs`](https://github.com/bakobo/did-webs), which implements the other
web-based DID method Bakobo supports, and why the two are not one codebase.

## License

Apache-2.0.
