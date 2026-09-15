[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

# did-webvh

Publish [`did:webvh`](https://github.com/decentralized-identity/didwebvh) DIDs on Bakobo
infrastructure for customers who already control a [KERI](https://github.com/WebOfTrust/keripy)
AID. A controller-signed DID log goes in, alongside the AID's key event log; verified artifacts —
`did.jsonl`, `did.json`, and `did-witness.json` where the log names witnesses — come out. Bakobo
holds no key anywhere in the DID's trust path, and hosts nothing it did not verify itself.

Two things here are not in the [DIF reference implementation](https://github.com/decentralized-identity/didwebvh-py)
this depends on. The publication gate refuses log entries that the `did:webvh:1.0` method version
forbids, including when the reference implementation is what produced them. And a DID that claims a
`did:webs` sibling has to prove it: the log's active update key must be the same Ed25519 key as that
AID's current signing key, rather than an `alsoKnownAs` entry we take on faith and republish.

## Status

**Designed, not yet implemented.** The intent tree at `this.i` is the source of truth and is complete
for phase 1; no code has landed yet.

`this.i` is plain YAML and its `why` fields are prose. It is the fastest way to see why this repo
exists beside [`bakobo/did-webs`](https://github.com/bakobo/did-webs), which implements the other
web-based DID method Bakobo supports, and why the two are not one codebase.

## License

Apache-2.0.
