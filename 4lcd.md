# did:webvh v1.0 ABNF forbids the non-ASCII its own worked example uses
kind: todo
created: 2026-09-15T02:23Z

- 2026-09-15T02:23Z spec-v1.0/specification.md: webvh-path-segment = 1*idchar and encoded-domain-label = 1*(ALPHA/DIGIT/'-'/pct-encoded) are both ASCII-only, but the same section's worked example is did:webvh:{SCID}:jp納豆.例.jp:用户 with raw non-ASCII in both positions, and the transformation section gives its expected HTTPS URL. src/didwebvh/did.py follows the example (its regexes admit non-ASCII) because that is what implementations are tested against. Raise upstream with DIF -- unlike the ToIP repos there is no posting restriction, so this can be a plain issue against decentralized-identity/didwebvh.
