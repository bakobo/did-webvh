# did-webvh — Intent Tree (this.i)
#
# Source of truth for this repo's intentions and the decisions that follow. Code and docs/ are
# derived from it. Format: dhh1128/intent node tree; see bakobo/dev/methodology.md.
# Node key line:  Name = [marks...] type:   (types: goal | decision | constraint | tension | deviation)
# id: opaque base32 [a-z2-7]{8}, never a semantic label.  why: meets the rebuttal-surface standard.

A KERI AID reaches the mainstream DID ecosystem, on a binding Bakobo verified = goal:
  id: b2ag3wmp
  why: >
    did-webvh exists so a Bakobo customer holding a KERI AID is also resolvable by the DID
    tooling that actually exists in the market. did:webvh is DIF-Recommended (findings document
    merged; the joint DIF/ToIP announcement of 2026-06-19 names it and did:webplus), has five
    implementations, a Universal Resolver driver, and deployments; did:webs is not recommended —
    its row in the DIF status matrix reads "No", it stalled after Deep Dive 1, and its proposal
    was last touched 2025-09-24. Rejected treating did:webvh as a replacement for did:webs:
    webvh's trust rests on a self-contained log the controller signs, with no key-event history
    behind it, so it buys reach and not root of trust. Rejected equally a webvh product with no
    KERI content, which would make Bakobo one more webvh host competing on price. The outcome
    this repo produces is one principal with two DIDs, where the binding between them is
    something Bakobo verified rather than something Bakobo repeated. Accepted tradeoff: this repo
    tracks two moving specifications and two dependency stacks that share no cryptography.
  children:

    Its own repo, not a second method inside did-webs = decision:
      id: d6tuonxu
      why: >
        Chose a separate repo over adding did:webvh to bakobo/did-webs. The two methods share the
        did:web-style DID-to-HTTPS transformation and the act of writing files at the resulting
        path — on the order of a hundred lines — and nothing else: the did:webvh v1.0
        specification contains no occurrence of "KERI", "CESR", "KEL" or "key event", and its
        substrate is multikey, SHA-256 multihash, JCS and W3C Data Integrity where did:webs' is
        CESR streams, KELs, TELs and ACDCs. Merging would place two independently churning
        upstream specs under one 100%-branch coverage gate and entangle their release cadences.
        Affinidi, the only organization shipping both methods, reached the same arrangement:
        did:webs is a crate in affinidi-tdk-rs while did:webvh lives in separate repos, bridged a
        layer up by did-scid feature flags. Accepted tradeoff: the atomic publish discipline is
        written a second time here rather than shared, until a third consumer justifies
        extracting it the way bakobo-errors was extracted.

    Python on didwebvh-py, pinned to a git commit = decision:
      id: 327yhyvd
      why: >
        Chose to depend on DIF's reference Python library (decentralized-identity/didwebvh-py,
        Apache-2.0) rather than reimplement the method or vendor it: it implements v1.0, covers
        registrar, resolver and witness in about 3,200 lines, and Bakobo has no reason to rewrite
        a JCS-and-Data-Integrity state machine. Python also follows from the other end — the AID
        binding (@k6fiebmm) needs keripy, so any other language means reimplementing both halves.
        Pinned to a git commit at or after 9deaddc rather than to the PyPI release, because
        did-webvh 1.0.1 (uploaded 2026-07-17) canonicalizes through jsoncanon, which is not
        RFC 8785-conformant for large integers and exponent forms; since SCIDs, entry hashes and
        proof hashes are all computed over JCS output, a DID containing such a number hashes
        differently from every other implementation. The fix landed on main on 2026-08-17 and has
        never been released. This is the same pinning pattern did-webs uses for keri and
        bakobo-errors. Accepted tradeoff: we track an unreleased HEAD, so every bump must re-run
        the conformance suite rather than trusting a version number.

    Only what did:webvh:1.0 permits is published = constraint:
      id: tvv6dvyn
      why: >
        The library we depend on both mints and accepts proofs the specification forbids.
        Demonstrated 2026-09-14: `did_webvh.provision --auto --algorithm p256` produces a genesis
        entry whose parameters.method is "did:webvh:1.0" and whose proof cryptosuite is
        ecdsa-jcs-2019, and the library's own resolver then accepts that log without error.
        core/proof.py's DI_SUPPORTED table selects a suite from the key's codec and never
        consults the active method parameter; core/state.py validates method only as a non-empty
        string. The specification says the permitted cryptosuite for method did:webvh:1.0 is
        exactly eddsa-jcs-2022, that resolvers MUST verify the proof's cryptosuite property, and
        that an unrecognized method value MUST terminate resolution. didwebvh-ts enforces both,
        so a DID the Python tool mints this way is resolvable only by the Python tool. Bakobo
        therefore runs its own admission check around the library's walk rather than inheriting
        its acceptance decision. Note this is not the did-webs Ed25519-only decision (3woefn)
        repeated: there, one curve of three was a Bakobo choice; here a single cryptosuite is
        what the method version means, and adding a curve "for parity" would be a defect.
        Rejected forking the library to fix it in place, which would make every upstream bump a
        merge. Accepted tradeoff: Bakobo refuses DIDs that the reference implementation created,
        so the refusal has to say exactly that, and the finding belongs upstream as a bug report.

    Bakobo holds no key in the DID's trust path = decision:
      id: 7ca6mlrg
      why: >
        The controller signs every log entry; Bakobo verifies and publishes. Rejected operating a
        specification-defined witness in phase 1 — a Bakobo did:key whose proofs land in
        did-witness.json — which is the role the ecosystem's server implementations assume and
        which would be a natural sibling to bakobo/witness. It would put Bakobo inside the
        customer's trust path and make their DID's updates depend on Bakobo staying available and
        uncompromised: a different risk posture, not merely a larger API. This mirrors did-webs'
        non-custodial stance (avuwzl) for the same reason. Accepted tradeoff: Bakobo cannot offer
        the duplicity detection that witnesses exist to provide, and a customer who wants it must
        name a third-party witness whose proofs we merely verify.

    The log is published verbatim or not at all; the document is derived = constraint:
      id: gzvt7mpn
      why: >
        did-webs' constraint that hosted artifacts are re-derived from verified state (embuup)
        cannot transfer literally: a Data Integrity proof covers exact JSON bytes, so a
        re-derived log entry would not verify and re-derivation would destroy the artifact's
        authority rather than establish it. What transfers is that nothing the submitter asserts
        is hosted on its own authority. did.jsonl is published byte-for-byte, and only after the
        whole log verifies from genesis on every publication rather than incrementally from a
        trusted tail; did.json is always the resolved state computed from that verified log,
        never a did.json the submitter supplied. Rejected accepting a submitted did.json as a
        convenience, and rejected incremental verification from the previously published tail,
        which would make Bakobo's own prior output an input to its trust decision. Accepted
        tradeoff: the submitter's exact bytes are what Bakobo serves, so content the proof
        happens to cover is served whatever it says — bounded by @tvv6dvyn and by shape
        validation, not by re-derivation.

    The AID binding is verified from submitted evidence = decision:
      id: k6fiebmm
      why: >
        A customer's did:webvh document names their did:webs DID in alsoKnownAs. Bakobo refuses
        to publish such a log unless the submission also carries the AID's keri.cesr and the
        log's active updateKeys decodes to the same Ed25519 public key as that AID's current
        signing key — the claim is verified at the gate, not repeated. Rejected hosting the
        alsoKnownAs as unverified controller-signed content, which is what every other webvh host
        does and precisely what did-webs exists to refuse; it would leave the root goal
        (@b2ag3wmp) asserting a binding the product never checks. Rejected resolving the named
        sibling over the network instead, which would make publication depend on a third party
        being reachable and would put network I/O into a pipeline deliberately free of it.
        Accepted tradeoff: a keripy dependency in a repo whose own method has no KERI content,
        and a customer obligation to assemble two artifacts rather than one.
      tensions:

        The binding can only be proven in one direction = tension:
          id: sqlp567q
          why: >
            The goal wants a mutual binding and the specifications permit only half of one. A
            did:webvh document may name a did:webs DID in alsoKnownAs, and that assertion is
            covered by the entry's Data Integrity proof. The reverse is not expressible: the
            did:webs specification limits alsoKnownAs to DIDs "that has the same AID" and its
            designated-aliases table enumerates exactly three admissible kinds — other same-AID
            did:webs DIDs, same-AID did:web DIDs, and did:keri:<AID>. A did:webvh DID contains no
            AID and matches no row, so a conforming did:webs resolver has no rule that would
            surface it even if the controller placed it in the designated-aliases ACDC's free
            `ids` list.
          resolution: >
            Phase 1 verifies the direction that is expressible, and verifies it on the strongest
            available evidence: key identity against the KEL, which is a stronger statement than
            an alias list would have been, because it is about control rather than about naming.
            The missing direction is an upstream gap in the did:webs method, not a defect here;
            it goes on did-webs' soft-spots list for the ToIP task force. Revisit if the
            designated-aliases table gains a row for foreign DIDs.

    Publish first; resolving and serving come later = decision:
      id: cx2fyuyz
      why: >
        The first deliverable is the publication gate — a verified log becomes hosted artifacts —
        with Bakobo's own resolver and the HTTP serving layer as later phases. Third parties
        already resolve did:webvh with the Universal Resolver's driver and with didwebvh-py, so
        publishing alone is immediately useful, which is the same reasoning as did-webs' ecwpad.
        Rejected resolve-first, which verifies other people's DIDs and ships nothing a customer
        can point at. Accepted tradeoff: until our own resolver exists, our end-to-end oracle is
        the reference stack we already distrust in one specific way (@tvv6dvyn), so the
        conformance suite has to carry the weight a second independent implementation normally
        would.

    One verb, and an operator contract that never publishes a partial DID = decision:
      id: nmhqxs5q
      why: >
        The command line is `didwebvh publish --log <did.jsonl> --stream <keri.cesr>
        --did <did:webvh:...> --out <dir>`, one verb, mirroring didwebs' single-verb surface and
        for the same reason: minting a DID means signing with the controller's update key, and
        under @7ca6mlrg that is not a thing an operator can be asked to run against a customer's
        DID. Exit 0 with every artifact present, or a nonzero exit with nothing written and one
        line on stderr carrying a stable error code and a plain sentence; exit 64 (EX_USAGE) when
        the invocation itself was wrong and no submission was read. did.jsonl and did.json are
        written under one directory and either all appear or none does — did-witness.json joins
        them unchanged when the log names witnesses, since verifying a threshold Bakobo did not
        sign (@7ca6mlrg) is still Bakobo's job. Rejected a separate verify verb that prints a
        verdict without publishing: it would create a second, weaker notion of "verified" that
        could drift from the one the gate enforces. Accepted tradeoff: an operator who wants to
        check a submission without hosting it must publish to a throwaway directory.
