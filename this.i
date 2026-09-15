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

    Publishing verbatim is what forces the clamp to be strict = decision:
      id: t2jkfguj
      why: >
        The clamp (@tvv6dvyn) states the version-policy rules itself rather than checking only
        the places didwebvh-py is known to be wrong today. A clamp written as a patch list would
        silently stop covering a rule the day upstream refactored around it, and the whole point
        of @tvv6dvyn is not to inherit the library's acceptance decision. So: the permitted
        cryptosuite, the permitted hash algorithm, the acceptable `method` values and the closed
        parameter set are enforced here on their own terms, and if the library later enforces
        them too that is redundancy rather than waste.

        The hard case is the JSON `null`. The specification says `null` **MUST NOT** be used for a
        parameter, because it destroys the typing that says what a deactivated value means — and
        then adds a note that resolvers **SHOULD** gracefully accept it and convert it to the
        parameter's default, since early implementations emitted it. Those two rules point in
        opposite directions and a publisher has to pick one.

        This gate refuses it, and the reason is @gzvt7mpn rather than strictness for its own sake.
        Because did.jsonl is published byte-for-byte, Bakobo cannot take the resolver's option:
        accepting a `null` and normalising it is exactly what we are unable to do, so "accept
        gracefully" would mean hosting a log that violates a MUST NOT under a customer's domain
        and relying on every future resolver to be lenient about it. Rejected accepting-and-
        normalising, which @gzvt7mpn forbids. Rejected accepting-and-publishing-anyway, which
        makes Bakobo the party that put a non-conformant artifact on the web.

        Accepted tradeoff, and it is a real one: a customer whose log was minted by an older tool
        that emitted `null` cannot publish here until they re-sign it, and every resolver in the
        ecosystem would have accepted it. The refusal has to say that plainly — that the log is
        publishable elsewhere and not here, and why — rather than reading as though the log were
        broken.

    The walk is the library's, entry point and all = decision:
      id: sug4xtzk
      why: >
        Verification drives didwebvh-py's `DidResolver`, not its parts. Assembling
        `load_history_line` and `HistoryVerifier.verify_state` by hand looks equivalent and is
        not: `check_version_id()` — the entry-hash check, which is most of what makes a log a
        chain rather than a list — is invoked only from `DidResolver`'s own loop
        (core/resolver.py:381), and witness verification only from `resolve_state`. A hand-rolled
        walk would verify every signature and silently skip the chain, and would look right doing
        it. Rejected assembling the primitives for a synchronous call path, which is what tempted
        us: `DidResolver` is async, so this module owns an `asyncio.run` it would rather not have.

        The log is handed over in memory through the library's own `HistoryResolver` extension
        point rather than by path. `LocalHistoryResolver` would re-read the file — a second read,
        unbounded, of something our doors already bounded (@43ukbqca), and of a file that could
        have changed in between. Rejected writing the bounded bytes to a temp file to satisfy the
        path-shaped API.

        An unmapped problem type is reported as *our* fault, not the submitter's. If the library
        refuses for a reason this package has never heard of, the submission may be perfectly
        good and the gap is certainly ours, so the message says so and asks for a report.
        Rejected a generic "your log was rejected", which would blame a customer for our gap.
        The mapping is kept total by a test that reads the problem types out of the installed
        library rather than from a list maintained here, so a pin bump that adds a failure mode
        breaks the build instead of reaching a customer as an internal fault.

        Accepted tradeoff across all three: this module is coupled to library internals —
        `HistoryResolver`, `ProblemDetails` type strings, the `resolution_metadata` shape — that
        are not a stable public API. That coupling is deliberate and is the price of not owning
        a verifier; the totality test is what turns a silent break into a loud one.

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
        trusted tail. No document the submitter supplies is ever hosted; whatever appears beside
        the log is computed from it (see @whgskdbb for which document that is). Rejected
        accepting a submitted did.json as a convenience, and rejected incremental verification
        from the previously published tail, which would make Bakobo's own prior output an input
        to its trust decision. Accepted tradeoff: the submitter's exact bytes are what Bakobo
        serves, so content the proof happens to cover is served whatever it says — bounded by
        @tvv6dvyn and by shape validation, not by re-derivation.
      children:

        did.json is the parallel did:web document, and only when the log asks for it = decision:
          id: whgskdbb
          why: >
            This node corrects @gzvt7mpn, which said did.json "is always the resolved state
            computed from that verified log". That was wrong, and it was wrong in the same way
            the reference implementation is wrong: didwebvh-py's provision writes the resolved
            did:webvh document to did.json, but did.json sits at the did:web location, so a
            did:web resolver fetching it receives a document whose `id` is a did:webvh DID —
            which DID Core requires it to reject. Serving that file is serving junk under a
            customer's domain.

            did:webs settles the question and its answer transfers. There, the hosted did.json
            *is* the did:web form: the sibling repo's `to_did_web` rewrites `id`, `controller`
            and the matching verification-method controllers and puts the did:webs DID in
            `alsoKnownAs`, and the spec makes it mandatory — "The `did:web` version of the DIDs
            MUST be the same (minus the `s`) and point to the same `did.json` file". What makes
            that safe is not the transform but the authorization behind it: the KEL's
            designated-aliases ACDC must commit to *both* identifiers, so the second DID is one
            the controller cryptographically asked for rather than one the host invented.

            did:webvh has its own version of that commitment, and this decision uses it. The
            method makes the parallel did:web optional — "MAY generate a corresponding did:web"
            — and pairs it with "if this is being done, the did:webvh DIDDoc SHOULD have the
            corresponding did:web in the alsoKnownAs array". That array lives inside the signed
            state and is covered by the entry's Data Integrity proof. So: did.json is published
            if and only if the resolved document's alsoKnownAs names the did:web DID that this
            DID transforms to, and when it is, it carries the spec's parallel transform rather
            than the raw resolved document. No commitment in the log, no did.json.

            Rejected publishing the resolved did:webvh document at that location, which is what
            the reference implementation does. Rejected publishing the parallel did:web
            unconditionally, which would mint a second identifier on a customer's domain that
            they never signed for, and which the spec warns loses did:webvh's security for
            anyone who resolves it. Rejected never publishing did.json, which is strictly
            conformant — did:webvh needs only did.jsonl — but throws away the reach that is this
            repo's whole purpose (@b2ag3wmp) for a customer who explicitly asked for it.
            Accepted tradeoff: a customer who wants the did:web form must put it in their own
            alsoKnownAs and re-sign, and cannot obtain it by asking the operator.

    Three doors, each with a number on it = constraint:
      id: 43ukbqca
      why: >
        Everything that crosses into this process arrives through one of three named doors and is
        bounded before it is parsed: the DID log, the KEL stream, and the witness file. The
        interview should have asked this and did not, so it is recorded now rather than left to
        the module that happens to open a file first
        (dev/standards/input-handling.md, "the standing question").

        Size first, then shape, then meaning. Every check this repo makes about what bytes *mean*
        — the clamp, the library's walk, the AID binding — runs after those bytes are in memory,
        so none of it starts if the submission is simply too large. A door reads at most its bound
        plus one byte and refuses on the overage, rather than reading the file and then measuring
        it, because a length check that first reads the whole thing is not a bound.

        The numbers are flood guards and are not opinions about what a real payload weighs: 8 MiB
        for the log, 1 MiB for any single entry within it, 10,000 entries, 8 MiB for the KEL
        stream, 4 MiB for the witness file. A did:webvh entry carries a whole DID document and
        runs a few kilobytes; a DID rotating weekly for two centuries would not reach the entry
        count. Do not tune these as though they were capacity planning — if a legitimate
        submission ever approaches one, that is a finding about the submission.

        Rejected relying on the operator to have checked, since phase 1 is host-side and the file
        came from a customer. Rejected bounding only in the CLI, which would leave the library
        surface unbounded for the resolver phase that follows. Accepted tradeoff: three more
        refusal codes, and a census test that fails whenever someone adds a call site that reads
        bytes outside a door — which is the point, since a new unguarded read never looks wrong
        when you write it.

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

    The identifier is a value type, and the worked example outranks the ABNF = decision:
      id: x7ad5zds
      why: >
        `did:webvh` identifiers enter this codebase through one parsed, normalized value type
        (`WebvhDid`) rather than being passed around as strings and re-parsed at each use. The
        normalized fields are what compares; the input string is kept only for diagnostics, so a
        `%3a` port separator and a mixed-case domain cannot produce two objects that name the same
        DID and fail to be equal. Rejected passing the raw string and validating at the point of
        use, which is how a publish path ends up disagreeing with a verify path about whether two
        DIDs are the same.

        Where the v1.0 specification contradicts itself, this follows the worked example rather
        than the ABNF. `encoded-domain-label` and `webvh-path-segment` are both ASCII-only
        productions -- `webvh-path-segment = 1*idchar`, and DID Core's `idchar` admits nothing
        above U+007F -- yet the same section's example is `did:webvh:{SCID}:jp納豆.例.jp:用户`, and
        the transformation section gives its expected HTTPS URL. Both cannot hold. Chose the
        example, because it is what implementations are tested against and what the IDNA2008 step
        in the transformation presupposes; an ASCII-only reading would make that step dead text.
        Rejected enforcing the ABNF literally and refusing the specification's own example.
        Accepted tradeoff: this parser accepts identifiers a literal ABNF reading forbids, which
        is the permissive direction and therefore the one that can publish a DID a stricter
        resolver will not read. Tick ~4lcd carries it upstream to DIF, where a plain issue is
        allowed.

        Artifact directories are the *decoded* path segment, not the percent-encoded one, because
        a static file server decodes a request path before it looks up a file. Rejected naming
        directories by their encoded form, which would serve `%E7%94%A8%E6%88%B7` only from a
        server that happens not to decode.

        Every parse failure raises one code rather than a taxonomy. An operator acts on "this is
        not a valid identifier" and reads which rule failed in the message; a code per ABNF
        production would be a vocabulary nobody branches on.

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
        The command line is `didwebvh publish --did <did:webvh:...> --log <did.jsonl>
        [--witness <did-witness.json>] [--stream <keri.cesr>] --out <dir>`, one verb, mirroring
        didwebs' single-verb surface and
        for the same reason: minting a DID means signing with the controller's update key, and
        under @7ca6mlrg that is not a thing an operator can be asked to run against a customer's
        DID. Exit 0 with every artifact present, or a nonzero exit with nothing written and one
        line on stderr carrying a stable error code and a plain sentence; exit 64 (EX_USAGE) when
        the invocation itself was wrong and no submission was read. did.jsonl and did.json are
        written under one directory and either all appear or none does — did-witness.json joins
        them unchanged when the log names witnesses, since verifying a threshold Bakobo did not
        sign (@7ca6mlrg) is still Bakobo's job, and did.json joins them only when the log commits
        to a parallel did:web (@whgskdbb).

        Both evidence arguments are optional at the command line and mandatory whenever the
        submission asks for them: `--witness` when the log names witnesses, `--stream` when the
        document claims a did:webs sibling (@k6fiebmm). Making them unconditionally required
        would force an operator to invent an empty file for a DID that has neither, and making
        them ignorable would let a missing one pass as "nothing to check". Supplying either
        without the corresponding claim is refused rather than ignored, for the same reason: an
        operator who passed a file believed it was doing something. Rejected a separate verify verb that prints a
        verdict without publishing: it would create a second, weaker notion of "verified" that
        could drift from the one the gate enforces. Accepted tradeoff: an operator who wants to
        check a submission without hosting it must publish to a throwaway directory.
