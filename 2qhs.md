# didwebvh-py hangs forever resolving an empty DID log
kind: todo
created: 2026-09-15T05:27Z

- 2026-09-15T05:27Z Upstream defect in decentralized-identity/didwebvh-py at the pin 905f5e1. DidResolver.resolve over an empty entry log never returns -- no timeout, no #missing-log, no exception. Minimal repro uses only library code:

    import asyncio
    from did_webvh.core.resolver import DidResolver, HistoryVerifier, HistoryResolver
    from did_webvh.core.file_utils import read_str
    class Empty(HistoryResolver):
        def resolve_entry_log(self, _): return read_str('')
        def resolve_witness_log(self, _): return read_str('[]')
    asyncio.run(DidResolver(HistoryVerifier()).resolve('did:webvh:QmX:example.com', Empty()))

Verified 2026-09-15: killed at 40s having produced nothing.

Why it matters beyond us: this is the network resolution path. A did:webvh resolver fetching did.jsonl from a host that returns an empty body -- a misconfigured static server, a truncated deploy, or a hostile one -- wedges the resolving thread rather than reporting notFound. Anything embedding this library as a resolver inherits that.

Here it is defence in depth only: bounds.open_log already refuses an empty file, so nothing reaches verify through the CLI. The guard at the mark exists anyway because a hang is the one failure mode nothing downstream can catch, which is also the input-handling standard's rubric 3 (a boundary validator must always return).

To do: report to DIF. Unlike the WebOfTrust and trustoverip repos there is no posting restriction on DIF, so this can be a plain issue against decentralized-identity/didwebvh-py -- Daniel's call whether he or we post it. Draft written to /tmp/didwebvh-py-empty-log-hang.md on 2026-09-15. Root cause not diagnosed; the loop in resolve_state around core/resolver.py:330-400 is where to start, and a fix probably belongs with whatever decides the log ended.
- 2026-09-16T16:14Z PR opened upstream 2026-09-16: decentralized-identity/didwebvh-py#42. Branch on the bakobo/didwebvh-py fork; DCO signed off; upstream suite green. Close this tick when the PR merges and our pin is bumped past it -- not when it merges alone, since we pin a commit.
