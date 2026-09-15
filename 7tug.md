# verify.verify() wraps asyncio.run, so it cannot be called from an async context
kind: todo
created: 2026-09-15T07:50Z

- 2026-09-15T07:51Z Panel finding TST-F4, deferred rather than fixed. Already a recorded accepted tradeoff in this.i sug4xtzk: DidResolver is async and this package's surface is a synchronous CLI, so verify() owns an asyncio.run it would rather not have. Zero impact today -- nothing in phase 1 is async. It becomes a hard failure the moment a resolver or any async entry point is added, because asyncio.run raises inside a running loop. Fix shape when it bites: expose an async verify_async() as the real implementation and keep verify() as the sync wrapper, rather than unpicking the wrapper at the call site.
