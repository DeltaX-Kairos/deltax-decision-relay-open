# Decision Relay runtime provenance

Based on Cognizant AI Lab’s Harbor Tours runtime from agentic-web commit
a39df2b7376ccf4a0dbe1c7dc411d04189838979. The vendored runtime retains
its Apache 2.0 license and its original README. The competition profile
is separately pinned to e4a8727d5c6807233b8976f28494bbdac7bc1c6e.

Decision Relay omits browser credentials on public artifact and supplier
MCP requests, refuses redirects, limits those requests to eight seconds,
and keeps resolved network definitions on their publisher origin. The
application provides a fixed supplier and explicit per-session consent.

The runner also supports the publisher declaring an owning agent for a
registered local capability. Decision Relay restricts receipt verification
to the fulfillment agent.

The buyer can explicitly choose the published deterministic replay.
The browser default for the live lane remains the publisher router.
