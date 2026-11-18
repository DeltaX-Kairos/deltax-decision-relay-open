# DeltaX Decision Relay

## What the judges should see

An operations coordinator needs replacement equipment within three days and under $450. A buyer agent loads a supplier's published network in its browser after the user approves that origin. The supplier returns versioned quotes. Hosted DeltaX Evaluate chooses a bounded review step from the evidence, and the buyer applies exact price, quantity, and delivery constraints. A separate fulfillment agent consumes an evidence-bound decision receipt before a simulated reservation.

Vendor A quotes $380 in two days. Vendor B quotes $420 in three days. The demo accepts the first decision, reuses it under unchanged or unrelated evidence, then rejects it after A moves to five days. The agent requests fresh evidence and reroutes to B. If both offers become late, it records an abstention. The story is the recovery after a decision crosses an agent boundary. All offers and reservations are fictional.

## Competition requirements

The submission is due January 11, 2027 at 8 a.m. Pacific. Free, unrestricted judging access runs through January 18 at 5 p.m. Pacific. Cash prizes are $5,000, $3,000, and $2,000. The app must be new or materially updated during the event. The submission needs a working public browser app, a public conforming JSON network definition and browser runtime, an interaction surface, a description, at least one screenshot, and a public YouTube demonstration under two minutes showing the app and explaining it.

- [Official competition rules](https://cognizant-agenticweb.devpost.com/rules)
- [Opening-day MVP profile 0.2 at e4a8727](https://github.com/cognizant-ai-labs/agentic-web/blob/e4a8727d5c6807233b8976f28494bbdac7bc1c6e/docs/worldwide_agentic_web_mvp_spec.md)
- [Hosted Evaluate developer reference](https://deltaxevaluate.com/developers)

### Stage one

Demonstrate section 6 of the opening-day profile against the public browser build. Publish two agent sites on distinct HTTPS origins. Provide the manifest, resolved Neuro SAN JSON, named links, and browser runtime. Start from the sponsor's reference runtime, pin the implementation used, and retain the upstream license and attribution. Its current Harbor Tours example is a candidate for the linked-site pattern. Test it against the opening-day profile.

The buyer network runs in the browser with its published default router. It calls an internal fulfillment agent and uses a grounded read capability. The reference runtime must support MCP and registered local site actions as specified. The browser shows the peer's origin and purpose before contacting it, resolves the exact named network, and runs the declarative supplier network with the caller's router. Public cross-origin requests omit credentials. The peer receives an explicit SKU, quantity, and delivery-region payload. The buyer retains its budget, secrets, and private state. Test denied origin, invalid network, missing exact name, cycle, and budget exhaustion. Capture both successful and refused runs with a clean browser and network evidence.

### Stage two

| Equal criterion | Evidence in the entry |
| --- | --- |
| Technological implementation | A fresh browser resolves a consented peer and executes its graph. The trace shows the grounded call, hosted evaluation, receipt verification, and bounded recovery. This criterion is the first tiebreaker. |
| Design | A coordinator can run the flow, see which quote met the mandate, introduce delivery drift, and understand why the agent reused, replaced, or refused a decision. |
| Potential impact | The benchmark reports valid simulated outcomes and recovery costs on procurement failures a coordinator recognizes. Publish a documented, reusable redacted receipt verifier or fixture pack if it stands on its own. |
| Quality of idea | The receiving agent independently checks an earlier decision against present evidence. Show where a portable receipt changes the next action or saves a repeat review. |

## Hosted Evaluate and receipt design

Expose a typed, same-origin service capability behind the browser agent. The service alone holds the dedicated Evaluate credential. Use the documented customer gateway and bounded evaluation profile. Submit 1–8 read-oriented candidate steps with scalar context, such as comparing an eligible alternate or requesting updated ETA evidence. The service may select one or refuse. Use deterministic local eligibility before simulated outcomes. A provider decision neither confirms the underlying supplier facts nor confers purchase authority.

Pin the customer gateway at `access-api.deltaxevaluate.com`. Use `/api/builder/oauth/token` for the `deltax:evaluate` client-credentials exchange and `/api/builder/evaluations` with `X-DeltaX-API-Version: 2026-09-16.beta2` and profile `deltax-hosted-bounded-review-evaluation-v1`. Before enabling dispatch, confirm these public contract details against the live API reference. Retain only allowlisted response fields and distinguish a missing or malformed receipt from a refusal delivered by the provider.

Record the provider receipt ID and evidence digest in an app-issued envelope that also binds the versioned intent, policy, selected quote, decision-relevant candidate set, and fixture revision. Have the fulfillment agent check the issuer using a trusted lookup or a separately authenticated app envelope. Evaluate's digest identifies recorded evidence. Application-layer issuer verification supplies authenticity. The receiver independently computes the relevant dependency digest from grounded current data. Relevant changes or validation failures invalidate reuse. Unrelated catalog revisions leave the bound receipt intact.

Use a single bounded attempt per uncached decision with a deadline, idempotency, and explicit selected, refused, unknown, and rejected outcomes. Treat uncertain results as unknown and stop the simulated reservation. Use synthetic fixtures throughout. Keep hosted credentials out of manifests, browser state, peer traffic, exported traces, and the repo. Credential-free replays are labeled separately from live runs.

## Benchmark protocol

Run the same seeded sequence, hard constraints, and evidence snapshot against three lanes:

1. Deterministic local rank-and-revalidate baseline that can recompute from current evidence on every handoff.
2. Hosted Evaluate on each handoff with receipt reuse disabled.
3. Hosted Evaluate with receipt verification and scope-aware reuse.

Freeze fixtures and expected outcome labels before recording. Cover unchanged evidence, an unrelated catalog revision, a late selected quote, changed membership in the eligible set, no valid quote, and provider uncertainty. Include invalid or altered receipts as a separate defensive check. Judge a selection by independent eligibility checks. Record correct choices and abstentions, stale decisions reused, remote evaluations, recovery latency, and whether the second agent can explain the original decision. Compare hosted lanes for reuse savings. Compare local and hosted for decision behavior and preserve ties. Every claim cites the exact case and recorded trace.

## Build sequence

1. Run the offline simulator and deterministic benchmark. Use it to freeze the cases and labels.
2. Run both origins locally with the reference runtime and the buyer's default router. Verify the full stage-one checklist with browser evidence before polishing the host interface.
3. Connect hosted Evaluate behind the typed service boundary. Use a dedicated credential and a documented bounded allowance. Capture normalized live receipts and validate the handoff independently.
4. Exercise the three benchmark lanes and repeat in a clean browser. Verify free, unrestricted judge access and the hosted budget through the judging window before claiming public readiness.
5. Record under two minutes in the actual browser. Show the problem, peer consent, initial receipt, changed quote, receipt rejection and reroute, and one benchmark result. Keep the screenshot, entry text, demo, and public links consistent.
