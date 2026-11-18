# DeltaX Decision Relay

A cross-site equipment procurement simulation. The buyer loads a supplier's published agent network in the browser after consent. The supplier returns versioned quotes through MCP. A separate fulfillment agent verifies the receipt before it reuses a decision or reviews the refreshed quote.

## Run locally

Use Node.js 22 or later.

```sh
node --test test/*.test.js
BUYER_ORIGIN=http://127.0.0.1:19170 SUPPLIER_ORIGIN=http://localhost:19171 node src/live-server.js
```

Open `http://127.0.0.1:19170` and select **Review offers**. The local fixture uses the sponsor runtime's deterministic browser model. The supplier peer fetch, MCP call, independent agent invocation, and authenticated application receipt are exercised on two loopback origins.

1. Approve the supplier origin once or for the browser session. See Vendor A at $380 and two days.
2. Recheck the same snapshot and then update an unrelated item. The fulfillment agent reuses the receipt.
3. Change Vendor A's quote to five days. The prior evidence basis expires and the app selects Vendor B at $420 and three days.
4. Make both quotes late. The app abstains.

The browser default closes the supplier boundary before contact. It sends only a fixed fictional SKU, quantity, region, and case. Public artifact and MCP requests omit browser credentials, and the supplier returns an authenticated fixture snapshot. Local budget and API credentials stay on the buyer side. Both sites publish agent manifests and resolved networks. The browser runs the supplier's graph with the buyer's router.

## Verification

With the services running, use `node scripts/run-benchmark.js` for the credential-free run. The explicit `--hosted` flag uses the local application budget for two comparison lanes, one with receipt reuse and one that requests a fresh review for each eligible phase. It requires an authorized local server configuration. The benchmark preserves the original deterministic policy baseline and reports each observed choice and hosted attempt.

Hosted Evaluate selects a bounded review step and returns provider evidence. The fulfillment action independently applies the $450 and three-day constraints to the supplier data. The app authenticates its own receipts and binds them to the browser session, intent, policy, and relevant quote versions. The app keeps fictional procurement within the simulation.

The [build plan](docs/BUILD-PLAN.md) maps the entry to the rules and judging criteria. The [capture plan](docs/DEMO-CAPTURE.md) covers the entrant narration and actual browser footage. The [deployment templates](deployment/) start with both providers disabled. See [runtime provenance](public/buyer/runtime/RELAY-NOTICE.md) for the sponsor version and local changes.
