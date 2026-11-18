import assert from "node:assert/strict";
import { once } from "node:events";
import { after, before, describe, it } from "node:test";
import {
  RECEIPT_KIND,
  buildReceipt,
  createScenario,
  evaluatePolicy,
  runBenchmark,
  runComparison,
  runTamperProbes,
  sha256Hex,
  verifyReceipt
} from "../src/relay.js";
import { createRelayServer } from "../src/server.js";

describe("DeltaX Decision Relay core replay", () => {
  it("executes initial selection, unchanged & unrelated reuse, relevant invalidation, and abstention", () => {
    const result = runComparison();
    assert.equal(result.mode, "local-fixture-replay");
    assert.equal(result.steps.length, 5);

    const [s1, s2, s3, s4, s5] = result.steps;
    assert.equal(s1.replay.action, "evaluated");
    assert.equal(s1.replay.selectedVendorId, "vendor-a");
    assert.equal(s1.replay.evalCalls, 2);

    assert.equal(s2.replay.action, "reused");
    assert.equal(s2.replay.selectedVendorId, "vendor-a");
    assert.equal(s2.replay.evalCalls, 0);

    assert.equal(s3.replay.action, "reused");
    assert.equal(s3.replay.selectedVendorId, "vendor-a");
    assert.equal(s3.replay.evalCalls, 0);

    assert.equal(s4.replay.action, "invalidated-and-reevaluated");
    assert.equal(s4.replay.invalidationReason, "relevant-revision-drift");
    assert.equal(s4.replay.selectedVendorId, "vendor-b");
    assert.equal(s4.replay.evalCalls, 2);

    assert.equal(s5.replay.action, "invalidated-and-reevaluated");
    assert.equal(s5.replay.invalidationReason, "relevant-revision-drift");
    assert.equal(s5.replay.status, "abstained");
    assert.equal(s5.replay.selectedVendorId, null);
    assert.equal(s5.replay.evalCalls, 2);

    assert.equal(result.metrics.baseline.evalCalls, 10);
    assert.equal(result.metrics.replay.evalCalls, 6);
    assert.equal(result.metrics.savedEvalCalls, 4);
    assert.equal(result.metrics.baseline.staleUses, 0);
    assert.equal(result.metrics.replay.staleUses, 0);
    assert.equal(result.metrics.accuracyTie, true);
  });

  it("matches independent golden expected outcomes for default 450/3 policy", () => {
    const golden = [
      {
        stepId: "step-1-initial",
        status: "selected",
        selectedVendorId: "vendor-a",
        cost: 380,
        days: 2,
        baselineChecks: 2,
        replayAction: "evaluated",
        replayChecks: 2
      },
      {
        stepId: "step-2-unchanged",
        status: "selected",
        selectedVendorId: "vendor-a",
        cost: 380,
        days: 2,
        baselineChecks: 2,
        replayAction: "reused",
        replayChecks: 0
      },
      {
        stepId: "step-3-unrelated",
        status: "selected",
        selectedVendorId: "vendor-a",
        cost: 380,
        days: 2,
        baselineChecks: 2,
        replayAction: "reused",
        replayChecks: 0
      },
      {
        stepId: "step-4-relevant-drift",
        status: "selected",
        selectedVendorId: "vendor-b",
        cost: 420,
        days: 3,
        baselineChecks: 2,
        replayAction: "invalidated-and-reevaluated",
        replayChecks: 2
      },
      {
        stepId: "step-5-all-invalid",
        status: "abstained",
        selectedVendorId: null,
        cost: null,
        days: null,
        baselineChecks: 2,
        replayAction: "invalidated-and-reevaluated",
        replayChecks: 2
      }
    ];

    const result = runComparison({ maxCost: 450, maxDays: 3 });
    assert.equal(result.steps.length, golden.length);

    for (let i = 0; i < golden.length; i += 1) {
      const exp = golden[i];
      const step = result.steps[i];
      assert.equal(step.stepId, exp.stepId);
      assert.equal(step.baseline.status, exp.status);
      assert.equal(step.baseline.selectedVendorId, exp.selectedVendorId);
      assert.equal(step.baseline.evalCalls, exp.baselineChecks);
      assert.equal(step.replay.action, exp.replayAction);
      assert.equal(step.replay.status, exp.status);
      assert.equal(step.replay.selectedVendorId, exp.selectedVendorId);
      assert.equal(step.replay.evalCalls, exp.replayChecks);
      if (exp.status === "selected") {
        assert.equal(step.replay.selectedQuote.cost, exp.cost);
        assert.equal(step.replay.selectedQuote.days, exp.days);
      } else {
        assert.equal(step.replay.selectedQuote, null);
      }
    }
  });

  it("fails closed on tampered digests, malformed shapes, policy drift, forged authority/envelope, and recomputed altered selections", () => {
    const probes = runTamperProbes();
    assert.equal(probes.allRejected, true);

    const { mandate, policy, steps } = createScenario();
    const eval1 = evaluatePolicy(policy, steps[0].quotes);
    const receipt = buildReceipt({ mandate, policy, evaluation: eval1 });

    const forgedEnvelope = structuredClone(receipt);
    forgedEnvelope.authority.appSignedEnvelope = true;
    const envelopeCheck = verifyReceipt(forgedEnvelope, { mandate, policy, quotes: steps[0].quotes });
    assert.equal(envelopeCheck.valid, false);
    assert.equal(envelopeCheck.reason, "invalid-authority-claim");

    const alteredReceiptPolicy = structuredClone(receipt);
    alteredReceiptPolicy.policy.maxCost = 999;
    const policyFieldCheck = verifyReceipt(alteredReceiptPolicy, { mandate, policy, quotes: steps[0].quotes });
    assert.equal(policyFieldCheck.valid, false);
    assert.equal(policyFieldCheck.reason, "policy-drift");

    const ungroundedRecomputed = structuredClone(receipt);
    ungroundedRecomputed.selection.selectedQuote = { ...ungroundedRecomputed.selection.selectedQuote, cost: 100 };
    ungroundedRecomputed.bindings.selectionDigest = sha256Hex(ungroundedRecomputed.selection);
    ungroundedRecomputed.evidenceDigest = sha256Hex({ kind: RECEIPT_KIND, ...ungroundedRecomputed.bindings });
    const ungroundedCheck = verifyReceipt(ungroundedRecomputed, { mandate, policy, quotes: steps[0].quotes });
    assert.equal(ungroundedCheck.valid, false);
    assert.equal(ungroundedCheck.reason, "ungrounded-selection");

    const strictPolicy = { ...policy, maxCost: 400 };
    const strictEval = evaluatePolicy(strictPolicy, steps[0].quotes);
    const strictReceipt = buildReceipt({ mandate, policy: strictPolicy, evaluation: strictEval });
    const quoteB = steps[0].quotes.find((q) => q.vendorId === "vendor-b");
    const overLimitRecomputed = structuredClone(strictReceipt);
    overLimitRecomputed.selection = {
      status: "selected",
      selectedVendorId: quoteB.vendorId,
      selectedQuote: { ...quoteB }
    };
    overLimitRecomputed.bindings.selectionDigest = sha256Hex(overLimitRecomputed.selection);
    overLimitRecomputed.evidenceDigest = sha256Hex({ kind: RECEIPT_KIND, ...overLimitRecomputed.bindings });
    const overLimitCheck = verifyReceipt(overLimitRecomputed, { mandate, policy: strictPolicy, quotes: steps[0].quotes });
    assert.equal(overLimitCheck.valid, false);
    assert.equal(overLimitCheck.reason, "selection-violates-policy");

    const stricterPolicy = { ...policy, maxCost: 400 };
    const drift = verifyReceipt(receipt, { mandate, policy: stricterPolicy, quotes: steps[0].quotes });
    assert.equal(drift.valid, false);
    assert.equal(drift.reason, "policy-drift");

    const mandateDrift = verifyReceipt(receipt, {
      mandate: { ...mandate, mandateId: "MND-OTHER" },
      policy,
      quotes: steps[0].quotes
    });
    assert.equal(mandateDrift.valid, false);
    assert.equal(mandateDrift.reason, "mandate-drift");
  });

  it("runs deterministic multi-round benchmark", () => {
    const bench = runBenchmark({ rounds: 25 });
    assert.equal(bench.deterministic, true);
    assert.equal(bench.totals.baselineEvalCalls, 250);
    assert.equal(bench.totals.replayEvalCalls, 150);
    assert.equal(bench.totals.replayStaleUses, 0);
    assert.equal(bench.totals.accuracyTie, true);
  });
});

describe("DeltaX Decision Relay local HTTP server", () => {
  let server;
  let baseUrl;

  before(async () => {
    server = createRelayServer();
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const addr = server.address();
    baseUrl = `http://127.0.0.1:${addr.port}`;
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  it("serves client view and fixed API endpoints", async () => {
    const homeRes = await fetch(`${baseUrl}/`);
    assert.equal(homeRes.status, 200);
    const html = await homeRes.text();
    assert.match(html, /LOCAL FIXTURE REPLAY/);

    const healthRes = await fetch(`${baseUrl}/health`);
    assert.equal(healthRes.status, 200);
    const health = await healthRes.json();
    assert.equal(health.outboundNetwork, false);

    const replayRes = await fetch(`${baseUrl}/api/replay`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ maxCost: 400, maxDays: 2 })
    });
    assert.equal(replayRes.status, 200);
    const replay = await replayRes.json();
    assert.equal(replay.steps[0].replay.selectedVendorId, "vendor-a");
    assert.equal(replay.steps[3].replay.status, "abstained");
    assert.equal(replay.tamperProbe.allRejected, true);

    const benchRes = await fetch(`${baseUrl}/api/benchmark?rounds=10`);
    assert.equal(benchRes.status, 200);
    const bench = await benchRes.json();
    assert.equal(bench.deterministic, true);
    assert.equal(bench.rounds, 10);
  });

  it("blocks non-allowlisted routes and arbitrary src reads", async () => {
    const srcRes = await fetch(`${baseUrl}/src/relay.js`);
    assert.equal(srcRes.status, 404);

    const travRes = await fetch(`${baseUrl}/../package.json`);
    assert.equal(travRes.status, 404);
  });
});
