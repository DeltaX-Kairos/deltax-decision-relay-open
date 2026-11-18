import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";

export const RECEIPT_KIND = "deltax.decision-replay.local-fixture.v1";
export const RECEIPT_SOURCE = "local-fixture-replay";

export const DEFAULT_POLICY = Object.freeze({
  sku: "EQ-CRIT-01",
  count: 1,
  region: "us-west",
  maxCost: 450,
  maxDays: 3
});

export function canonicalize(value) {
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  const out = {};
  for (const key of Object.keys(value).sort()) {
    out[key] = canonicalize(value[key]);
  }
  return out;
}

export function sha256Hex(value) {
  return createHash("sha256")
    .update(JSON.stringify(canonicalize(value)))
    .digest("hex");
}

export function normalizePolicy(overrides = {}) {
  const maxCost = overrides.maxCost === undefined ? DEFAULT_POLICY.maxCost : Number(overrides.maxCost);
  const maxDays = overrides.maxDays === undefined ? DEFAULT_POLICY.maxDays : Number(overrides.maxDays);
  if (!Number.isFinite(maxCost) || maxCost <= 0) {
    throw new RangeError("maxCost must be a positive finite number");
  }
  if (!Number.isFinite(maxDays) || maxDays <= 0) {
    throw new RangeError("maxDays must be a positive finite number");
  }
  return Object.freeze({
    sku: DEFAULT_POLICY.sku,
    count: DEFAULT_POLICY.count,
    region: DEFAULT_POLICY.region,
    maxCost,
    maxDays
  });
}

export function createScenario(overrides = {}) {
  const mandate = Object.freeze({
    mandateId: "MND-EQ-2026-01",
    purpose: "time-critical-equipment-procurement"
  });
  const policy = normalizePolicy(overrides);

  const quoteA1 = { vendorId: "vendor-a", name: "Vendor A", sku: "EQ-CRIT-01", cost: 380, days: 2, revision: 1 };
  const quoteB1 = { vendorId: "vendor-b", name: "Vendor B", sku: "EQ-CRIT-01", cost: 420, days: 3, revision: 1 };
  const quoteAux1 = { vendorId: "aux-d", name: "Aux D (Unrelated)", sku: "AUX-99", cost: 90, days: 2, revision: 1 };

  const quoteAux2 = { ...quoteAux1, cost: 95, revision: 2 };
  const quoteA2 = { ...quoteA1, days: 5, revision: 2 };
  const quoteB2 = { ...quoteB1, days: 4, revision: 2 };

  const steps = [
    {
      stepId: "step-1-initial",
      label: "1. Initial cheapest valid selection",
      quotes: [quoteA1, quoteB1, quoteAux1]
    },
    {
      stepId: "step-2-unchanged",
      label: "2. Unchanged input decision receipt reuse",
      quotes: [quoteA1, quoteB1, quoteAux1]
    },
    {
      stepId: "step-3-unrelated",
      label: "3. Unrelated item revision (AUX-99) receipt reuse",
      quotes: [quoteA1, quoteB1, quoteAux2]
    },
    {
      stepId: "step-4-relevant-drift",
      label: "4. Relevant revision (Vendor A -> 5 days) invalidation & alternative",
      quotes: [quoteA2, quoteB1, quoteAux2]
    },
    {
      stepId: "step-5-all-invalid",
      label: "5. All invalid (Vendor B -> 4 days) abstention",
      quotes: [quoteA2, quoteB2, quoteAux2]
    }
  ];

  return { mandate, policy, steps };
}

export function getRelevantQuotes(policy, quotes) {
  return quotes
    .filter((q) => q && q.sku === policy.sku)
    .map((q) => ({ ...q }))
    .sort((a, b) => a.vendorId.localeCompare(b.vendorId));
}

export function buildRevisionsMap(relevantQuotes) {
  const revisions = {};
  for (const q of relevantQuotes) {
    revisions[q.vendorId] = {
      revision: q.revision,
      cost: q.cost,
      days: q.days,
      sku: q.sku
    };
  }
  return revisions;
}

export function evaluatePolicy(policy, quotes) {
  const relevantQuotes = getRelevantQuotes(policy, quotes);
  const evaluations = [];
  const validCandidates = [];

  for (const q of relevantQuotes) {
    const reasons = [];
    if (!Number.isFinite(q.cost) || q.cost < 0 || q.cost > policy.maxCost) {
      reasons.push(`cost $${q.cost} exceeds max $${policy.maxCost}`);
    }
    if (!Number.isFinite(q.days) || q.days < 0 || q.days > policy.maxDays) {
      reasons.push(`lead time ${q.days}d exceeds max ${policy.maxDays}d`);
    }
    const valid = reasons.length === 0;
    evaluations.push({
      vendorId: q.vendorId,
      name: q.name,
      cost: q.cost,
      days: q.days,
      revision: q.revision,
      valid,
      reasons
    });
    if (valid) {
      validCandidates.push(q);
    }
  }

  validCandidates.sort(
    (a, b) => a.cost - b.cost || a.days - b.days || a.vendorId.localeCompare(b.vendorId)
  );

  if (validCandidates.length > 0) {
    const chosen = { ...validCandidates[0] };
    return {
      status: "selected",
      selectedVendorId: chosen.vendorId,
      selectedQuote: chosen,
      relevantQuotes,
      evaluations,
      evalCalls: relevantQuotes.length
    };
  }

  return {
    status: "abstained",
    selectedVendorId: null,
    selectedQuote: null,
    relevantQuotes,
    evaluations,
    evalCalls: relevantQuotes.length
  };
}

export function buildReceipt({ mandate, policy, evaluation }) {
  const relevantSet = evaluation.relevantQuotes.map((q) => q.vendorId);
  const revisions = buildRevisionsMap(evaluation.relevantQuotes);
  const selection = {
    status: evaluation.status,
    selectedVendorId: evaluation.selectedVendorId,
    selectedQuote: evaluation.selectedQuote ? { ...evaluation.selectedQuote } : null
  };

  const bindings = {
    mandateDigest: sha256Hex(mandate),
    policyDigest: sha256Hex(policy),
    relevantSetDigest: sha256Hex(relevantSet),
    revisionsDigest: sha256Hex(revisions),
    selectionDigest: sha256Hex(selection)
  };

  const evidenceDigest = sha256Hex({ kind: RECEIPT_KIND, ...bindings });

  return {
    kind: RECEIPT_KIND,
    source: RECEIPT_SOURCE,
    authority: {
      providerSignature: false,
      appSignedEnvelope: false,
      authorityClaim: false,
      note: "Local fixture digest binding only; digest alone is not authenticity."
    },
    mandateId: mandate.mandateId,
    policy: { ...policy },
    relevantSet,
    revisions,
    selection,
    bindings,
    evidenceDigest
  };
}

export function verifyReceipt(receipt, { mandate, policy, quotes }) {
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) {
    return { valid: false, reason: "invalid-receipt-shape" };
  }
  if (receipt.kind !== RECEIPT_KIND || receipt.source !== RECEIPT_SOURCE) {
    return { valid: false, reason: "invalid-receipt-kind-or-source" };
  }
  if (
    !receipt.authority ||
    receipt.authority.providerSignature !== false ||
    receipt.authority.appSignedEnvelope !== false ||
    receipt.authority.authorityClaim !== false
  ) {
    return { valid: false, reason: "invalid-authority-claim" };
  }
  if (!receipt.bindings || typeof receipt.bindings !== "object" || Array.isArray(receipt.bindings)) {
    return { valid: false, reason: "missing-bindings" };
  }
  if (
    !receipt.selection ||
    (receipt.selection.status !== "selected" && receipt.selection.status !== "abstained")
  ) {
    return { valid: false, reason: "invalid-selection-shape" };
  }
  if (receipt.selection.status === "selected") {
    const q = receipt.selection.selectedQuote;
    if (typeof receipt.selection.selectedVendorId !== "string" || !q || q.vendorId !== receipt.selection.selectedVendorId) {
      return { valid: false, reason: "invalid-selected-quote-shape" };
    }
  } else if (receipt.selection.selectedVendorId !== null || receipt.selection.selectedQuote !== null) {
    return { valid: false, reason: "invalid-abstained-shape" };
  }
  if (
    !Array.isArray(receipt.relevantSet) ||
    !receipt.revisions ||
    typeof receipt.revisions !== "object" ||
    Array.isArray(receipt.revisions)
  ) {
    return { valid: false, reason: "invalid-dependency-shape" };
  }

  const expectedSelectionDigest = sha256Hex({
    status: receipt.selection.status,
    selectedVendorId: receipt.selection.selectedVendorId,
    selectedQuote: receipt.selection.selectedQuote
  });
  if (receipt.bindings.selectionDigest !== expectedSelectionDigest) {
    return { valid: false, reason: "selection-digest-mismatch" };
  }

  const expectedEvidenceDigest = sha256Hex({
    kind: RECEIPT_KIND,
    mandateDigest: receipt.bindings.mandateDigest,
    policyDigest: receipt.bindings.policyDigest,
    relevantSetDigest: receipt.bindings.relevantSetDigest,
    revisionsDigest: receipt.bindings.revisionsDigest,
    selectionDigest: receipt.bindings.selectionDigest
  });
  if (receipt.evidenceDigest !== expectedEvidenceDigest) {
    return { valid: false, reason: "evidence-digest-mismatch" };
  }

  if (receipt.mandateId !== mandate.mandateId || receipt.bindings.mandateDigest !== sha256Hex(mandate)) {
    return { valid: false, reason: "mandate-drift" };
  }
  const expectedPolicyDigest = sha256Hex(policy);
  if (
    !receipt.policy ||
    typeof receipt.policy !== "object" ||
    Array.isArray(receipt.policy) ||
    receipt.bindings.policyDigest !== expectedPolicyDigest ||
    sha256Hex(receipt.policy) !== expectedPolicyDigest
  ) {
    return { valid: false, reason: "policy-drift" };
  }

  const currentRelevant = getRelevantQuotes(policy, quotes);
  const currentRelevantSet = currentRelevant.map((q) => q.vendorId);
  const currentRevisions = buildRevisionsMap(currentRelevant);

  const expectedRelevantSetDigest = sha256Hex(currentRelevantSet);
  if (
    receipt.bindings.relevantSetDigest !== expectedRelevantSetDigest ||
    sha256Hex(receipt.relevantSet) !== expectedRelevantSetDigest
  ) {
    return { valid: false, reason: "relevant-set-drift" };
  }

  const expectedRevisionsDigest = sha256Hex(currentRevisions);
  if (
    receipt.bindings.revisionsDigest !== expectedRevisionsDigest ||
    sha256Hex(receipt.revisions) !== expectedRevisionsDigest
  ) {
    return { valid: false, reason: "relevant-revision-drift" };
  }

  if (receipt.selection.status === "selected") {
    const groundedQuote = currentRelevant.find((q) => q.vendorId === receipt.selection.selectedVendorId);
    if (!groundedQuote || sha256Hex(receipt.selection.selectedQuote) !== sha256Hex(groundedQuote)) {
      return { valid: false, reason: "ungrounded-selection" };
    }
    if (
      !Number.isFinite(groundedQuote.cost) ||
      groundedQuote.cost < 0 ||
      groundedQuote.cost > policy.maxCost ||
      !Number.isFinite(groundedQuote.days) ||
      groundedQuote.days < 0 ||
      groundedQuote.days > policy.maxDays
    ) {
      return { valid: false, reason: "selection-violates-policy" };
    }
  }

  return { valid: true, reason: "verified-exact-bindings" };
}

function formatEvalReason(evaluation) {
  if (evaluation.status === "selected") {
    const rejected = evaluation.evaluations
      .filter((e) => !e.valid)
      .map((e) => `${e.name} rejected (${e.reasons.join(", ")})`);
    const chosen = evaluation.selectedQuote;
    const base = `Selected ${chosen.name} ($${chosen.cost}, ${chosen.days}d) as cheapest valid quote.`;
    return rejected.length > 0 ? `${base} ${rejected.join("; ")}.` : base;
  }
  const rejected = evaluation.evaluations
    .map((e) => `${e.name}: ${e.reasons.join(", ")}`)
    .join("; ");
  return `Abstained because all relevant quotes failed hard limits (${rejected}).`;
}

export function runComparison(overrides = {}) {
  const scenario = createScenario(overrides);
  const { mandate, policy, steps } = scenario;

  let activeReceipt = null;
  const stepResults = [];

  const baselineMetrics = { validActions: 0, staleUses: 0, evalCalls: 0, abstentions: 0, reuses: 0, invalidations: 0, accuracyMatches: 0 };
  const replayMetrics = { validActions: 0, staleUses: 0, evalCalls: 0, abstentions: 0, reuses: 0, invalidations: 0, accuracyMatches: 0 };

  for (const step of steps) {
    const truth = evaluatePolicy(policy, step.quotes);

    const baseEval = evaluatePolicy(policy, step.quotes);
    baselineMetrics.evalCalls += baseEval.evalCalls;
    if (baseEval.status === "selected") baselineMetrics.validActions += 1;
    else baselineMetrics.abstentions += 1;
    const baseMatch = baseEval.status === truth.status && baseEval.selectedVendorId === truth.selectedVendorId;
    if (baseMatch) baselineMetrics.accuracyMatches += 1;
    else baselineMetrics.staleUses += 1;

    let replayAction = "evaluated";
    let replayEvalCalls = 0;
    let invalidationReason = null;
    let replayReason = "";
    let evaluations = null;

    if (activeReceipt) {
      const check = verifyReceipt(activeReceipt, { mandate, policy, quotes: step.quotes });
      if (check.valid) {
        replayAction = "reused";
        replayMetrics.reuses += 1;
        replayReason = "Reused verified receipt: mandate, policy, relevant set, and relevant revisions match exact digests.";
      } else {
        invalidationReason = check.reason;
        replayMetrics.invalidations += 1;
        const fresh = evaluatePolicy(policy, step.quotes);
        activeReceipt = buildReceipt({ mandate, policy, evaluation: fresh });
        replayAction = "invalidated-and-reevaluated";
        replayEvalCalls = fresh.evalCalls;
        evaluations = fresh.evaluations;
        replayReason = `Invalidated prior receipt (${invalidationReason}). ${formatEvalReason(fresh)}`;
      }
    } else {
      const fresh = evaluatePolicy(policy, step.quotes);
      activeReceipt = buildReceipt({ mandate, policy, evaluation: fresh });
      replayEvalCalls = fresh.evalCalls;
      evaluations = fresh.evaluations;
      replayReason = `Initial evaluation. ${formatEvalReason(fresh)}`;
    }

    replayMetrics.evalCalls += replayEvalCalls;
    const sel = activeReceipt.selection;
    if (sel.status === "selected") replayMetrics.validActions += 1;
    else replayMetrics.abstentions += 1;
    const replayMatch = sel.status === truth.status && sel.selectedVendorId === truth.selectedVendorId;
    if (replayMatch) replayMetrics.accuracyMatches += 1;
    else replayMetrics.staleUses += 1;

    stepResults.push({
      stepId: step.stepId,
      label: step.label,
      quotes: step.quotes,
      baseline: {
        action: "evaluated",
        status: baseEval.status,
        selectedVendorId: baseEval.selectedVendorId,
        evalCalls: baseEval.evalCalls,
        reason: formatEvalReason(baseEval)
      },
      replay: {
        action: replayAction,
        invalidationReason,
        status: sel.status,
        selectedVendorId: sel.selectedVendorId,
        selectedQuote: sel.selectedQuote,
        evalCalls: replayEvalCalls,
        source: activeReceipt.source,
        authority: activeReceipt.authority,
        evidenceDigest: activeReceipt.evidenceDigest,
        bindings: activeReceipt.bindings,
        reason: replayReason,
        evaluations: evaluations ?? baseEval.evaluations
      }
    });
  }

  return {
    mode: "local-fixture-replay",
    label: "Offline Replay (Public Local Fixtures)",
    mandate,
    policy,
    steps: stepResults,
    metrics: {
      stepsCount: steps.length,
      baseline: baselineMetrics,
      replay: replayMetrics,
      savedEvalCalls: baselineMetrics.evalCalls - replayMetrics.evalCalls,
      accuracyTie: baselineMetrics.accuracyMatches === replayMetrics.accuracyMatches
    }
  };
}

export function runTamperProbes(overrides = {}) {
  const scenario = createScenario(overrides);
  const { mandate, policy, steps } = scenario;
  const step1 = steps[0];
  const eval1 = evaluatePolicy(policy, step1.quotes);
  const validReceipt = buildReceipt({ mandate, policy, evaluation: eval1 });

  const tamperedSelection = structuredClone(validReceipt);
  tamperedSelection.selection.selectedVendorId = "vendor-b";

  const malformedShape = structuredClone(validReceipt);
  delete malformedShape.bindings;

  const forgedAuthority = structuredClone(validReceipt);
  forgedAuthority.authority.providerSignature = true;

  const forgedEnvelope = structuredClone(validReceipt);
  forgedEnvelope.authority.appSignedEnvelope = true;

  const alteredSelectionRecomputed = structuredClone(validReceipt);
  alteredSelectionRecomputed.selection.selectedQuote.cost = 100;
  alteredSelectionRecomputed.bindings.selectionDigest = sha256Hex(alteredSelectionRecomputed.selection);
  alteredSelectionRecomputed.evidenceDigest = sha256Hex({
    kind: RECEIPT_KIND,
    ...alteredSelectionRecomputed.bindings
  });

  const probes = [
    { name: "tampered-selection", ...verifyReceipt(tamperedSelection, { mandate, policy, quotes: step1.quotes }) },
    { name: "malformed-shape", ...verifyReceipt(malformedShape, { mandate, policy, quotes: step1.quotes }) },
    { name: "forged-authority", ...verifyReceipt(forgedAuthority, { mandate, policy, quotes: step1.quotes }) },
    { name: "forged-envelope", ...verifyReceipt(forgedEnvelope, { mandate, policy, quotes: step1.quotes }) },
    { name: "altered-selection-recomputed", ...verifyReceipt(alteredSelectionRecomputed, { mandate, policy, quotes: step1.quotes }) }
  ];

  return {
    allRejected: probes.every((p) => p.valid === false),
    probes
  };
}

export function runBenchmark({ rounds = 200, maxCost, maxDays } = {}) {
  if (!Number.isInteger(rounds) || rounds < 1 || rounds > 10000) {
    throw new RangeError("rounds must be an integer between 1 and 10000");
  }
  let referenceDigests = null;
  let deterministic = true;
  let lastRun = null;

  for (let i = 0; i < rounds; i += 1) {
    const run = runComparison({ maxCost, maxDays });
    const digests = run.steps.map((s) => s.replay.evidenceDigest);
    if (referenceDigests === null) {
      referenceDigests = digests;
    } else if (JSON.stringify(referenceDigests) !== JSON.stringify(digests)) {
      deterministic = false;
    }
    lastRun = run;
  }

  return {
    mode: "local-fixture-benchmark",
    rounds,
    caseNote: "Repeats one deterministic 5-step local fixture case across all rounds.",
    deterministic,
    policy: lastRun.policy,
    perRunMetrics: lastRun.metrics,
    totals: {
      baselineEvalCalls: lastRun.metrics.baseline.evalCalls * rounds,
      replayEvalCalls: lastRun.metrics.replay.evalCalls * rounds,
      savedEvalCalls: lastRun.metrics.savedEvalCalls * rounds,
      baselineStaleUses: lastRun.metrics.baseline.staleUses * rounds,
      replayStaleUses: lastRun.metrics.replay.staleUses * rounds,
      replayReuses: lastRun.metrics.replay.reuses * rounds,
      replayInvalidations: lastRun.metrics.replay.invalidations * rounds,
      replayAbstentions: lastRun.metrics.replay.abstentions * rounds,
      accuracyTie: lastRun.metrics.accuracyTie
    },
    evidenceDigests: referenceDigests
  };
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const result = runBenchmark({ rounds: 200 });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}
