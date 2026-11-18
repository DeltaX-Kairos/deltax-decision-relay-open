import crypto from 'node:crypto';
import { createScenario, evaluatePolicy, getRelevantQuotes, sha256Hex } from './relay.js';

const RECEIPT_VERSION = 1;
const VALID_KINDS = new Set(['replay', 'hosted', 'hosted-no-reuse']);
const VALID_SOURCES = new Set(['local-fixture', 'hosted-evaluate', 'local-policy']);
const VALID_RECEIPT_STATUSES = new Set(['selected', 'abstained']);
const SAFE_PHASE_RE = /^[a-zA-Z0-9_-]{1,64}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const MAX_SESSION_LEN = 256;
const MAX_CANDIDATES = 2;

/**
 * Canonicalize values into a deterministic JSON-compatible structure
 * so digests and HMAC signatures are independent of key insertion order.
 */
export function canonicalize(value) {
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => (item === undefined ? null : canonicalize(item)));
  }
  const out = {};
  for (const key of Object.keys(value).sort()) {
    if (value[key] !== undefined) {
      out[key] = canonicalize(value[key]);
    }
  }
  return out;
}

/**
 * Adapt ledger.reserve() output into the expected { ok: boolean, code?: string } shape.
 * Supports native { ok, code } as well as { allowed } or { reserved } fallbacks.
 */
export function adaptLedgerReserve(raw) {
  if (!raw || typeof raw !== 'object') {
    return { ok: false, code: 'LEDGER_INVALID_RESPONSE' };
  }
  if (typeof raw.ok === 'boolean') {
    return raw.code ? { ok: raw.ok, code: String(raw.code) } : { ok: raw.ok };
  }
  if (typeof raw.allowed === 'boolean') {
    const code = raw.code ?? raw.reason;
    return code ? { ok: raw.allowed, code: String(code) } : { ok: raw.allowed };
  }
  if (typeof raw.reserved === 'boolean') {
    const code = raw.code ?? raw.reason;
    return code ? { ok: raw.reserved, code: String(code) } : { ok: raw.reserved };
  }
  return { ok: false, code: 'LEDGER_INVALID_RESPONSE' };
}

function keyToBytes(signingKey) {
  if (Buffer.isBuffer(signingKey)) {
    return signingKey;
  }
  if (typeof signingKey === 'string') {
    if (/^[0-9a-f]{32,}$/i.test(signingKey) && signingKey.length % 2 === 0) {
      return Buffer.from(signingKey, 'hex');
    }
    return Buffer.from(signingKey, 'utf8');
  }
  throw new TypeError('signingKey must be a non-empty string or Buffer');
}

function computeHmacHex(keyBytes, payload) {
  const serialized = JSON.stringify(canonicalize(payload));
  return crypto.createHmac('sha256', keyBytes).update(serialized, 'utf8').digest('hex');
}

function timingSafeEqualHex(expectedHex, actualHex) {
  if (typeof expectedHex !== 'string' || typeof actualHex !== 'string') {
    return false;
  }
  if (!HEX64_RE.test(expectedHex) || !HEX64_RE.test(actualHex)) {
    return false;
  }
  const a = Buffer.from(expectedHex, 'hex');
  const b = Buffer.from(actualHex, 'hex');
  if (a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

function isPlainObject(val) {
  if (!val || typeof val !== 'object' || Array.isArray(val)) {
    return false;
  }
  const proto = Object.getPrototypeOf(val);
  return proto === Object.prototype || proto === null;
}

function hasExactKeys(obj, expectedKeys) {
  const keys = Object.keys(obj);
  if (keys.length !== expectedKeys.length) {
    return false;
  }
  return expectedKeys.every((k) => Object.prototype.hasOwnProperty.call(obj, k));
}

function sanitizeQuote(quote) {
  if (!quote || typeof quote !== 'object') {
    return null;
  }
  const out = {};
  for (const key of Object.keys(quote).sort()) {
    const val = quote[key];
    if (
      val === null ||
      typeof val === 'string' ||
      typeof val === 'number' ||
      typeof val === 'boolean'
    ) {
      out[key] = val;
    }
  }
  return out;
}

function computeDependencyDigest(relevantQuotes) {
  const normalized = [...relevantQuotes]
    .map((q) => canonicalize(q))
    .sort((a, b) => {
      const va = String(a?.vendorId ?? '');
      const vb = String(b?.vendorId ?? '');
      if (va !== vb) return va.localeCompare(vb);
      const ra = String(a?.revision ?? '');
      const rb = String(b?.revision ?? '');
      if (ra !== rb) return ra.localeCompare(rb);
      return JSON.stringify(a).localeCompare(JSON.stringify(b));
    });
  return sha256Hex(normalized);
}

function sanitizeProviderEvidence(evalRes) {
  if (!evalRes || typeof evalRes !== 'object') {
    return null;
  }
  const ev = isPlainObject(evalRes.evidence) ? evalRes.evidence : {};
  return {
    receiptId: typeof evalRes.receiptId === 'string' ? evalRes.receiptId.slice(0, 128) : null,
    providerReceiptId: typeof evalRes.providerReceiptId === 'string' ? evalRes.providerReceiptId.slice(0, 64) : null,
    selectedCandidateId:
      typeof evalRes.selectedCandidateId === 'string' ? evalRes.selectedCandidateId.slice(0, 128) : null,
    requestDigest: typeof ev.requestDigest === 'string' ? ev.requestDigest.slice(0, 128) : null,
    policyDigest: typeof ev.policyDigest === 'string' ? ev.policyDigest.slice(0, 128) : null,
    receiptDigest: typeof ev.receiptDigest === 'string' ? ev.receiptDigest.slice(0, 128) : null,
    gates: Array.isArray(ev.gates) ? ev.gates.slice(0, 16).map((g) => canonicalize(g)) : null,
    evaluatedAt: typeof ev.evaluatedAt === 'string' ? ev.evaluatedAt.slice(0, 64) : null
  };
}

function validateProviderEvidenceShape(evidence) {
  if (evidence === null) {
    return true;
  }
  if (!isPlainObject(evidence)) {
    return false;
  }
  const expected = [
    'receiptId',
    'providerReceiptId',
    'selectedCandidateId',
    'requestDigest',
    'policyDigest',
    'receiptDigest',
    'gates',
    'evaluatedAt'
  ];
  if (!hasExactKeys(evidence, expected)) {
    return false;
  }
  for (const k of ['receiptId', 'providerReceiptId', 'selectedCandidateId', 'requestDigest', 'policyDigest', 'receiptDigest', 'evaluatedAt']) {
    const v = evidence[k];
    if (v !== null && (typeof v !== 'string' || v.length > 128)) {
      return false;
    }
  }
  if (evidence.gates !== null && (!Array.isArray(evidence.gates) || evidence.gates.length > 16)) {
    return false;
  }
  return true;
}

function validateReceiptEnvelope(receipt, keyBytes) {
  if (!isPlainObject(receipt) || !hasExactKeys(receipt, ['v', 'payload', 'sig'])) {
    return { ok: false, reason: 'Malformed receipt envelope.' };
  }
  if (receipt.v !== RECEIPT_VERSION || typeof receipt.sig !== 'string' || !HEX64_RE.test(receipt.sig)) {
    return { ok: false, reason: 'Invalid receipt version or signature format.' };
  }
  const p = receipt.payload;
  const payloadKeys = [
    'v',
    'sessionDigest',
    'lane',
    'source',
    'status',
    'mandateDigest',
    'policyDigest',
    'dependencyDigest',
    'selectedVendorId',
    'selectedQuote',
    'providerEvidence',
    'issuedAt'
  ];
  if (!isPlainObject(p) || !hasExactKeys(p, payloadKeys)) {
    return { ok: false, reason: 'Malformed receipt payload fields.' };
  }
  if (p.v !== RECEIPT_VERSION) {
    return { ok: false, reason: 'Unsupported receipt payload version.' };
  }
  if (!HEX64_RE.test(p.sessionDigest)) {
    return { ok: false, reason: 'Invalid receipt session binding.' };
  }
  if (!VALID_KINDS.has(p.lane) || !VALID_SOURCES.has(p.source) || !VALID_RECEIPT_STATUSES.has(p.status)) {
    return { ok: false, reason: 'Invalid receipt lane, source, or status.' };
  }
  if (!HEX64_RE.test(p.mandateDigest) || !HEX64_RE.test(p.policyDigest) || !HEX64_RE.test(p.dependencyDigest)) {
    return { ok: false, reason: 'Invalid receipt digest format.' };
  }
  if (p.status === 'abstained') {
    if (p.selectedVendorId !== null || p.selectedQuote !== null) {
      return { ok: false, reason: 'Abstained receipt must not contain a selection.' };
    }
  } else {
    if (typeof p.selectedVendorId !== 'string' || p.selectedVendorId.length === 0 || p.selectedVendorId.length > 64) {
      return { ok: false, reason: 'Selected receipt missing selectedVendorId.' };
    }
    if (!isPlainObject(p.selectedQuote) || p.selectedQuote.vendorId !== p.selectedVendorId) {
      return { ok: false, reason: 'Selected receipt has invalid selectedQuote.' };
    }
  }
  if (!validateProviderEvidenceShape(p.providerEvidence)) {
    return { ok: false, reason: 'Invalid receipt provider evidence.' };
  }
  if (typeof p.issuedAt !== 'string' || Number.isNaN(Date.parse(p.issuedAt))) {
    return { ok: false, reason: 'Invalid receipt timestamp.' };
  }

  const expectedSig = computeHmacHex(keyBytes, p);
  if (!timingSafeEqualHex(expectedSig, receipt.sig)) {
    return { ok: false, reason: 'Receipt HMAC verification failed.' };
  }
  return { ok: true, payload: p };
}

function isLaneCompatible(receiptLane, requestKind) {
  if (requestKind === 'replay') {
    return receiptLane === 'replay';
  }
  if (requestKind === 'hosted') {
    return receiptLane === 'hosted';
  }
  if (requestKind === 'hosted-no-reuse') {
    return receiptLane === 'hosted' || receiptLane === 'hosted-no-reuse';
  }
  return false;
}

function quotesMatch(a, b) {
  if (!a || !b) return false;
  return JSON.stringify(canonicalize(sanitizeQuote(a))) === JSON.stringify(canonicalize(sanitizeQuote(b)));
}

function signReceipt(keyBytes, payload) {
  const sig = computeHmacHex(keyBytes, payload);
  return { v: RECEIPT_VERSION, payload, sig };
}

function buildCandidatesAndContext({ phase, kind, mandate, policy, mandateDigest, policyDigest, dependencyDigest, relevantQuotes, baseline }) {
  const validEvaluations = baseline.evaluations.filter((e) => e && e.valid === true);
  const quoteByVendor = new Map();
  for (const q of relevantQuotes) {
    if (q && typeof q.vendorId === 'string' && !quoteByVendor.has(q.vendorId)) {
      quoteByVendor.set(q.vendorId, q);
    }
  }

  const eligiblePairs = [];
  for (const ev of validEvaluations) {
    const quote = quoteByVendor.get(ev.vendorId);
    if (quote) {
      eligiblePairs.push({ evalRow: ev, quote });
    }
  }

  // Rank deterministically; default A above B when both are eligible with equal policy metrics.
  eligiblePairs.sort((a, b) => {
    const costDiff = Number(a.evalRow.cost ?? a.quote.cost ?? 0) - Number(b.evalRow.cost ?? b.quote.cost ?? 0);
    if (costDiff !== 0) return costDiff;
    const daysDiff = Number(a.evalRow.days ?? a.quote.days ?? 0) - Number(b.evalRow.days ?? b.quote.days ?? 0);
    if (daysDiff !== 0) return daysDiff;
    return String(a.quote.vendorId).localeCompare(String(b.quote.vendorId));
  });

  const capped = eligiblePairs.slice(0, MAX_CANDIDATES);
  const stepType = capped.length > 1 ? 'compare' : 'validate';
  const candidateMap = new Map();
  const candidates = capped.map(({ quote }, index) => {
    const normalizedVendor = String(quote.vendorId).toLowerCase().replace(/[^a-z0-9-]+/g, '-');
    const id = `review-${normalizedVendor}`;
    const support = index === 0 ? 0.9 : 0.7;
    candidateMap.set(id, quote);
    return {
      candidate_id: id,
      semantic_class: stepType,
      description: `Review fictional quote ${quote.vendorId} revision ${quote.revision}: $${quote.cost}, delivery in ${quote.days} days.`,
      operator_reported_support: support
    };
  });

  const context = {
    phase,
    lane: kind,
    mandate_id: mandate.mandateId,
    mandate_digest: mandateDigest,
    rule_digest: policyDigest,
    dependency_digest: dependencyDigest,
    max_cost: policy.maxCost,
    max_days: policy.maxDays,
    eligible_count: eligiblePairs.length
  };

  return { candidates, context, candidateMap };
}

/**
 * Create a Decision Relay reviewer enforcing HMAC receipts, lane isolation,
 * independent policy revalidation, and one-review-per-uncached-basis hosted evaluation.
 */
export function createReviewer({ supplier, signingKey, evaluate, ledger, scenario }) {
  if (!supplier || typeof supplier.verify !== 'function') {
    throw new TypeError('createReviewer requires supplier.verify');
  }
  if (!signingKey) {
    throw new TypeError('createReviewer requires signingKey');
  }
  const keyBytes = keyToBytes(signingKey);
  if (keyBytes.length < 16) {
    throw new RangeError('signingKey must be at least 16 bytes');
  }

  return {
    async decide({ session, phase, snapshot, receipt = null, kind }) {
      const defaultSource = kind === 'replay' ? 'local-fixture' : 'local-policy';

      if (!VALID_KINDS.has(kind)) {
        return {
          status: 'refused',
          reason: 'Unsupported decision kind.',
          selectedQuote: null,
          receipt: null,
          state: 'stopped',
          source: 'local-policy',
          providerCalls: 0,
          quotes: [],
          baseline: { status: 'abstained', selectedVendorId: null }
        };
      }

      if (typeof session !== 'string' || session.length === 0 || session.length > MAX_SESSION_LEN) {
        return {
          status: 'refused',
          reason: 'Invalid or missing session binding.',
          selectedQuote: null,
          receipt: null,
          state: 'stopped',
          source: defaultSource,
          providerCalls: 0,
          quotes: [],
          baseline: { status: 'abstained', selectedVendorId: null }
        };
      }

      if (typeof phase !== 'string' || !SAFE_PHASE_RE.test(phase)) {
        return {
          status: 'refused',
          reason: 'Invalid or missing phase.',
          selectedQuote: null,
          receipt: null,
          state: 'stopped',
          source: defaultSource,
          providerCalls: 0,
          quotes: [],
          baseline: { status: 'abstained', selectedVendorId: null }
        };
      }

      const sessionDigest = sha256Hex({ domain: 'relay-session-v1', session });
      let validOldPayload = null;
      if (receipt !== null && receipt !== undefined) {
        const check = validateReceiptEnvelope(receipt, keyBytes);
        if (!check.ok) {
          return {
            status: 'refused',
            reason: check.reason,
            selectedQuote: null,
            receipt: null,
            state: 'stopped',
            source: defaultSource,
            providerCalls: 0,
            quotes: [],
            baseline: { status: 'abstained', selectedVendorId: null }
          };
        }
        if (check.payload.sessionDigest !== sessionDigest) {
          return {
            status: 'refused',
            reason: 'Receipt session mismatch.',
            selectedQuote: null,
            receipt: null,
            state: 'stopped',
            source: defaultSource,
            providerCalls: 0,
            quotes: [],
            baseline: { status: 'abstained', selectedVendorId: null }
          };
        }
        if (!isLaneCompatible(check.payload.lane, kind)) {
          return {
            status: 'refused',
            reason: 'Receipt lane mismatch.',
            selectedQuote: null,
            receipt: null,
            state: 'stopped',
            source: defaultSource,
            providerCalls: 0,
            quotes: [],
            baseline: { status: 'abstained', selectedVendorId: null }
          };
        }
        validOldPayload = check.payload;
      }

      const activeScenario = scenario ?? createScenario();
      const { mandate, policy } = activeScenario;
      const trustedQuotes = await supplier.verify(snapshot, phase);

      if (!Array.isArray(trustedQuotes) || (trustedQuotes.length === 0 && phase === 'unavailable')) {
        return {
          status: 'unavailable',
          reason: 'Supplier snapshot unavailable or untrusted.',
          selectedQuote: null,
          receipt: null,
          state: 'stopped',
          source: defaultSource,
          providerCalls: 0,
          quotes: [],
          baseline: { status: 'abstained', selectedVendorId: null }
        };
      }

      const relevantQuotes = getRelevantQuotes(policy, trustedQuotes);
      const policyEval = evaluatePolicy(policy, relevantQuotes);
      const baseline = {
        status: policyEval.status,
        selectedVendorId: policyEval.selectedVendorId ?? null
      };

      const mandateDigest = sha256Hex(canonicalize(mandate));
      const policyDigest = sha256Hex(canonicalize(policy));
      const dependencyDigest = computeDependencyDigest(relevantQuotes);

      if (validOldPayload && kind !== 'hosted-no-reuse') {
        const sameBasis =
          validOldPayload.mandateDigest === mandateDigest &&
          validOldPayload.policyDigest === policyDigest &&
          validOldPayload.dependencyDigest === dependencyDigest;

        if (sameBasis) {
          if (validOldPayload.status === 'abstained' && policyEval.status === 'abstained') {
            return {
              status: 'abstained',
              reason: 'Reused verified abstention receipt for unchanged dependency basis.',
              selectedQuote: null,
              receipt,
              state: 'reused',
              source: validOldPayload.source,
              providerCalls: 0,
              quotes: trustedQuotes,
              baseline
            };
          }

          if (validOldPayload.status === 'selected') {
            const stillValid = policyEval.evaluations.some(
              (e) => e.vendorId === validOldPayload.selectedVendorId && e.valid === true
            );
            const currentMatch = relevantQuotes.find(
              (q) => q && q.vendorId === validOldPayload.selectedVendorId
            );
            if (stillValid && currentMatch && quotesMatch(currentMatch, validOldPayload.selectedQuote)) {
              return {
                status: 'selected',
                reason: 'Reused verified decision receipt for unchanged dependency basis.',
                selectedQuote: currentMatch,
                receipt,
                state: 'reused',
                source: validOldPayload.source,
                providerCalls: 0,
                quotes: trustedQuotes,
                baseline
              };
            }
          }
        }
      }

      const nextState = validOldPayload && kind !== 'hosted-no-reuse' ? 'replanned' : 'new';
      const priorQuote = validOldPayload?.selectedQuote;
      const refreshedQuote = priorQuote && relevantQuotes.find(q => q.vendorId === priorQuote.vendorId);
      const driftExplanation = nextState !== 'replanned' ? '' :
        refreshedQuote && refreshedQuote.days !== priorQuote.days
          ? `${refreshedQuote.name} shifted from ${priorQuote.days} to ${refreshedQuote.days} days. The prior receipt expired. `
          : 'The decision evidence changed. The prior receipt expired. ';

      const issuedAt = new Date().toISOString();

      if (kind === 'replay') {
        const selectedQuote =
          policyEval.status === 'selected'
            ? relevantQuotes.find((q) => q && q.vendorId === policyEval.selectedVendorId) ??
              policyEval.selectedQuote ??
              null
            : null;
        const status = selectedQuote ? 'selected' : 'abstained';
        const newReceipt = signReceipt(keyBytes, {
          v: RECEIPT_VERSION,
          sessionDigest,
          lane: 'replay',
          source: 'local-fixture',
          status,
          mandateDigest,
          policyDigest,
          dependencyDigest,
          selectedVendorId: selectedQuote ? selectedQuote.vendorId : null,
          selectedQuote: selectedQuote ? sanitizeQuote(selectedQuote) : null,
          providerEvidence: null,
          issuedAt
        });
        return {
          status,
          reason:
            status === 'selected'
              ? driftExplanation + 'Selected the best eligible quote under local policy.'
              : driftExplanation + 'No quote meets the policy.',
          selectedQuote,
          receipt: newReceipt,
          state: nextState,
          source: 'local-fixture',
          providerCalls: 0,
          quotes: trustedQuotes,
          baseline
        };
      }

      const eligibleEvals = policyEval.evaluations.filter((e) => e && e.valid === true);
      if (policyEval.status === 'abstained' || eligibleEvals.length === 0) {
        const abstainReceipt = signReceipt(keyBytes, {
          v: RECEIPT_VERSION,
          sessionDigest,
          lane: kind,
          source: 'local-policy',
          status: 'abstained',
          mandateDigest,
          policyDigest,
          dependencyDigest,
          selectedVendorId: null,
          selectedQuote: null,
          providerEvidence: null,
          issuedAt
        });
        return {
          status: 'abstained',
          reason: driftExplanation + 'No quote meets the policy. Hosted review skipped.',
          selectedQuote: null,
          receipt: abstainReceipt,
          state: nextState,
          source: 'local-policy',
          providerCalls: 0,
          quotes: trustedQuotes,
          baseline
        };
      }

      if (typeof evaluate !== 'function' || !ledger) {
        return {
          status: 'refused',
          reason: 'Hosted evaluation or ledger is not configured.',
          selectedQuote: null,
          receipt: null,
          state: 'stopped',
          source: 'local-policy',
          providerCalls: 0,
          quotes: trustedQuotes,
          baseline
        };
      }

      // An unknown or lost response must never be replayed for the same basis.
      const digest = sha256Hex({ sessionDigest, phase, kind, policyDigest, dependencyDigest });
      const idempotencyKey = `${digest.slice(0, 8)}-${digest.slice(8, 12)}-5${digest.slice(13, 16)}-a${digest.slice(17, 20)}-${digest.slice(20, 32)}`;
      const reserveRaw = await ledger.reserve({ session, idempotencyKey });
      const reserve = adaptLedgerReserve(reserveRaw);
      if (!reserve.ok) {
        return {
          status: 'refused',
          reason: reserve.code
            ? `Hosted review blocked by ledger (${reserve.code}).`
            : 'Hosted review blocked by ledger.',
          selectedQuote: null,
          receipt: null,
          state: 'stopped',
          source: 'local-policy',
          providerCalls: 0,
          quotes: trustedQuotes,
          baseline
        };
      }

      const { candidates, context, candidateMap } = buildCandidatesAndContext({
        phase,
        kind,
        mandate,
        policy,
        mandateDigest,
        policyDigest,
        dependencyDigest,
        relevantQuotes,
        baseline: policyEval
      });

      let evalRes;
      try {
        evalRes = await evaluate({ context, candidates, idempotencyKey });
      } catch {
        try {
          await ledger.result(idempotencyKey, 'unknown');
        } catch {
          // Best-effort ledger completion.
        }
        return {
          status: 'unknown',
          reason: 'Hosted evaluator call failed.',
          selectedQuote: null,
          receipt: null,
          state: 'stopped',
          source: 'hosted-evaluate',
          providerCalls: 1,
          quotes: trustedQuotes,
          baseline
        };
      }

      const evalStatus = evalRes?.status ?? 'unknown';
      try {
        await ledger.result(idempotencyKey, ['selected', 'refused', 'rejected'].includes(evalStatus) ? evalStatus : 'unknown');
      } catch {
        // Best-effort ledger completion.
      }

      if (evalStatus === 'unconfigured') {
        return {
          status: 'refused',
          reason: 'Hosted evaluator reported unconfigured credentials.',
          selectedQuote: null,
          receipt: null,
          state: 'stopped',
          source: 'local-policy',
          providerCalls: 1,
          quotes: trustedQuotes,
          baseline
        };
      }

      if (evalStatus === 'unknown') {
        return {
          status: 'unknown',
          reason: evalRes?.code
            ? `Hosted evaluator returned unknown (${evalRes.code}).`
            : 'Hosted evaluator returned unknown outcome.',
          selectedQuote: null,
          receipt: null,
          state: 'stopped',
          source: 'hosted-evaluate',
          providerCalls: 1,
          quotes: trustedQuotes,
          baseline
        };
      }

      if (evalStatus === 'refused' || evalStatus === 'rejected') {
        return {
          status: 'refused',
          reason: evalRes?.code
            ? `Hosted evaluator ${evalStatus} request (${evalRes.code}).`
            : `Hosted evaluator ${evalStatus} request.`,
          selectedQuote: null,
          receipt: null,
          state: 'stopped',
          source: 'hosted-evaluate',
          providerCalls: 1,
          quotes: trustedQuotes,
          baseline
        };
      }

      if (evalStatus !== 'selected') {
        return {
          status: 'unknown',
          reason: 'Hosted evaluator returned unrecognized status.',
          selectedQuote: null,
          receipt: null,
          state: 'stopped',
          source: 'hosted-evaluate',
          providerCalls: 1,
          quotes: trustedQuotes,
          baseline
        };
      }

      const selectedCandidateId = evalRes?.selectedCandidateId;
      const mappedQuote =
        typeof selectedCandidateId === 'string' ? candidateMap.get(selectedCandidateId) : null;
      const isBaselineEligible =
        mappedQuote &&
        policyEval.evaluations.some((e) => e.vendorId === mappedQuote.vendorId && e.valid === true);

      if (!mappedQuote || !isBaselineEligible) {
        return {
          status: 'refused',
          reason: 'Hosted evaluator selected an invalid or ineligible candidate.',
          selectedQuote: null,
          receipt: null,
          state: 'stopped',
          source: 'hosted-evaluate',
          providerCalls: 1,
          quotes: trustedQuotes,
          baseline
        };
      }

      const hostedReceipt = signReceipt(keyBytes, {
        v: RECEIPT_VERSION,
        sessionDigest,
        lane: kind,
        source: 'hosted-evaluate',
        status: 'selected',
        mandateDigest,
        policyDigest,
        dependencyDigest,
        selectedVendorId: mappedQuote.vendorId,
        selectedQuote: sanitizeQuote(mappedQuote),
        providerEvidence: sanitizeProviderEvidence(evalRes),
        issuedAt
      });

      return {
        status: 'selected',
        reason: driftExplanation + 'Hosted Evaluate selected the review step. The quote met local policy.',
        selectedQuote: mappedQuote,
        receipt: hostedReceipt,
        state: nextState,
        source: 'hosted-evaluate',
        providerCalls: 1,
        quotes: trustedQuotes,
        baseline
      };
    }
  };
}
