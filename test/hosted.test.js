import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createHostedEvaluate } from "../src/hosted-evaluate.js";
import { createLedger } from "../src/hosted-ledger.js";
import { createRelayPair } from "../src/live-server.js";

const TOKEN_URL = "https://access-api.deltaxevaluate.com/api/builder/oauth/token";
const EVAL_URL = "https://access-api.deltaxevaluate.com/api/builder/evaluations";
const VALID_SHA = "a".repeat(64);
const VALID_SHA_B = "b".repeat(64);
const VALID_SHA_C = "c".repeat(64);
const VALID_SHA_D = "d".repeat(64);

function makeSampleRequest() {
  return {
    idempotencyKey: `key_${crypto.randomBytes(16).toString("hex")}`,
    context: {
      quote_id: "Q-4419",
      asset_class: "industrial_pump",
      budget_cap_usd: 18500,
      urgent_replacement: false
    },
    candidates: [
      {
        candidate_id: "cand_vendor_verify",
        semantic_class: "validate",
        description: "Verify vendor warranty and replacement serial compatibility.",
        operator_reported_support: 0.82
      },
      {
        candidate_id: "cand_dual_quote",
        semantic_class: "compare",
        description: "Compare two competing replacement equipment quotes.",
        operator_reported_support: 0.65
      }
    ]
  };
}

function makeValidGates(decision = "pass") {
  return Array.from({ length: 12 }, (_, i) => ({
    gate_id: `HES-G${String(i + 1).padStart(2, "0")}`,
    disposition: decision,
    reason_code: "GATE_OK"
  }));
}

function makeValidEvalPayload(overrides = {}) {
  const receiptId = overrides.receipt_id ?? "eval_rec_01J9XYZ";
  const base = {
    receipt_id: receiptId,
    evaluated_at: "2026-11-18T08:00:00.000Z",
    counted: true,
    result: {
      api_version: "2026-09-16.beta2",
      profile_id: "deltax-hosted-bounded-review-evaluation-v1",
      outcome: "selected",
      selected_candidate_id: "cand_vendor_verify",
      reason_codes: ["BOUNDED_SUPPORT_MATCH"],
      trace: {
        request_digest: VALID_SHA,
        candidate_field_digest: VALID_SHA_B,
        policy_digest: VALID_SHA_C,
        trace_id: "tr_01J9XYZ",
        release_set_digest: VALID_SHA_D,
        committed_at: "2026-11-18T08:00:00.000Z",
        lambda_decisions: makeValidGates(),
        evidence_labels: ["quote_scalar_only"],
        submitted_candidate_executed: false,
        external_effect: false,
        learning_applied: false,
        operator_reported_context_verified: false
      },
      commercial_receipt: {
        mode: "free_beta",
        receipt_sha256: VALID_SHA_B,
        commercial_binding_sha256: VALID_SHA_C,
        receipt_id: "99beb239-0f2a-4a8f-a094-18aaa71b9c6e",
        committed_at: "2026-11-18T08:00:00.000Z"
      },
      authority: {
        selected_is_executed: false,
        selected_is_correct_or_safe: false,
        response_authorizes_downstream_action: false,
        response_is_professional_advice: false,
        trace_is_certification_or_legal_non_repudiation: false
      }
    }
  };
  return structuredClone({ ...base, ...overrides });
}

function jsonResponse(bodyObj, status = 200) {
  return new Response(JSON.stringify(bodyObj), {
    status,
    headers: { "content-type": "application/json" }
  });
}

function makeTempLedgerPath(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hosted-ledger-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return path.join(dir, "ledger.jsonl");
}

test("unconfigured credentials return unconfigured without calling fetch or touching ledger", async (t) => {
  let fetchCalled = false;
  const evaluate = createHostedEvaluate({
    clientId: "",
    clientSecret: "",
    fetchImpl: async () => {
      fetchCalled = true;
      throw new Error("should not fetch");
    }
  });

  const ledgerFile = makeTempLedgerPath(t);
  const ledger = createLedger({
    file: ledgerFile,
    totalLimit: 5,
    cutoff: Date.now() + 60_000
  });

  const res = await evaluate(makeSampleRequest());
  assert.deepEqual(res, { status: "unconfigured", code: "UNCONFIGURED" });
  assert.equal(fetchCalled, false);
  assert.equal(ledger.status().totalUsed, 0);
  assert.equal(ledger.status().active, false);
});

test("successful verified gateway selects candidate, caches token with safety margin, and strips secrets/authority", async () => {
  let tokenCalls = 0;
  let evalCalls = 0;
  let clockMs = 1_700_000_000_000;
  const seenEvalRequests = [];

  const fetchImpl = async (url, init) => {
    assert.equal(init.redirect, "error");
    if (url === TOKEN_URL) {
      tokenCalls += 1;
      assert.equal(init.method, "POST");
      const params = new URLSearchParams(init.body);
      assert.equal(params.get("grant_type"), "client_credentials");
      assert.equal(params.get("client_id"), "cid_test");
      assert.equal(params.get("client_secret"), "secret_super_sensitive");
      assert.equal(params.get("scope"), "deltax:evaluate");
      return jsonResponse({
        token_type: "Bearer",
        access_token: "dxbt_token_abc123",
        scope: "deltax:evaluate",
        expires_in: 1200
      });
    }
    if (url === EVAL_URL) {
      evalCalls += 1;
      assert.equal(init.method, "POST");
      assert.equal(init.headers.Authorization, "Bearer dxbt_token_abc123");
      assert.equal(init.headers["X-DeltaX-API-Version"], "2026-09-16.beta2");
      assert.ok(init.headers["Idempotency-Key"].startsWith("key_"));
      const parsedBody = JSON.parse(init.body);
      seenEvalRequests.push(parsedBody);
      return jsonResponse(makeValidEvalPayload());
    }
    throw new Error(`Unexpected URL: ${url}`);
  };

  const evaluate = createHostedEvaluate({
    clientId: "cid_test",
    clientSecret: "secret_super_sensitive",
    fetchImpl,
    now: () => clockMs
  });

  const first = await evaluate(makeSampleRequest());
  assert.equal(first.status, "selected");
  assert.equal(first.code, "SELECTED");
  assert.equal(first.receiptId, "eval_rec_01J9XYZ");
  assert.equal(first.selectedCandidateId, "cand_vendor_verify");
  assert.equal(first.evidence.requestDigest, VALID_SHA);
  assert.equal(first.evidence.policyDigest, VALID_SHA_C);
  assert.equal(first.evidence.receiptDigest, VALID_SHA_B);
  assert.equal(first.evidence.gates.length, 12);
  assert.equal(first.evidence.evaluatedAt, "2026-11-18T08:00:00.000Z");

  const serialized = JSON.stringify(first);
  assert.equal(serialized.includes("dxbt_"), false);
  assert.equal(serialized.includes("secret_super_sensitive"), false);
  assert.equal(serialized.includes("authority"), false);
  assert.equal(seenEvalRequests[0].profile_id, "deltax-hosted-bounded-review-evaluation-v1");

  // Within clamped 900s - 30s = 870s cache window -> reuses token.
  clockMs += 800_000;
  const second = await evaluate(makeSampleRequest());
  assert.equal(second.status, "selected");
  assert.equal(tokenCalls, 1);
  assert.equal(evalCalls, 2);

  // Past 870s safety margin -> refreshes token.
  clockMs += 80_000;
  const third = await evaluate(makeSampleRequest());
  assert.equal(third.status, "selected");
  assert.equal(tokenCalls, 2);
  assert.equal(evalCalls, 3);
});

test("governed_noop_refusal returns normalized refused outcome", async () => {
  const fetchImpl = async (url) => {
    if (url === TOKEN_URL) {
      return jsonResponse({
        token_type: "Bearer",
        access_token: "dxbt_token_refuse",
        scope: "deltax:evaluate",
        expires_in: 300
      });
    }
    const payload = makeValidEvalPayload();
    payload.result.outcome = "governed_noop_refusal";
    payload.result.selected_candidate_id = null;
    payload.result.reason_codes = ["INSUFFICIENT_SUPPORT"];
    return jsonResponse(payload);
  };

  const evaluate = createHostedEvaluate({
    clientId: "cid",
    clientSecret: "sec",
    fetchImpl
  });
  const res = await evaluate(makeSampleRequest());
  assert.equal(res.status, "refused");
  assert.equal(res.code, "GOVERNED_NOOP_REFUSAL");
  assert.equal(res.selectedCandidateId, null);
  assert.deepEqual(res.reasonCodes, ["INSUFFICIENT_SUPPORT"]);
});

test("malicious response shapes (foreign candidate, authority, bad digest, wrong gates) resolve to unknown", async () => {
  const scenarios = [
    {
      name: "foreign candidate",
      mutate: (p) => {
        p.result.selected_candidate_id = "cand_foreign_injected";
      },
      expectedCode: "FOREIGN_CANDIDATE"
    },
    {
      name: "authority selected_is_executed true",
      mutate: (p) => {
        p.result.authority.selected_is_executed = true;
      },
      expectedCode: "INVALID_AUTHORITY"
    },
    {
      name: "trace external_effect true",
      mutate: (p) => {
        p.result.trace.external_effect = true;
      },
      expectedCode: "INVALID_AUTHORITY"
    },
    {
      name: "bad digest",
      mutate: (p) => {
        p.result.trace.request_digest = "not-a-sha256-digest";
      },
      expectedCode: "INVALID_DIGEST"
    },
    {
      name: "bad commercial receipt digest",
      mutate: (p) => {
        p.result.commercial_receipt.receipt_sha256 = "1234";
      },
      expectedCode: "INVALID_DIGEST"
    },
    {
      name: "out-of-order HES gates",
      mutate: (p) => {
        const g0 = p.result.trace.lambda_decisions[0];
        p.result.trace.lambda_decisions[0] = p.result.trace.lambda_decisions[1];
        p.result.trace.lambda_decisions[1] = g0;
      },
      expectedCode: "MALFORMED_RESPONSE"
    },
    {
      name: "mismatched api_version",
      mutate: (p) => {
        p.result.api_version = "2025-01-01";
      },
      expectedCode: "MALFORMED_RESPONSE"
    }
  ];

  for (const scenario of scenarios) {
    const fetchImpl = async (url) => {
      if (url === TOKEN_URL) {
        return jsonResponse({
          token_type: "Bearer",
          access_token: "dxbt_valid_123",
          scope: "deltax:evaluate",
          expires_in: 300
        });
      }
      const payload = makeValidEvalPayload();
      scenario.mutate(payload);
      return jsonResponse(payload);
    };

    const evaluate = createHostedEvaluate({ clientId: "cid", clientSecret: "sec", fetchImpl });
    const res = await evaluate(makeSampleRequest());
    assert.equal(res.status, "unknown", scenario.name);
    assert.equal(res.code, scenario.expectedCode, scenario.name);
  }
});

test("handles 202 pending, 429 quota, 401 unauthorized, 503 5xx, oversized body, and streamed timeout without retries", async () => {
  const makeClientWithEvalResponse = (evalResponder) => {
    let evalCount = 0;
    const evaluate = createHostedEvaluate({
      clientId: "cid",
      clientSecret: "sec",
      timeoutMs: 40,
      fetchImpl: async (url, init) => {
        if (url === TOKEN_URL) {
          return jsonResponse({
            token_type: "Bearer",
            access_token: "dxbt_valid_123",
            scope: "deltax:evaluate",
            expires_in: 300
          });
        }
        evalCount += 1;
        return evalResponder(init);
      }
    });
    return { evaluate, getEvalCount: () => evalCount };
  };

  {
    const { evaluate, getEvalCount } = makeClientWithEvalResponse(() => new Response("", { status: 202 }));
    const res = await evaluate(makeSampleRequest());
    assert.deepEqual(res, { status: "unknown", code: "PENDING_202" });
    assert.equal(getEvalCount(), 1);
  }

  {
    const { evaluate, getEvalCount } = makeClientWithEvalResponse(() => new Response("", { status: 429 }));
    const res = await evaluate(makeSampleRequest());
    assert.deepEqual(res, { status: "rejected", code: "QUOTA_EXCEEDED" });
    assert.equal(getEvalCount(), 1);
  }

  {
    const { evaluate, getEvalCount } = makeClientWithEvalResponse(() => new Response("", { status: 401 }));
    const res = await evaluate(makeSampleRequest());
    assert.deepEqual(res, { status: "rejected", code: "UNAUTHORIZED" });
    assert.equal(getEvalCount(), 1);
  }

  {
    const { evaluate, getEvalCount } = makeClientWithEvalResponse(() => new Response("", { status: 503 }));
    const res = await evaluate(makeSampleRequest());
    assert.deepEqual(res, { status: "unknown", code: "UPSTREAM_5XX" });
    assert.equal(getEvalCount(), 1);
  }

  {
    const oversized = "x".repeat(65 * 1024);
    const { evaluate } = makeClientWithEvalResponse(() => new Response(oversized, { status: 200 }));
    const res = await evaluate(makeSampleRequest());
    assert.deepEqual(res, { status: "unknown", code: "RESPONSE_TOO_LARGE" });
  }

  {
    const { evaluate } = makeClientWithEvalResponse(() => {
      const stream = new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode("{\"partial\":"));
        }
      });
      return new Response(stream, { status: 200 });
    });
    const res = await evaluate(makeSampleRequest());
    assert.deepEqual(res, { status: "unknown", code: "TIMEOUT" });
  }
});

test("durable ledger enforces private 0600 file, one active, duplicate key rejection, and restart recovery", (t) => {
  const file = makeTempLedgerPath(t);
  let nowMs = 1_700_000_000_000;
  const cutoff = nowMs + 86_400_000 * 10;

  const ledger1 = createLedger({
    file,
    totalLimit: 9999,
    cutoff,
    windowLimit: 99,
    now: () => nowMs
  });

  const mode = fs.statSync(file).mode & 0o777;
  assert.equal(mode, 0o600);

  // Configurable bounds are clamped.
  const initialStatus = ledger1.status();
  assert.equal(initialStatus.totalLimit, 100);
  assert.equal(initialStatus.windowLimit, 20);

  const sessionA = `sess_${crypto.randomBytes(16).toString("hex")}`;
  const sessionB = `sess_${crypto.randomBytes(16).toString("hex")}`;
  const key1 = `idem_${crypto.randomBytes(16).toString("hex")}`;
  const key2 = `idem_${crypto.randomBytes(16).toString("hex")}`;

  // Low-entropy identifiers are rejected.
  assert.equal(ledger1.reserve({ session: "short", idempotencyKey: key1 }).code, "INVALID_IDENTITY_OR_KEY");
  assert.equal(ledger1.reserve({ session: sessionA, idempotencyKey: "aaaaaaaaaaaaaaaa" }).code, "INVALID_IDENTITY_OR_KEY");

  // Sync reservation marks active=true before dispatch.
  const r1 = ledger1.reserve({ session: sessionA, idempotencyKey: key1 });
  assert.equal(r1.ok, true);
  assert.equal(ledger1.status().active, true);

  // Global one-active policy blocks even a different session while key1 is pending.
  const rBlocked = ledger1.reserve({ session: sessionB, idempotencyKey: key2 });
  assert.equal(rBlocked.ok, false);
  assert.equal(rBlocked.code, "ACTIVE_IN_FLIGHT");

  // Simulate process crash before result() is called, then restart on same file.
  const ledger2 = createLedger({
    file,
    totalLimit: 5,
    cutoff,
    windowLimit: 4,
    now: () => nowMs
  });

  const recoveredStatus = ledger2.status();
  assert.equal(recoveredStatus.active, false);
  assert.equal(recoveredStatus.totalUsed, 1);
  assert.equal(recoveredStatus.recoveredUnknownCount, 1);
  assert.equal(recoveredStatus.counts.unknown, 1);
  assert.equal(recoveredStatus.counts.pending, 0);

  // Safe status never exposes raw session or idempotency keys.
  const statusJson = JSON.stringify(recoveredStatus);
  assert.equal(statusJson.includes(sessionA), false);
  assert.equal(statusJson.includes(key1), false);

  // Duplicate key is rejected globally after restart.
  const rDup = ledger2.reserve({ session: sessionB, idempotencyKey: key1 });
  assert.equal(rDup.ok, false);
  assert.equal(rDup.code, "DUPLICATE_IDEMPOTENCY_KEY");

  // Unrelated explicit session can now progress.
  const r2 = ledger2.reserve({ session: sessionB, idempotencyKey: key2 });
  assert.equal(r2.ok, true);
  const rec2 = ledger2.result(key2, "selected");
  assert.equal(rec2.ok, true);
  assert.equal(ledger2.status().active, false);
  assert.equal(ledger2.status().totalUsed, 2);
});

test("ledger enforces per-identity rolling 24h window, total limit, and cutoff", (t) => {
  const file = makeTempLedgerPath(t);
  let nowMs = 1_700_000_000_000;
  const cutoff = nowMs + 48 * 60 * 60 * 1000;

  const ledger = createLedger({
    file,
    totalLimit: 5,
    cutoff,
    windowLimit: 2,
    now: () => nowMs
  });

  const sessionA = `sess_${crypto.randomBytes(16).toString("hex")}`;
  const sessionB = `sess_${crypto.randomBytes(16).toString("hex")}`;

  for (let i = 0; i < 2; i += 1) {
    const k = `key_${crypto.randomBytes(16).toString("hex")}`;
    assert.equal(ledger.reserve({ session: sessionA, idempotencyKey: k }).ok, true);
    assert.equal(ledger.result(k, "selected").ok, true);
  }

  // 3rd attempt in <24h for sessionA is blocked by windowLimit=2.
  const kBlocked = `key_${crypto.randomBytes(16).toString("hex")}`;
  assert.equal(
    ledger.reserve({ session: sessionA, idempotencyKey: kBlocked }).code,
    "SESSION_WINDOW_LIMIT_EXCEEDED"
  );

  // Unrelated sessionB can still progress.
  const kB = `key_${crypto.randomBytes(16).toString("hex")}`;
  assert.equal(ledger.reserve({ session: sessionB, idempotencyKey: kB }).ok, true);
  assert.equal(ledger.result(kB, "refused").ok, true);

  // Advance 24h: sessionA window rolls over and allows another call.
  nowMs += 24 * 60 * 60 * 1000;
  const kA3 = `key_${crypto.randomBytes(16).toString("hex")}`;
  assert.equal(ledger.reserve({ session: sessionA, idempotencyKey: kA3 }).ok, true);
  assert.equal(ledger.result(kA3, "selected").ok, true);

  const kB2 = `key_${crypto.randomBytes(16).toString("hex")}`;
  assert.equal(ledger.reserve({ session: sessionB, idempotencyKey: kB2 }).ok, true);
  assert.equal(ledger.result(kB2, "selected").ok, true);

  // Total limit of 5 is now exhausted.
  const kTotal = `key_${crypto.randomBytes(16).toString("hex")}`;
  assert.equal(
    ledger.reserve({ session: sessionB, idempotencyKey: kTotal }).code,
    "TOTAL_LIMIT_EXCEEDED"
  );

  // Passing cutoff rejects new reservations even if a new ledger with higher limit reads past cutoff.
  nowMs = cutoff;
  const ledgerAfterCutoff = createLedger({
    file,
    totalLimit: 10,
    cutoff,
    windowLimit: 4,
    now: () => nowMs
  });
  const kCutoff = `key_${crypto.randomBytes(16).toString("hex")}`;
  assert.equal(
    ledgerAfterCutoff.reserve({ session: sessionA, idempotencyKey: kCutoff }).code,
    "CUTOFF_EXCEEDED"
  );
  assert.equal(ledgerAfterCutoff.status().cutoffReached, true);
});

test("real adapter wiring consumes two hosted reviews across all five signed supplier snapshots", async (t) => {
  const seen = [];
  const pair = await createRelayPair({
    buyerPort: 0,
    supplierPort: 0,
    hostedAvailable: true,
    hostedBudget: 8,
    hostedWindowLimit: 4,
    cutoff: new Date(Date.now() + 3600_000).toISOString(),
    evaluateClientId: "fixture-client",
    evaluateClientSecret: "fixture-secret",
    evaluateLedgerFile: makeTempLedgerPath(t),
    async evaluateFetchImpl(url, init) {
      if (url === TOKEN_URL) {
        return jsonResponse({ token_type: "Bearer", access_token: "dxbt_fixture_token", scope: "deltax:evaluate", expires_in: 900 });
      }
      assert.equal(url, EVAL_URL);
      assert.equal(init.headers["X-DeltaX-API-Version"], "2026-09-16.beta2");
      const payload = JSON.parse(init.body);
      assert.ok(Object.values(payload.context).every(value => value === null || typeof value !== "object"));
      seen.push(init.headers["Idempotency-Key"]);
      const sample = makeValidEvalPayload({ receipt_id: `eval_test_${seen.length}` });
      sample.result.selected_candidate_id = payload.candidates[0].candidate_id;
      return jsonResponse(sample);
    },
  });
  t.after(() => pair.close());

  const config = await fetch(`${pair.buyerOrigin}/api/config`);
  const cookie = config.headers.getSetCookie()[0].split(";", 1)[0];
  const cases = [
    ["initial", "vendor-a", 1, "new"],
    ["unchanged", "vendor-a", 0, "reused"],
    ["unrelated", "vendor-a", 0, "reused"],
    ["delay", "vendor-b", 1, "replanned"],
    ["unavailable", null, 0, "replanned"],
  ];
  let receipt = null;
  let initialSnapshot;
  async function decide(phase, snapshot, prior) {
    const response = await fetch(`${pair.buyerOrigin}/api/decision`, {
      method: "POST",
      headers: { Origin: pair.buyerOrigin, Cookie: cookie, "Content-Type": "application/json" },
      body: JSON.stringify({ phase, snapshot, receipt: prior, kind: "hosted" }),
    });
    assert.equal(response.status, 200);
    return response.json();
  }
  for (const [phase, vendor, attempted, expectedState] of cases) {
    const rpc = await fetch(`${pair.supplierOrigin}/mcp`, {
      method: "POST",
      headers: { Origin: pair.buyerOrigin, "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: {
        name: "get_quote_snapshot",
        arguments: { request: `Read fictional quote for EQ-CRIT-01 x1 us-west in case ${phase}.` },
      } }),
    });
    assert.equal(rpc.status, 200);
    const snapshot = JSON.parse((await rpc.json()).result.content[0].text);
    if (!initialSnapshot) initialSnapshot = snapshot;
    const decision = await decide(phase, snapshot, receipt);
    assert.equal(decision.state, expectedState);
    assert.equal(decision.selectedQuote?.vendorId ?? null, vendor);
    assert.equal(decision.providerCalls, attempted);
    if (attempted) assert.equal(decision.receipt.payload.providerEvidence.gates.length, 12);
    receipt = decision.receipt;
  }

  const duplicate = await decide("initial", initialSnapshot, null);
  assert.equal(duplicate.providerCalls, 0);
  assert.match(duplicate.reason, /DUPLICATE_IDEMPOTENCY_KEY/);
  assert.equal(new Set(seen).size, 2);
});
