import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createLedger } from '../src/hosted-ledger.js';
import { createRelayPair, parseConfigFromEnv } from '../src/live-server.js';
import { createScenario } from '../src/relay.js';
import { createReviewer } from '../src/review.js';
import { createRouter, OTARI_UPSTREAM_URL } from '../src/router.js';

function getStep(steps, name, index) {
  if (!steps) return { quotes: [] };
  if (!Array.isArray(steps) && steps[name]) return steps[name];
  if (Array.isArray(steps)) {
    return steps.find((s) => s?.phase === name || s?.id === name || s?.name === name) ?? steps[index];
  }
  return { quotes: [] };
}

function clone(val) {
  return JSON.parse(JSON.stringify(val));
}

function makeTempLedger(name, { totalLimit = 10, windowLimit = 10 } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-test-'));
  const file = path.join(dir, `${name}.json`);
  const cutoff = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  return {
    file,
    cutoff,
    ledger: createLedger({ file, totalLimit, cutoff, windowLimit }),
    cleanup() {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  };
}

function makeTestSupplier(scenario) {
  return {
    async handleRpc() {
      return { status: 200, body: {} };
    },
    verify(snapshot, phase) {
      if (snapshot === null || snapshot?.untrusted) return null;
      if (Array.isArray(snapshot?.quotes)) {
        return clone(snapshot.quotes);
      }
      const idxMap = { initial: 0, unchanged: 1, unrelated: 2, delay: 3, unavailable: 4 };
      const step = getStep(scenario.steps, phase, idxMap[phase] ?? 0);
      if (!step || !Array.isArray(step.quotes) || phase === 'unavailable') {
        return phase === 'unavailable' ? null : [];
      }
      return clone(step.quotes);
    }
  };
}

function makeMockEvaluate(handler) {
  const calls = [];
  return {
    calls,
    async evaluate(req) {
      calls.push(req);
      return handler(req, calls.length);
    }
  };
}

const TEST_SIGNING_KEY = crypto.randomBytes(32).toString('hex');

function stableSession(label) {
  return crypto.createHash('sha256').update(label).digest('base64url');
}

test('independent policy lanes: replay vs hosted and lane mismatch refusal', async () => {
  const scenario = createScenario();
  const supplier = makeTestSupplier(scenario);
  const { ledger, cleanup } = makeTempLedger('lanes');
  const mockEval = makeMockEvaluate(({ candidates }) => ({
    status: 'selected',
    code: 'OK',
    receiptId: 'prov-1',
    selectedCandidateId: candidates[0].candidate_id,
    evidence: {
      requestDigest: 'req-d',
      policyDigest: 'pol-d',
      receiptDigest: 'rec-d',
      gates: ['budget', 'policy'],
      evaluatedAt: '2026-01-01T00:00:00.000Z'
    }
  }));

  try {
    const reviewer = createReviewer({
      supplier,
      signingKey: TEST_SIGNING_KEY,
      evaluate: mockEval.evaluate,
      ledger,
      scenario
    });

    const replayRes = await reviewer.decide({
      session: stableSession('sess-1'),
      phase: 'initial',
      snapshot: {},
      receipt: null,
      kind: 'replay'
    });
    assert.equal(replayRes.status, 'selected');
    assert.equal(replayRes.state, 'new');
    assert.equal(replayRes.source, 'local-fixture');
    assert.equal(replayRes.providerCalls, 0);
    assert.ok(replayRes.receipt);

    const crossLane = await reviewer.decide({
      session: stableSession('sess-1'),
      phase: 'initial',
      snapshot: {},
      receipt: replayRes.receipt,
      kind: 'hosted'
    });
    assert.equal(crossLane.status, 'refused');
    assert.equal(crossLane.state, 'stopped');
    assert.equal(crossLane.providerCalls, 0);
    assert.equal(crossLane.receipt, null);
    assert.equal(mockEval.calls.length, 0);

    const hostedRes = await reviewer.decide({
      session: stableSession('sess-1'),
      phase: 'initial',
      snapshot: {},
      receipt: null,
      kind: 'hosted'
    });
    assert.equal(hostedRes.status, 'selected');
    assert.equal(hostedRes.state, 'new');
    assert.equal(hostedRes.source, 'hosted-evaluate');
    assert.equal(hostedRes.providerCalls, 1);
    assert.equal(mockEval.calls.length, 1);

    const reverseLane = await reviewer.decide({
      session: stableSession('sess-1'),
      phase: 'initial',
      snapshot: {},
      receipt: hostedRes.receipt,
      kind: 'replay'
    });
    assert.equal(reverseLane.status, 'refused');
    assert.equal(reverseLane.state, 'stopped');
    assert.equal(reverseLane.providerCalls, 0);
  } finally {
    cleanup();
  }
});

test('HMAC tampering, wrong session, and malformed receipt refuse with zero provider calls', async () => {
  const scenario = createScenario();
  const supplier = makeTestSupplier(scenario);
  const { ledger, cleanup } = makeTempLedger('tamper');
  const mockEval = makeMockEvaluate(({ candidates }) => ({
    status: 'selected',
    code: 'OK',
    receiptId: 'prov-2',
    selectedCandidateId: candidates[0].candidate_id,
    evidence: { requestDigest: 'a', policyDigest: 'b', receiptDigest: 'c', gates: [], evaluatedAt: '2026-01-01T00:00:00Z' }
  }));

  try {
    const reviewer = createReviewer({
      supplier,
      signingKey: TEST_SIGNING_KEY,
      evaluate: mockEval.evaluate,
      ledger,
      scenario
    });

    const first = await reviewer.decide({
      session: stableSession('sess-a'),
      phase: 'initial',
      snapshot: {},
      receipt: null,
      kind: 'hosted'
    });
    assert.equal(first.status, 'selected');
    assert.equal(mockEval.calls.length, 1);

    const tamperedSig = clone(first.receipt);
    tamperedSig.sig = tamperedSig.sig.replace(/^[0-9a-f]/, tamperedSig.sig[0] === '0' ? '1' : '0');
    const resTamperedSig = await reviewer.decide({
      session: stableSession('sess-a'),
      phase: 'unchanged',
      snapshot: {},
      receipt: tamperedSig,
      kind: 'hosted'
    });
    assert.equal(resTamperedSig.status, 'refused');
    assert.equal(resTamperedSig.state, 'stopped');
    assert.equal(resTamperedSig.providerCalls, 0);
    assert.equal(resTamperedSig.receipt, null);

    const tamperedPayload = clone(first.receipt);
    tamperedPayload.payload.selectedVendorId = 'vendor-evil';
    const resTamperedPayload = await reviewer.decide({
      session: stableSession('sess-a'),
      phase: 'unchanged',
      snapshot: {},
      receipt: tamperedPayload,
      kind: 'hosted'
    });
    assert.equal(resTamperedPayload.status, 'refused');
    assert.equal(resTamperedPayload.state, 'stopped');
    assert.equal(resTamperedPayload.providerCalls, 0);

    const wrongSession = await reviewer.decide({
      session: stableSession('sess-b'),
      phase: 'unchanged',
      snapshot: {},
      receipt: first.receipt,
      kind: 'hosted'
    });
    assert.equal(wrongSession.status, 'refused');
    assert.equal(wrongSession.state, 'stopped');
    assert.equal(wrongSession.providerCalls, 0);

    const malformed = await reviewer.decide({
      session: stableSession('sess-a'),
      phase: 'unchanged',
      snapshot: {},
      receipt: { bad: true },
      kind: 'hosted'
    });
    assert.equal(malformed.status, 'refused');
    assert.equal(malformed.state, 'stopped');
    assert.equal(malformed.providerCalls, 0);
    assert.equal(mockEval.calls.length, 1);
  } finally {
    cleanup();
  }
});

test('unchanged and unrelated steps reuse receipt with zero provider calls', async () => {
  const scenario = createScenario();
  const supplier = makeTestSupplier(scenario);
  const { ledger, cleanup } = makeTempLedger('reuse');
  const mockEval = makeMockEvaluate(({ candidates }) => ({
    status: 'selected',
    code: 'OK',
    receiptId: 'prov-reuse',
    selectedCandidateId: candidates[0].candidate_id,
    evidence: { requestDigest: 'a', policyDigest: 'b', receiptDigest: 'c', gates: [], evaluatedAt: '2026-01-01T00:00:00Z' }
  }));

  try {
    const reviewer = createReviewer({
      supplier,
      signingKey: TEST_SIGNING_KEY,
      evaluate: mockEval.evaluate,
      ledger,
      scenario
    });

    const initial = await reviewer.decide({
      session: stableSession('sess-reuse'),
      phase: 'initial',
      snapshot: {},
      receipt: null,
      kind: 'hosted'
    });
    assert.equal(initial.status, 'selected');
    assert.equal(initial.state, 'new');
    assert.equal(initial.providerCalls, 1);

    const unchanged = await reviewer.decide({
      session: stableSession('sess-reuse'),
      phase: 'unchanged',
      snapshot: {},
      receipt: initial.receipt,
      kind: 'hosted'
    });
    assert.equal(unchanged.status, 'selected');
    assert.equal(unchanged.state, 'reused');
    assert.equal(unchanged.source, 'hosted-evaluate');
    assert.equal(unchanged.providerCalls, 0);

    const unrelated = await reviewer.decide({
      session: stableSession('sess-reuse'),
      phase: 'unrelated',
      snapshot: {},
      receipt: unchanged.receipt,
      kind: 'hosted'
    });
    assert.equal(unrelated.status, 'selected');
    assert.equal(unrelated.state, 'reused');
    assert.equal(unrelated.source, 'hosted-evaluate');
    assert.equal(unrelated.providerCalls, 0);
    assert.equal(mockEval.calls.length, 1);
  } finally {
    cleanup();
  }
});

test('late drift and scope changes stop reuse and replan accurately', async () => {
  const scenario = createScenario();
  const supplier = makeTestSupplier(scenario);
  const { ledger, cleanup } = makeTempLedger('replan');
  const mockEval = makeMockEvaluate(({ candidates }) => ({
    status: 'selected',
    code: 'OK',
    receiptId: 'prov-replan',
    selectedCandidateId: candidates[0].candidate_id,
    evidence: { requestDigest: 'a', policyDigest: 'b', receiptDigest: 'c', gates: [], evaluatedAt: '2026-01-01T00:00:00Z' }
  }));

  try {
    const reviewer = createReviewer({
      supplier,
      signingKey: TEST_SIGNING_KEY,
      evaluate: mockEval.evaluate,
      ledger,
      scenario
    });

    const initial = await reviewer.decide({
      session: stableSession('sess-drift'),
      phase: 'initial',
      snapshot: {},
      receipt: null,
      kind: 'hosted'
    });
    assert.equal(initial.status, 'selected');
    assert.equal(initial.providerCalls, 1);

    const delayRes = await reviewer.decide({
      session: stableSession('sess-drift'),
      phase: 'delay',
      snapshot: {},
      receipt: initial.receipt,
      kind: 'hosted'
    });
    assert.equal(delayRes.state, 'replanned');
    assert.ok(['selected', 'abstained'].includes(delayRes.status));
    if (delayRes.status === 'abstained') {
      assert.equal(delayRes.source, 'local-policy');
      assert.equal(delayRes.providerCalls, 0);
    } else {
      assert.equal(delayRes.source, 'hosted-evaluate');
      assert.equal(delayRes.providerCalls, 1);
    }

    // Explicit scope change stops reuse even if quotes did not change.
    const mutatedScenario = clone(scenario);
    mutatedScenario.policy = { ...scenario.policy, scopeTag: 'changed-scope' };
    const scopedReviewer = createReviewer({
      supplier,
      signingKey: TEST_SIGNING_KEY,
      evaluate: mockEval.evaluate,
      ledger,
      scenario: mutatedScenario
    });
    const scopedRes = await scopedReviewer.decide({
      session: stableSession('sess-drift'),
      phase: 'initial',
      snapshot: {},
      receipt: initial.receipt,
      kind: 'hosted'
    });
    assert.notEqual(scopedRes.state, 'reused');
  } finally {
    cleanup();
  }
});

test('no eligible quotes abstain with local-policy and zero provider calls', async () => {
  const scenario = createScenario();
  const baseQuotes = clone(getStep(scenario.steps, 'initial', 0).quotes);
  const ineligibleQuotes = baseQuotes.map((q) => ({
    ...q,
    cost: 999999999,
    days: 9999
  }));
  const supplier = makeTestSupplier(scenario);
  const { ledger, cleanup } = makeTempLedger('abstain');
  const mockEval = makeMockEvaluate(() => {
    throw new Error('Provider should not be called when all quotes are ineligible');
  });

  try {
    const reviewer = createReviewer({
      supplier,
      signingKey: TEST_SIGNING_KEY,
      evaluate: mockEval.evaluate,
      ledger,
      scenario
    });

    const res = await reviewer.decide({
      session: stableSession('sess-abstain'),
      phase: 'initial',
      snapshot: { quotes: ineligibleQuotes },
      receipt: null,
      kind: 'hosted'
    });
    assert.equal(res.status, 'abstained');
    assert.equal(res.source, 'local-policy');
    assert.equal(res.providerCalls, 0);
    assert.equal(res.selectedQuote, null);
    assert.equal(mockEval.calls.length, 0);
  } finally {
    cleanup();
  }
});

test('provider unknown and invalid selection stop without authorization', async () => {
  const scenario = createScenario();
  const supplier = makeTestSupplier(scenario);
  const { ledger, cleanup } = makeTempLedger('unknown-invalid');

  try {
    const unknownEval = makeMockEvaluate(() => ({
      status: 'unknown',
      code: 'TIMEOUT',
      receiptId: 'prov-u',
      selectedCandidateId: null,
      evidence: { requestDigest: 'a', policyDigest: 'b', receiptDigest: 'c', gates: [], evaluatedAt: '2026-01-01T00:00:00Z' }
    }));
    const reviewerUnknown = createReviewer({
      supplier,
      signingKey: TEST_SIGNING_KEY,
      evaluate: unknownEval.evaluate,
      ledger,
      scenario
    });

    const unknownRes = await reviewerUnknown.decide({
      session: stableSession('sess-u'),
      phase: 'initial',
      snapshot: {},
      receipt: null,
      kind: 'hosted'
    });
    assert.equal(unknownRes.status, 'unknown');
    assert.equal(unknownRes.state, 'stopped');
    assert.equal(unknownRes.selectedQuote, null);
    assert.equal(unknownRes.receipt, null);
    assert.equal(unknownRes.providerCalls, 1);

    const invalidSelEval = makeMockEvaluate(() => ({
      status: 'selected',
      code: 'OK',
      receiptId: 'prov-bad-id',
      selectedCandidateId: 'review-rogue-vendor',
      evidence: { requestDigest: 'a', policyDigest: 'b', receiptDigest: 'c', gates: [], evaluatedAt: '2026-01-01T00:00:00Z' }
    }));
    const reviewerInvalid = createReviewer({
      supplier,
      signingKey: TEST_SIGNING_KEY,
      evaluate: invalidSelEval.evaluate,
      ledger,
      scenario
    });

    const invalidRes = await reviewerInvalid.decide({
      session: stableSession('sess-inv'),
      phase: 'initial',
      snapshot: {},
      receipt: null,
      kind: 'hosted'
    });
    assert.equal(invalidRes.status, 'refused');
    assert.equal(invalidRes.state, 'stopped');
    assert.equal(invalidRes.selectedQuote, null);
    assert.equal(invalidRes.receipt, null);
    assert.equal(invalidRes.providerCalls, 1);
  } finally {
    cleanup();
  }
});

test('hosted-no-reuse bypasses reuse and candidates/context remain bounded and secret-free', async () => {
  const scenario = createScenario();
  const supplier = makeTestSupplier(scenario);
  const { ledger, cleanup } = makeTempLedger('no-reuse');
  const mockEval = makeMockEvaluate(({ candidates }) => ({
    status: 'selected',
    code: 'OK',
    receiptId: 'prov-nr',
    selectedCandidateId: candidates[0].candidate_id,
    evidence: { requestDigest: 'a', policyDigest: 'b', receiptDigest: 'c', gates: [], evaluatedAt: '2026-01-01T00:00:00Z' }
  }));

  try {
    const reviewer = createReviewer({
      supplier,
      signingKey: TEST_SIGNING_KEY,
      evaluate: mockEval.evaluate,
      ledger,
      scenario
    });

    const first = await reviewer.decide({
      session: 'secret-session-token',
      phase: 'initial',
      snapshot: {},
      receipt: null,
      kind: 'hosted'
    });
    assert.equal(first.status, 'selected');

    const second = await reviewer.decide({
      session: 'secret-session-token',
      phase: 'unchanged',
      snapshot: {},
      receipt: first.receipt,
      kind: 'hosted-no-reuse'
    });
    assert.equal(second.status, 'selected');
    assert.equal(second.state, 'new');
    assert.equal(second.providerCalls, 1);
    assert.equal(mockEval.calls.length, 2);

    const callArg = mockEval.calls[0];
    assert.ok(callArg.candidates.length >= 1 && callArg.candidates.length <= 2);
    assert.match(callArg.candidates[0].candidate_id, /^review-/);
    assert.equal(typeof callArg.candidates[0].operator_reported_support, 'number');
    const serializedCall = JSON.stringify(callArg);
    assert.equal(serializedCall.includes('secret-session-token'), false);
    assert.equal(serializedCall.includes(TEST_SIGNING_KEY), false);

    const unavailable = await reviewer.decide({
      session: 'secret-session-token',
      phase: 'unavailable',
      snapshot: { untrusted: true },
      receipt: null,
      kind: 'hosted'
    });
    assert.equal(unavailable.status, 'unavailable');
    assert.equal(unavailable.state, 'stopped');
    assert.equal(unavailable.providerCalls, 0);
  } finally {
    cleanup();
  }
});

test('router enforces model, max_tokens <= 800, Authorization stripping, SSE cap, and disabled fixture error', async () => {
  const { ledger, cleanup } = makeTempLedger('router', { totalLimit: 1, windowLimit: 1 });
  const buyerOrigin = 'http://127.0.0.1:4190';

  try {
    const disabledRouter = createRouter({ apiKey: '', model: '', buyerOrigin });
    assert.equal(disabledRouter.mode, 'fixture');

    const srvDisabled = await startHttpTestServer((req, res) => disabledRouter.handleRequest(req, res));
    try {
      const r = await fetch(`${srvDisabled.origin}/api/router/v1/chat/completions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: buyerOrigin },
        body: JSON.stringify({ model: 'x', messages: [{ role: 'user', content: 'hi' }] })
      });
      assert.equal(r.status, 503);
      const body = await r.json();
      assert.equal(body.error.code, 'ROUTER_DISABLED_FIXTURE_MODE');
    } finally {
      await srvDisabled.close();
    }

    const upstreamSeen = [];
    const mockFetch = async (url, init) => {
      upstreamSeen.push({ url, init });
      const stream = new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('data: {"ok":true}\n\n'));
          controller.close();
        }
      });
      return new Response(stream, {
        status: 200,
        headers: { 'Content-Type': 'text/event-stream' }
      });
    };

    const enabledRouter = createRouter({
      apiKey: 'server-otari-secret',
      model: 'otari-small',
      buyerOrigin,
      ledger,
      fetchImpl: mockFetch
    });
    assert.equal(enabledRouter.mode, 'provider');

    const srv = await startHttpTestServer((req, res) => enabledRouter.handleRequest(req, res, { session: stableSession('s1') }));
    try {
      const badOrigin = await fetch(`${srv.origin}/api/router/v1/chat/completions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example' },
        body: JSON.stringify({ model: 'otari-small', messages: [{ role: 'user', content: 'hi' }] })
      });
      assert.equal(badOrigin.status, 403);

      const badTokens = await fetch(`${srv.origin}/api/router/v1/chat/completions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: buyerOrigin },
        body: JSON.stringify({ model: 'otari-small', max_tokens: 801, messages: [{ role: 'user', content: 'hi' }] })
      });
      assert.equal(badTokens.status, 400);

      const okRes = await fetch(`${srv.origin}/api/router/v1/chat/completions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Origin: buyerOrigin,
          Authorization: 'Bearer attacker-token'
        },
        body: JSON.stringify({
          model: 'otari-small',
          max_tokens: 400,
          stream: true,
          messages: [{ role: 'user', content: 'Summarize quotes.' }]
        })
      });
      assert.equal(okRes.status, 200);
      const sseText = await okRes.text();
      assert.match(sseText, /"ok":true/);
      assert.equal(upstreamSeen.length, 1);
      assert.equal(upstreamSeen[0].url, OTARI_UPSTREAM_URL);
      assert.equal(upstreamSeen[0].init.headers.Authorization, 'Bearer server-otari-secret');

      const budgetExceeded = await fetch(`${srv.origin}/api/router/v1/chat/completions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: buyerOrigin },
        body: JSON.stringify({ model: 'otari-small', max_tokens: 100, messages: [{ role: 'user', content: 'again' }] })
      });
      assert.equal(budgetExceeded.status, 429);
    } finally {
      await srv.close();
    }
  } finally {
    cleanup();
  }
});

test('live-server enforces config, cookies, origin, host, path traversal, and supplier CORS', async () => {
  assert.throws(() =>
    parseConfigFromEnv({
      RELAY_HOSTED_MODE: '1',
      RELAY_EVALUATE_CLIENT_ID: 'id',
      RELAY_EVALUATE_CLIENT_SECRET: 'secret'
    })
  );

  const disabledCfg = parseConfigFromEnv({ RELAY_HOSTED_MODE: '1' });
  assert.equal(disabledCfg.hostedAvailable, false);

  const pair = await createRelayPair({
    buyerPort: 0,
    supplierPort: 0,
    buyerOrigin: 'http://127.0.0.1:0',
    supplierOrigin: 'http://127.0.0.1:0',
    hostedAvailable: false,
    evidenceKey: crypto.randomBytes(32).toString('hex'),
    receiptKey: crypto.randomBytes(32).toString('hex')
  });

  try {
    const cfgRes = await fetch(`${pair.buyerOrigin}/api/config`);
    assert.equal(cfgRes.status, 200);
    const setCookie = cfgRes.headers.get('set-cookie') || '';
    assert.match(setCookie, /relay_session=/);
    assert.match(setCookie, /HttpOnly/);
    assert.match(setCookie, /SameSite=Strict/);
    assert.equal(/Secure/i.test(setCookie), false);

    const cfg = await cfgRes.json();
    assert.equal(cfg.relayRouterTag, 'relay-publisher-session');
    assert.equal(cfg.routerMode, 'fixture');
    assert.equal(cfg.hostedAvailable, false);

    const cookiePair = setCookie.split(';')[0];

    const noCookie = await fetch(`${pair.buyerOrigin}/api/decision`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: pair.buyerOrigin },
      body: JSON.stringify({ phase: 'initial', snapshot: {}, receipt: null, kind: 'replay' })
    });
    assert.equal(noCookie.status, 403);

    const badOrigin = await fetch(`${pair.buyerOrigin}/api/decision`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example', Cookie: cookiePair },
      body: JSON.stringify({ phase: 'initial', snapshot: {}, receipt: null, kind: 'replay' })
    });
    assert.equal(badOrigin.status, 403);

    const hostedDisabled = await fetch(`${pair.buyerOrigin}/api/decision`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: pair.buyerOrigin, Cookie: cookiePair },
      body: JSON.stringify({ phase: 'initial', snapshot: {}, receipt: null, kind: 'hosted' })
    });
    assert.equal(hostedDisabled.status, 403);

    const traversal = await fetch(`${pair.buyerOrigin}/.git/config`);
    assert.equal(traversal.status, 403);

    const mcpOptions = await fetch(`${pair.supplierOrigin}/mcp`, {
      method: 'OPTIONS',
      headers: { Origin: pair.buyerOrigin }
    });
    assert.equal(mcpOptions.status, 204);
    assert.equal(mcpOptions.headers.get('access-control-allow-origin'), pair.buyerOrigin);
    assert.equal(mcpOptions.headers.get('access-control-allow-headers'), 'MCP-Protocol-Version, Content-Type');

    const mcpWrongOrigin = await fetch(`${pair.supplierOrigin}/mcp`, {
      method: 'OPTIONS',
      headers: { Origin: 'https://evil.example' }
    });
    assert.equal(mcpWrongOrigin.status, 403);
  } finally {
    await pair.close();
  }
});

function startHttpTestServer(handler) {
  const httpMod = import('node:http');
  return httpMod.then(({ default: http }) => {
    const server = http.createServer(handler);
    return new Promise((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const { port } = server.address();
        resolve({
          origin: `http://127.0.0.1:${port}`,
          close: () => new Promise((r) => server.close(r))
        });
      });
    });
  });
}
