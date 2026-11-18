#!/usr/bin/env node
const PHASES = ['initial', 'unchanged', 'unrelated', 'delay', 'unavailable'];
const EXPECTED = ['vendor-a', 'vendor-a', 'vendor-a', 'vendor-b', null];
const BAD_STATUS = new Set(['refused', 'unknown', 'unavailable']);
const CASE_REQUEST = 'Read fictional quote for EQ-CRIT-01 x1 us-west in case ';

function parseLoopbackOrigin(raw) {
  let u;
  try { u = new URL(raw); } catch { throw 'ERR_INVALID_ORIGIN'; }
  if (u.protocol !== 'http:' || (u.hostname !== 'localhost' && u.hostname !== '127.0.0.1')) {
    throw 'ERR_INVALID_ORIGIN';
  }
  if (u.username || u.password || u.search || u.hash || u.pathname !== '/' || u.origin !== raw) {
    throw 'ERR_INVALID_ORIGIN';
  }
  return u.origin;
}

function publicProof(receipt) {
  if (!receipt || typeof receipt !== 'object') return null;
  const pe = receipt.payload?.providerEvidence ?? null;
  const rawGates = pe ? (Array.isArray(pe.gateIds) ? pe.gateIds : Array.isArray(pe.gates) ? pe.gates : pe.gateId ? [pe.gateId] : []) : [];
  const gateIds = rawGates.map((g) => (typeof g === 'string' ? g : g?.id ?? g?.gateId ?? g?.gate_id ?? null)).filter((g) => typeof g === 'string' && g.length > 0);
  return {
    payload: receipt.payload && typeof receipt.payload === 'object' ? { dependencyDigest: receipt.payload.dependencyDigest ?? null } : null,
    providerEvidence: pe ? {
      receiptId: pe.receiptId ?? null,
      providerReceiptId: pe.providerReceiptId ?? null,
      requestDigest: pe.requestDigest ?? null,
      receiptDigest: pe.receiptDigest ?? null,
      policyDigest: pe.policyDigest ?? null,
      evaluatedAt: pe.evaluatedAt ?? null,
      gateIds,
    } : null,
  };
}

async function run() {
  const args = process.argv.slice(2);
  let lanes;
  if (args.length === 0) lanes = ['replay'];
  else if (args.length === 1 && args[0] === '--hosted') lanes = ['replay', 'hosted', 'hosted-no-reuse'];
  else throw 'ERR_INVALID_ARGS';

  const buyerOrigin = parseLoopbackOrigin(process.env.BUYER_ORIGIN ?? 'http://127.0.0.1:19170');
  const supplierOrigin = parseLoopbackOrigin(process.env.SUPPLIER_ORIGIN ?? 'http://localhost:19171');
  const rows = [];
  let rpcId = 0;
  let hostedEvaluateAttempts = 0;

  for (const lane of lanes) {
    const cfgRes = await fetch(`${buyerOrigin}/api/config`, {
      headers: { Origin: buyerOrigin, Accept: 'application/json' },
      redirect: 'error',
      signal: AbortSignal.timeout(30000),
    }).catch(() => { throw 'ERR_CONFIG_FETCH'; });
    if (!cfgRes.ok) throw 'ERR_CONFIG_HTTP';
    const cookie = (cfgRes.headers.getSetCookie()[0] ?? '').split(';', 1)[0].trim();
    if (!cookie.startsWith('relay_session=') || cookie.length <= 14) throw 'ERR_BAD_SESSION';
    const cfg = await cfgRes.json().catch(() => { throw 'ERR_CONFIG_INVALID'; });
    const advBuyer = cfg?.buyerOrigin ?? cfg?.origins?.buyer;
    const advSupplier = cfg?.supplierOrigin ?? cfg?.origins?.supplier;
    if (advBuyer !== buyerOrigin || advSupplier !== supplierOrigin) throw 'ERR_CONFIG_ORIGIN_MISMATCH';
    if (lane !== 'replay' && cfg?.hostedAvailable !== true) throw 'ERR_HOSTED_UNAVAILABLE';

    let priorReceipt = null;
    for (let i = 0; i < PHASES.length; i++) {
      const phase = PHASES[i];
      const expectedChoice = EXPECTED[i];
      const id = ++rpcId;
      const mcpRes = await fetch(`${supplierOrigin}/mcp`, {
        method: 'POST',
        headers: { Origin: buyerOrigin, 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'get_quote_snapshot', arguments: { request: `${CASE_REQUEST}${phase}.` } } }),
        redirect: 'error',
        signal: AbortSignal.timeout(30000),
      }).catch(() => { throw 'ERR_MCP_FETCH'; });
      if (!mcpRes.ok) throw 'ERR_MCP_HTTP';
      const rpc = await mcpRes.json().catch(() => { throw 'ERR_MCP_INVALID'; });
      if (!rpc || rpc.id !== id || rpc.error || rpc.result?.isError) throw 'ERR_MCP_INVALID';
      let snapshot;
      try { snapshot = JSON.parse(rpc.result?.content?.[0]?.text); } catch { throw 'ERR_MCP_INVALID'; }
      if (!snapshot || typeof snapshot !== 'object' || snapshot.phase !== phase) throw 'ERR_MCP_PHASE_MISMATCH';

      const kind = lane;
      const sentReceipt = lane === 'hosted-no-reuse' ? null : priorReceipt;
      const t0 = performance.now();
      const decRes = await fetch(`${buyerOrigin}/api/decision`, {
        method: 'POST',
        headers: { Origin: buyerOrigin, Cookie: cookie, 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ phase, snapshot, receipt: sentReceipt, kind }),
        redirect: 'error',
        signal: AbortSignal.timeout(30000),
      }).catch(() => { throw 'ERR_DECISION_FETCH'; });
      if (!decRes.ok) throw 'ERR_DECISION_HTTP';
      const dec = await decRes.json().catch(() => { throw 'ERR_DECISION_INVALID'; });
      const elapsedMs = Number((performance.now() - t0).toFixed(2));
      if (!dec || typeof dec !== 'object' || typeof dec.status !== 'string') {
        throw 'ERR_DECISION_STATUS';
      }
      if (BAD_STATUS.has(dec.status)) {
        process.stderr.write(JSON.stringify({ lane, phase, status: dec.status,
          reason: typeof dec.reason === 'string' ? dec.reason.slice(0,200) : null }) + '\n');
        throw 'ERR_DECISION_STOPPED';
      }
      const providerCalls = Number.isInteger(dec.providerCalls) && dec.providerCalls >= 0 ? dec.providerCalls : 0;
      if (lane !== 'replay') {
        hostedEvaluateAttempts += providerCalls;
        if (hostedEvaluateAttempts > 6) throw 'ERR_HOSTED_BUDGET_EXCEEDED';
      }
      if (lane !== 'hosted-no-reuse') priorReceipt = dec.receipt ?? null;
      const chosenVendorId = dec.selectedQuote?.vendorId ?? null;
      const baselineVendorId = dec.baseline?.selectedVendorId ?? null;
      const source = typeof dec.source === 'string' ? dec.source : 'unknown';
      const label = lane === 'replay' ? 'fixture' : (providerCalls > 0 ? 'measured' : dec.state === 'reused' ? 'reused' : 'local-policy');
      const proof = publicProof(dec.receipt);
      const selectedByGate = chosenVendorId !== null && (proof?.providerEvidence?.gateIds?.length ?? 0) > 0;
      rows.push({
        lane,
        phase,
        expectedChoice,
        chosenVendorId,
        baselineVendorId,
        matchesGolden: chosenVendorId === expectedChoice,
        status: dec.status,
        source,
        label,
        reason: typeof dec.reason === 'string' ? dec.reason.slice(0, 200) : null,
        elapsedMs,
        providerCalls: typeof dec.providerCalls === 'number' ? dec.providerCalls : null,
        selectedByGate,
        receipt: proof,
      });
    }
  }

  const totals = {
    stages: rows.length,
    goldenMatches: rows.filter((r) => r.matchesGolden).length,
    eligibleStages: rows.filter((r) => r.expectedChoice !== null).length,
    eligibleGoldenMatches: rows.filter((r) => r.expectedChoice !== null && r.matchesGolden).length,
    lanes: Object.fromEntries(lanes.map(lane => {
      const stages = rows.filter(row => row.lane === lane);
      return [lane, { attempts: stages.reduce((sum,row) => sum + row.providerCalls, 0),
        alignedWithBaseline: stages.filter(row => row.chosenVendorId === row.baselineVendorId).length,
        elapsedMs: Number(stages.reduce((sum,row) => sum + row.elapsedMs, 0).toFixed(2)),
        abstentions: stages.filter(row => row.status === 'abstained').length }];
    })),
    fixtureStages: rows.filter((r) => r.label === 'fixture').length,
    fixtureMatches: rows.filter((r) => r.label === 'fixture' && r.matchesGolden).length,
    measuredStages: rows.filter((r) => r.label === 'measured').length,
    reusedStages: rows.filter((r) => r.label === 'reused').length,
    selectedByGateCount: rows.filter((r) => r.selectedByGate).length,
    providerCalls: rows.reduce((sum, r) => sum + (r.providerCalls ?? 0), 0),
    hostedEvaluateAttempts,
  };
  process.stdout.write(JSON.stringify({ case: 'EQ-CRIT-01 x1 us-west', goldenExpectedChoices: EXPECTED, rows, totals }, null, 2) + '\n');
}

try {
  await run();
} catch (err) {
  const code = typeof err === 'string' && err.startsWith('ERR_') ? err : 'ERR_RUNTIME';
  process.stderr.write(code + '\n');
  process.exitCode = 1;
}
