import { createHmac, timingSafeEqual } from "node:crypto";
import { createScenario, canonicalize, sha256Hex } from "./relay.js";

const PHASES = Object.freeze([
  "initial",
  "unchanged",
  "unrelated",
  "delay",
  "unavailable",
]);

const REQUEST_TO_PHASE = new Map(
  PHASES.map((phase, index) => [
    `Read fictional quote for EQ-CRIT-01 x1 us-west in case ${phase}.`,
    { phase, index },
  ])
);

const PHASE_TO_INDEX = new Map(PHASES.map((phase, index) => [phase, index]));
const HMAC_DOMAIN = "decision-relay:supplier-quote-snapshot:v1";

function parseEvidenceKey(evidenceKey) {
  if (Buffer.isBuffer(evidenceKey)) {
    if (evidenceKey.byteLength === 32) {
      return Buffer.from(evidenceKey);
    }
    throw new Error("evidenceKey Buffer must be exactly 32 bytes.");
  }
  if (ArrayBuffer.isView(evidenceKey)) {
    const buf = Buffer.from(evidenceKey.buffer, evidenceKey.byteOffset, evidenceKey.byteLength);
    if (buf.byteLength === 32) {
      return buf;
    }
    throw new Error("evidenceKey view must be exactly 32 bytes.");
  }
  if (typeof evidenceKey === "string") {
    if (/^[0-9a-fA-F]{64}$/.test(evidenceKey)) {
      return Buffer.from(evidenceKey, "hex");
    }
    const utf8 = Buffer.from(evidenceKey, "utf8");
    if (utf8.byteLength === 32) {
      return utf8;
    }
    const b64 = Buffer.from(evidenceKey, "base64");
    if (b64.byteLength === 32 && b64.toString("base64") === evidenceKey) {
      return b64;
    }
  }
  throw new Error("evidenceKey must be a 32-byte key.");
}

function normalizeOrigin(origin, label) {
  if (origin === undefined) {
    return null;
  }
  const parsed = new URL(origin);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`${label} must use http or https.`);
  }
  return parsed.origin;
}

function normalizeQuotes(rawQuotes) {
  if (!Array.isArray(rawQuotes)) {
    return null;
  }
  const quotes = [];
  for (const item of rawQuotes) {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      return null;
    }
    const keys = Object.keys(item);
    if (
      keys.length !== 6 ||
      !Object.hasOwn(item, "vendorId") ||
      !Object.hasOwn(item, "name") ||
      !Object.hasOwn(item, "sku") ||
      !Object.hasOwn(item, "cost") ||
      !Object.hasOwn(item, "days") ||
      !Object.hasOwn(item, "revision")
    ) {
      return null;
    }
    const { vendorId, name, sku, cost, days, revision } = item;
    if (
      typeof vendorId !== "string" ||
      !vendorId ||
      typeof name !== "string" ||
      !name ||
      typeof sku !== "string" ||
      !sku ||
      typeof cost !== "number" ||
      !Number.isFinite(cost) ||
      typeof days !== "number" ||
      !Number.isFinite(days) ||
      typeof revision !== "number" ||
      !Number.isFinite(revision)
    ) {
      return null;
    }
    quotes.push({ vendorId, name, sku, cost, days, revision });
  }
  return quotes;
}

function extractScenarioQuotes(index) {
  const scenario = createScenario();
  const step = scenario?.steps?.[index];
  const rawQuotes = Array.isArray(step?.quotes) ? step.quotes : Array.isArray(step) ? step : null;
  if (!rawQuotes) {
    throw new Error(`Missing scenario step quotes at index ${index}.`);
  }
  const normalized = normalizeQuotes(
    rawQuotes.map((q) => ({
      vendorId: q.vendorId,
      name: q.name,
      sku: q.sku,
      cost: q.cost,
      days: q.days,
      revision: q.revision,
    }))
  );
  if (!normalized) {
    throw new Error(`Invalid scenario quotes at index ${index}.`);
  }
  return normalized;
}

function jsonRpcResult(id, result) {
  return { jsonrpc: "2.0", id, result };
}

function jsonRpcError(id, code, message) {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

export function createSupplier({ evidenceKey, buyerOrigin, supplierOrigin }) {
  const keyBuf = parseEvidenceKey(evidenceKey);
  normalizeOrigin(buyerOrigin, "buyerOrigin");
  normalizeOrigin(supplierOrigin, "supplierOrigin");

  function signPayload(phase, quotes) {
    const digest = sha256Hex(canonicalize({ phase, quotes }));
    return createHmac("sha256", keyBuf)
      .update(`${HMAC_DOMAIN}:${digest}`)
      .digest("hex");
  }

  function buildSnapshot(phase, index) {
    const quotes = extractScenarioQuotes(index);
    const signature = signPayload(phase, quotes);
    return { phase, quotes, signature };
  }

  function handleRpc(rawBody) {
    let body = rawBody;
    if (typeof rawBody === "string") {
      try {
        body = JSON.parse(rawBody);
      } catch {
        return { status: 400, body: jsonRpcError(null, -32700, "Parse error") };
      }
    }

    if (!body || typeof body !== "object" || Array.isArray(body) || body.jsonrpc !== "2.0" || typeof body.method !== "string") {
      return { status: 400, body: jsonRpcError(body?.id ?? null, -32600, "Invalid Request") };
    }

    const id = body.id ?? null;

    if (body.method === "initialize") {
      return {
        status: 200,
        body: jsonRpcResult(id, {
          protocolVersion: "2025-06-18",
          capabilities: { tools: {} },
          serverInfo: { name: "decision-relay-supplier", version: "1.0.0" },
        }),
      };
    }

    if (body.method === "notifications/initialized") {
      if (body.id === undefined) {
        return { status: 202, body: null };
      }
      return { status: 200, body: jsonRpcResult(id, {}) };
    }

    if (body.method === "tools/list") {
      return {
        status: 200,
        body: jsonRpcResult(id, {
          tools: [
            {
              name: "get_quote_snapshot",
              description: "Read fictional supplier quote snapshot for an exact Decision Relay request.",
              inputSchema: {
                type: "object",
                properties: {
                  request: { type: "string" },
                },
                required: ["request"],
                additionalProperties: false,
              },
            },
          ],
        }),
      };
    }

    if (body.method === "tools/call") {
      const params = body.params;
      if (!params || typeof params !== "object" || Array.isArray(params)) {
        return { status: 200, body: jsonRpcError(id, -32602, "Invalid params") };
      }
      if (params.name !== "get_quote_snapshot") {
        return { status: 200, body: jsonRpcError(id, -32602, "Unknown tool") };
      }
      const args = params.arguments;
      if (
        !args ||
        typeof args !== "object" ||
        Array.isArray(args) ||
        Object.keys(args).length !== 1 ||
        !Object.hasOwn(args, "request") ||
        typeof args.request !== "string"
      ) {
        return { status: 200, body: jsonRpcError(id, -32602, "Tool arguments must contain only request string") };
      }
      const matched = REQUEST_TO_PHASE.get(args.request);
      if (!matched) {
        return { status: 200, body: jsonRpcError(id, -32602, "Request does not match allowed supplier grammar") };
      }
      const snapshot = buildSnapshot(matched.phase, matched.index);
      return {
        status: 200,
        body: jsonRpcResult(id, {
          content: [{ type: "text", text: JSON.stringify(snapshot) }],
          isError: false,
        }),
      };
    }

    return { status: 200, body: jsonRpcError(id, -32601, "Method not found") };
  }

  function verify(snapshot, phase) {
    if (!PHASE_TO_INDEX.has(phase)) {
      return null;
    }
    if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) {
      return null;
    }
    const keys = Object.keys(snapshot);
    if (
      keys.length !== 3 ||
      !Object.hasOwn(snapshot, "phase") ||
      !Object.hasOwn(snapshot, "quotes") ||
      !Object.hasOwn(snapshot, "signature")
    ) {
      return null;
    }
    if (snapshot.phase !== phase) {
      return null;
    }
    if (typeof snapshot.signature !== "string" || !/^[0-9a-f]{64}$/i.test(snapshot.signature)) {
      return null;
    }

    const quotes = normalizeQuotes(snapshot.quotes);
    if (!quotes) {
      return null;
    }

    const index = PHASE_TO_INDEX.get(phase);
    const expectedQuotes = extractScenarioQuotes(index);
    if (sha256Hex(quotes) !== sha256Hex(expectedQuotes)) {
      return null;
    }

    const expectedSig = signPayload(phase, expectedQuotes);
    const actualBuf = Buffer.from(snapshot.signature.toLowerCase(), "hex");
    const expectedBuf = Buffer.from(expectedSig, "hex");
    if (actualBuf.length !== expectedBuf.length || !timingSafeEqual(actualBuf, expectedBuf)) {
      return null;
    }

    return expectedQuotes;
  }

  return { handleRpc, verify };
}
