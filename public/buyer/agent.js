import { Engine } from "./runtime/engine.js";
import { TraceBus } from "./runtime/trace.js";
import { setWorkflowPhase } from "./site-actions.js";

const VALID_PHASES = Object.freeze([
  "initial",
  "unchanged",
  "unrelated",
  "delay",
  "unavailable",
]);

const PHASE_SET = new Set(VALID_PHASES);
const TERMINAL_OK_STATUSES = new Set(["ok", "success", "succeeded", "completed"]);
const TERMINAL_ERR_STATUSES = new Set([
  "error",
  "failed",
  "declined",
  "denied",
  "cancelled",
]);
const END_PHASES = new Set(["end", "finish", "finished", "complete", "completed"]);
const RELEVANT_STATUSES = new Set([
  "start",
  "started",
  "running",
  "pending",
  "ok",
  "success",
  "succeeded",
  "completed",
  "finish",
  "finished",
  "end",
  "error",
  "failed",
  "declined",
  "denied",
  "cancelled",
]);

class RelayError extends Error {
  constructor(message) {
    super(message);
    this.name = "RelayError";
  }
}

function normalizeOrigin(value, label) {
  if (typeof value !== "string" || !value) {
    throw new RelayError(`Invalid ${label} configuration.`);
  }
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new Error("Unsupported protocol");
    }
    return parsed.origin;
  } catch {
    throw new RelayError(`Invalid ${label} configuration.`);
  }
}

function buildPromptForPhase(phase) {
  return `Read fictional quote for EQ-CRIT-01 x1 us-west in case ${phase}.`;
}

function validateCapturedSnapshot(raw, expectedPhase) {
  let parsed;
  try {
    parsed = typeof raw === "string" ? JSON.parse(raw) : null;
  } catch {
    return { ok: false, error: new RelayError("Supplier returned malformed JSON snapshot.") };
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, error: new RelayError("Supplier snapshot must be an object.") };
  }
  if (parsed.phase !== expectedPhase) {
    return { ok: false, error: new RelayError("Supplier snapshot phase mismatch.") };
  }
  if (!Array.isArray(parsed.quotes)) {
    return { ok: false, error: new RelayError("Supplier snapshot quotes missing.") };
  }
  if (typeof parsed.signature !== "string" || parsed.signature.length === 0) {
    return { ok: false, error: new RelayError("Supplier snapshot signature missing.") };
  }

  const quotes = [];
  for (const item of parsed.quotes) {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      return { ok: false, error: new RelayError("Supplier quote entry has invalid shape.") };
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
      return { ok: false, error: new RelayError("Supplier quote fields failed type validation.") };
    }
    quotes.push({ vendorId, name, sku, cost, days, revision });
  }

  return {
    ok: true,
    snapshot: {
      phase: parsed.phase,
      quotes,
      signature: parsed.signature,
    },
  };
}

function extractModelText(result) {
  if (typeof result === "string") {
    return result;
  }
  if (!result || typeof result !== "object") {
    return "";
  }
  if (typeof result.text === "string") {
    return result.text;
  }
  if (typeof result.response === "string") {
    return result.response;
  }
  if (typeof result.output === "string") {
    return result.output;
  }
  if (typeof result.content === "string") {
    return result.content;
  }
  if (typeof result.message?.content === "string") {
    return result.message.content;
  }
  return "";
}

function sanitizeAdvisorySummary(rawText) {
  const cleaned = String(rawText ?? "")
    .replace(/<[^>]*>/g, " ")
    .replace(/[\u0000-\u001F\u007F]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 800);
  return cleaned
    ? `Advisory model summary: ${cleaned}`
    : "Advisory model summary: unavailable.";
}

export function createRelayAgent({
  emit,
  askConsent,
  config,
  submitReceipt,
  fetchImpl = fetch,
}) {
  if (!config || typeof config !== "object") {
    throw new RelayError("Missing relay configuration.");
  }
  if (typeof askConsent !== "function") {
    throw new RelayError("askConsent callback is required.");
  }
  if (typeof submitReceipt !== "function") {
    throw new RelayError("submitReceipt callback is required.");
  }
  if (typeof fetchImpl !== "function") {
    throw new RelayError("fetchImpl must be a function.");
  }

  const supplierOrigin = normalizeOrigin(config.supplierOrigin, "supplierOrigin");
  const supplierHost = new URL(supplierOrigin).host;
  const routerMode = config.routerMode;
  if (routerMode !== "fixture" && routerMode !== "provider") {
    throw new RelayError("Invalid routerMode configuration.");
  }
  if (routerMode === "provider" && (typeof config.relayRouterTag !== "string" || !config.relayRouterTag)) {
    throw new RelayError("Missing relayRouterTag for provider mode.");
  }

  const originUrl =
    typeof globalThis.location?.origin === "string" && globalThis.location.origin !== "null"
      ? globalThis.location.origin
      : normalizeOrigin(config.buyerOrigin, "buyerOrigin");

  const trace = new TraceBus();
  const engineOptions = {
    originUrl,
    trace,
    ...(routerMode === "provider"
      ? { byokKey: config.relayRouterTag, routerOverride: `${originUrl}/api/router/v1` }
      : { routerOverride: "browser://mock" }),
  };
  const engine = new Engine(engineOptions);

  const alwaysAllowedOrigins = new Set();
  const wrappedClients = new WeakSet();
  let topLoaded = false;
  let activeTurn = null;

  engine.onConsent = async ({ kind, peerOrigin, peerLabel, requestText, phase }) => {
    if (peerOrigin !== supplierHost) {
      if (activeTurn) {
        activeTurn.declined = true;
      }
      return "decline";
    }
    if (alwaysAllowedOrigins.has(peerOrigin)) {
      return "always";
    }
    const decision = await askConsent({
      kind,
      peerOrigin: supplierOrigin,
      peerLabel,
      requestText: activeTurn?.requestText ?? requestText,
      phase: activeTurn?.phase ?? phase,
    });
    emit?.({ kind: "consent", status: decision === "decline" ? "declined" : "approved", peerOrigin: supplierOrigin });
    if (decision === "always") {
      alwaysAllowedOrigins.add(peerOrigin);
      return "always";
    }
    if (decision === "allow") {
      return "allow";
    }
    if (activeTurn) {
      activeTurn.declined = true;
    }
    return "decline";
  };

  if (typeof engine.resolveMcp === "function") {
    const origResolveMcp = engine.resolveMcp;
    engine.resolveMcp = async function resolveMcp(ref, parentSpan, slyData, sourceManifest) {
      const client = await origResolveMcp.call(this, ref, parentSpan, slyData, sourceManifest);
      let isSupplierMcp = false;
      try {
        if (ref && typeof ref.url === "string") {
          const parsed = new URL(ref.url);
          isSupplierMcp = parsed.origin === supplierOrigin && parsed.pathname === "/mcp";
        }
      } catch {
        isSupplierMcp = false;
      }

      if (!isSupplierMcp || !client || typeof client.callTool !== "function" || wrappedClients.has(client)) {
        return client;
      }

      const origCallTool = client.callTool;
      client.callTool = async function callTool(name, args, span) {
        if (!activeTurn || name !== "get_quote_snapshot" ||
            args?.request !== activeTurn.requestText || Object.keys(args).length !== 1) {
          throw new RelayError("Supplier request was outside the scoped fixture.");
        }
        const rawResult = await origCallTool.call(this, name, args, span);
        if (activeTurn && !activeTurn.captureError) {
          if (activeTurn.capturedSnapshot !== null) {
            activeTurn.captureError = new RelayError("Duplicate supplier tool invocation detected.");
          } else {
            const validated = validateCapturedSnapshot(rawResult, activeTurn.phase);
            if (!validated.ok) {
              activeTurn.captureError = validated.error;
            } else {
              activeTurn.capturedSnapshot = validated.snapshot;
              emit?.({ kind: "grounded_snapshot", status: "received", peerOrigin: supplierOrigin });
            }
          }
        }
        return rawResult;
      };
      wrappedClients.add(client);
      return client;
    };
  }

  trace.addEventListener("event", (event) => {
    if (!activeTurn || !event?.detail || typeof event.detail !== "object") {
      return;
    }
    const d = event.detail;
    const status = typeof d.status === "string" ? d.status : null;
    const spanPhase = typeof d.phase === "string" ? d.phase : null;
    const kind = typeof d.kind === "string" ? d.kind : null;
    const agent = typeof d.agent === "string" ? d.agent : null;
    const network = typeof d.network === "string" ? d.network : null;
    const method = typeof d.method === "string" ? d.method : null;
    const peerOrigin = d.peerOrigin === supplierHost ? supplierOrigin : null;

    if (kind === "remote_call" && d.peerOrigin === supplierHost) {
      if (TERMINAL_ERR_STATUSES.has(status)) {
        activeTurn.remoteCallFailed = true;
      } else if (TERMINAL_OK_STATUSES.has(status) || END_PHASES.has(spanPhase)) {
        activeTurn.remoteCallSucceeded = true;
      }
    }

    if (agent === "fulfillment_agent") {
      if (TERMINAL_ERR_STATUSES.has(status)) {
        activeTurn.fulfillmentAgentFailed = true;
      } else {
        activeTurn.fulfillmentAgentSeen = true;
      }
    }

    const isRelevantTarget =
      kind === "remote_call" ||
      agent === "relay_buyer" ||
      agent === "relay_supplier" ||
      network === "relay_supplier" ||
      agent === "fulfillment_agent" ||
      method === "website_read_workflow" ||
      method === "mcp_get_quote_snapshot";

    const hasRelevantStatus =
      (status !== null && RELEVANT_STATUSES.has(status)) ||
      (spanPhase !== null && RELEVANT_STATUSES.has(spanPhase));

    if (isRelevantTarget && hasRelevantStatus && typeof emit === "function") {
      emit({
        type: "trace",
        relayPhase: activeTurn.phase,
        kind,
        phase: spanPhase,
        status,
        agent,
        network,
        peerOrigin,
        method,
      });
    }
  });

  async function runPhase(phase, { receipt, kind } = {}) {
    if (activeTurn !== null) {
      throw new RelayError("A Decision Relay run is already active.");
    }
    if (!PHASE_SET.has(phase)) {
      throw new RelayError("Unsupported Decision Relay phase.");
    }

    const startedAt = Date.now();
    const requestText = buildPromptForPhase(phase);
    const turnState = {
      phase,
      requestText,
      declined: false,
      remoteCallSucceeded: false,
      remoteCallFailed: false,
      fulfillmentAgentSeen: false,
      fulfillmentAgentFailed: false,
      capturedSnapshot: null,
      captureError: null,
      review: null,
      decision: null,
    };
    activeTurn = turnState;

    try {
      setWorkflowPhase(phase, async () => {
        if (turnState.declined || !turnState.remoteCallSucceeded || !turnState.capturedSnapshot ||
            turnState.captureError || turnState.remoteCallFailed) {
          return { status: "unavailable", reason: "Grounded supplier evidence is required." };
        }
        if (!turnState.review) {
          turnState.review = submitReceipt({ phase, snapshot: turnState.capturedSnapshot, receipt, kind });
        }
        const decision = await turnState.review;
        if (!decision || typeof decision.status !== "string") throw new RelayError("Invalid review response.");
        turnState.decision = decision;
        emit?.({ kind: "receipt_review", agent: "fulfillment_agent", status: decision.state });
        return {
          status: decision.status, reason: decision.reason, state: decision.state, source: decision.source,
          selectedQuote: decision.selectedQuote, providerCalls: decision.providerCalls,
          receiptBasis: decision.receipt?.payload?.dependencyDigest ?? null,
        };
      });
      if (!topLoaded) {
        await engine.loadTop();
        topLoaded = true;
      } else {
        engine.resetHistory();
      }

      let turnResult = null;
      try {
        turnResult = await engine.runTurn(requestText, { slyData: { phase, buyer_budget: 450 } });
      } catch (error) {
        if (!turnState.decision) throw error;
      }

      if (turnState.declined) {
        throw new RelayError("Supplier peer consent was declined.");
      }
      if (turnState.captureError) {
        throw turnState.captureError;
      }
      if (!turnState.remoteCallSucceeded || turnState.remoteCallFailed) {
        throw new RelayError("Remote supplier call did not complete successfully.");
      }
      if (!turnState.fulfillmentAgentSeen || turnState.fulfillmentAgentFailed) {
        throw new RelayError("Internal fulfillment workflow check did not complete.");
      }
      if (!turnState.capturedSnapshot || turnState.capturedSnapshot.phase !== phase) {
        throw new RelayError("Authoritative supplier quote snapshot was not captured.");
      }

      const submission = turnState.decision;
      if (!submission) throw new RelayError("The fulfillment agent did not complete its scoped review.");

      return {
        decision: submission,
        source: submission.source ?? "authoritative-simulation",
        summary: sanitizeAdvisorySummary(extractModelText(turnResult)),
        proof: submission.proof ?? {
          phase,
          snapshotVerified: true,
          quoteCount: turnState.capturedSnapshot.quotes.length,
        },
        elapsedMs: Math.max(0, Date.now() - startedAt),
      };
    } catch (err) {
      if (err instanceof RelayError) {
        throw err;
      }
      if (turnState.declined) {
        throw new RelayError("Supplier peer consent was declined.");
      }
      throw new RelayError("Decision Relay execution failed.");
    } finally {
      setWorkflowPhase(phase);
      activeTurn = null;
    }
  }

  return { runPhase };
}
