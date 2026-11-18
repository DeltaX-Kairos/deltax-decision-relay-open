const FIXTURE_MODEL = "neuro-san-mock-browser";

function normalizeOrigin(value, name) {
  if (typeof value !== "string" || !value) {
    throw new Error(`${name} must be a non-empty origin string.`);
  }
  const parsed = new URL(value);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`${name} must use http or https protocol.`);
  }
  return parsed.origin;
}

/**
 * Build deterministic buyer and supplier runtime artifacts from server config.
 *
 * @param {object} params
 * @param {string} params.buyerOrigin Exact buyer origin URL.
 * @param {string} params.supplierOrigin Exact supplier origin URL.
 * @param {"fixture"|"provider"} params.routerMode Routing mode.
 * @param {string} [params.model] Provider model name when routerMode is "provider".
 * @returns {{ buyer: Record<string, object>, supplier: Record<string, object> }}
 *   Maps artifact file basenames to plain JSON-serializable values.
 */
export function buildAgentArtifacts({ buyerOrigin, supplierOrigin, routerMode, model }) {
  const normalizedBuyerOrigin = normalizeOrigin(buyerOrigin, "buyerOrigin");
  const normalizedSupplierOrigin = normalizeOrigin(supplierOrigin, "supplierOrigin");

  if (routerMode !== "fixture" && routerMode !== "provider") {
    throw new Error("routerMode must be 'fixture' or 'provider'.");
  }
  if (routerMode === "provider" && (typeof model !== "string" || !model.trim())) {
    throw new Error("model is required when routerMode is 'provider'.");
  }

  const llmRouter =
    routerMode === "fixture"
      ? { base_url: "browser://mock", mock: true }
      : { base_url: `${normalizedBuyerOrigin}/api/router/v1`, browser_reference_fallback: true };
  const modelName = routerMode === "fixture" ? FIXTURE_MODEL : model.trim();

  const buyerManifest = {
    brand: "Decision Relay Buyer",
    metadata: {
      description: "Decision Relay buyer origin manifest.",
      buyerOrigin: normalizedBuyerOrigin,
    },
    networks: [
      {
        name: "decision_relay",
        front_man: "relay_buyer",
        hocon: "./buyer.network.json",
      },
    ],
    links: "./links.json",
    llm_router: llmRouter,
    allowed_peers: [normalizedSupplierOrigin],
    peer_policy: { mode: "closed" },
    actions: {
      version: 1,
      module: "./site-actions.js",
      agentTools: ["read_workflow"],
      agentToolOwners: { read_workflow: "fulfillment_agent" },
    },
  };

  const buyerGraph = {
    link_slots: { relay_supplier: {} },
    metadata: {
      description: "Decision Relay buyer agent network coordinating supplier quote lookup and fulfillment read workflow.",
    },
    llm_config: {
      model_name: modelName,
    },
    max_steps: 6,
    tools: [
      {
        name: "relay_buyer",
        function: {
          description: "Coordinate supplier quote lookup via relay_supplier then verify workflow via fulfillment_agent.",
          parameters: {
            type: "object",
            properties: {
              request: { type: "string" },
            },
            required: ["request"],
          },
        },
        instructions: [
          "You are the Decision Relay buyer coordinator.",
          "Step 1: Always call relay_supplier first with {\"request\": <exact user prompt>}. Forward only the exact prompt string with no added context, budget, or prior results.",
          "Step 2: Wait for the supplier result, then call fulfillment_agent with {\"request\": <exact user prompt>} to check the current workflow state.",
          "Step 3: Provide a concise advisory summary based solely on observed tool outputs without inventing quotes, prices, or signatures.",
        ].join(" "),
        tools: ["relay_supplier", "fulfillment_agent"],
      },
      {
        name: "fulfillment_agent",
        parallel_safe: false,
        function: {
          description: "Check internal workflow phase and state using website_read_workflow.",
          parameters: {
            type: "object",
            properties: {
              request: { type: "string" },
            },
            required: ["request"],
          },
        },
        instructions:
          "Call website_read_workflow with {} to verify the receipt against the current supplier evidence and review the quote. Return a brief summary of the completed fictional decision.",
        tools: [],
      },
    ],
  };

  const buyerLinks = {
    version: 1,
    networks: {
      decision_relay: {
        relay_supplier: `${normalizedSupplierOrigin}/relay_supplier`,
      },
    },
  };

  const supplierManifest = {
    brand: "Decision Relay Supplier",
    metadata: {
      description: "Decision Relay supplier origin manifest.",
    },
    networks: [
      {
        name: "relay_supplier",
        front_man: "relay_supplier",
        hocon: "./supplier.network.json",
      },
    ],
    llm_router: llmRouter,
    allowed_peers: [normalizedSupplierOrigin],
    peer_policy: { mode: "closed" },
    mcp: [
      {
        url: `${normalizedSupplierOrigin}/mcp`,
        tools: ["get_quote_snapshot"],
      },
    ],
  };

  const supplierGraph = {
    metadata: {
      description: "Decision Relay supplier agent network backed solely by mcp_get_quote_snapshot.",
    },
    llm_config: {
      model_name: modelName,
    },
    max_steps: 6,
    tools: [
      {
        name: "relay_supplier",
        function: {
          description: "Retrieve the authoritative signed fictional quote snapshot for an exact quote request.",
          parameters: {
            type: "object",
            properties: {
              request: { type: "string" },
            },
            required: ["request"],
          },
        },
        instructions:
          "Call mcp_get_quote_snapshot with {\"request\": <exact input request string>} preserving exact punctuation, and return the snapshot output verbatim without altering values or signatures.",
        tools: [{ url: `${normalizedSupplierOrigin}/mcp`, tools: ["get_quote_snapshot"] }],
      },
    ],
  };

  return {
    buyer: {
      "agent-manifest.json": buyerManifest,
      "buyer.network.json": buyerGraph,
      "links.json": buyerLinks,
    },
    supplier: {
      "agent-manifest.json": supplierManifest,
      "links.json": { version: 1, networks: { relay_supplier: {} } },
      "supplier.network.json": supplierGraph,
    },
  };
}
