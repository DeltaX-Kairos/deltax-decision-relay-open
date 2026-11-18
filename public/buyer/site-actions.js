const WORKFLOW_STATES = Object.freeze({
  initial: Object.freeze({
    phase: "initial",
    workState: "awaiting_initial_quote_comparison",
  }),
  unchanged: Object.freeze({
    phase: "unchanged",
    workState: "comparing_unchanged_revision",
  }),
  unrelated: Object.freeze({
    phase: "unrelated",
    workState: "reviewing_unrelated_catalog_change",
  }),
  delay: Object.freeze({
    phase: "delay",
    workState: "handling_lead_time_delay",
  }),
  unavailable: Object.freeze({
    phase: "unavailable",
    workState: "handling_supplier_unavailable",
  }),
});

let currentPhase = "initial";
let reviewCurrentEvidence = null;

export function setWorkflowPhase(phase, review = null) {
  if (!Object.hasOwn(WORKFLOW_STATES, phase)) {
    throw new Error(`Unsupported workflow phase: ${String(phase)}`);
  }
  currentPhase = phase;
  reviewCurrentEvidence = review;
}

function registerReadWorkflow(target) {
  const registerFn = typeof target === "function" ? target : target?.register;
  if (typeof registerFn !== "function") {
    throw new TypeError("Action registration requires a register function.");
  }
  registerFn({
    name: "read_workflow",
    description: "Review the scoped supplier evidence and verify the current decision receipt.",
    timeoutMs: 28000,
    effect: "read",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
    async execute() {
      const state = WORKFLOW_STATES[currentPhase];
      if (!reviewCurrentEvidence) return { ...state, status: "unavailable" };
      return { ...state, ...await reviewCurrentEvidence() };
    },
  });
}

export function register(target) {
  return registerReadWorkflow(target);
}

export function registerActions(target) {
  return registerReadWorkflow(target);
}

export default registerReadWorkflow;
