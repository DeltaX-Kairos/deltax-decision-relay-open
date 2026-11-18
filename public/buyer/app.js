import {createRelayAgent} from './agent.js';

const MAX_COST_USD = 450;
const MAX_DAYS = 3;
const MAX_TRACE_EVENTS = 24;

const PHASE_LABELS = {
  initial: 'Review offers',
  unchanged: 'Recheck unchanged',
  unrelated: 'Update unrelated item',
  delay: 'Vendor A slips to 5 days',
  unavailable: 'Both offers miss deadline'
};

const STATUS_LABELS = {
  selected: 'Selected',
  abstained: 'Abstained',
  unavailable: 'Unavailable',
  refused: 'Refused',
  unknown: 'Unknown'
};

const STATE_LABELS = {
  new: 'New receipt',
  reused: 'Reused receipt',
  replanned: 'Replanned',
  stopped: 'Stopped'
};

const SOURCE_LABELS = {
  'local-fixture': 'Local fixture (fictional)',
  'hosted-evaluate': 'Hosted Evaluate',
  'local-policy': 'Local policy'
};

const state = {
  config: null,
  agent: null,
  lane: 'replay',
  running: false,
  activePhase: null,
  cachedReceipts: { replay: null, hosted: null },
  sessionConsent: new Set(),
  traceEvents: [],
  totalTraceEvents: 0,
  lastEvidence: null
};

const el = {
  laneBadge: document.getElementById('lane-badge'),
  laneInputs: Array.from(document.querySelectorAll('input[name="lane"]')),
  hostedLabel: document.getElementById('hosted-label'),
  btnDownload: document.getElementById('btn-download'),
  btnReset: document.getElementById('btn-reset'),
  btnRetryConfig: document.getElementById('btn-retry-config'),
  phaseButtons: Array.from(document.querySelectorAll('.phase-btn')),
  runStatusPill: document.getElementById('run-status-pill'),
  announcer: document.getElementById('live-announcer'),
  errorPanel: document.getElementById('error-panel'),
  errorTitle: document.getElementById('error-title'),
  errorCodeBadge: document.getElementById('error-code-badge'),
  errorMessage: document.getElementById('error-message'),
  errorActions: document.getElementById('error-actions'),
  outcomeStatusBadge: document.getElementById('outcome-status-badge'),
  outcomeReason: document.getElementById('outcome-reason'),
  metricSource: document.getElementById('metric-source'),
  metricBaseline: document.getElementById('metric-baseline'),
  metricCalls: document.getElementById('metric-calls'),
  metricElapsed: document.getElementById('metric-elapsed'),
  selectedCallout: document.getElementById('selected-quote-callout'),
  selectedQuoteText: document.getElementById('selected-quote-text'),
  quotesEmpty: document.getElementById('quotes-empty'),
  quotesList: document.getElementById('quotes-list'),
  receiptStateBadge: document.getElementById('receipt-state-badge'),
  receiptSource: document.getElementById('receipt-source'),
  receiptPriorBasis: document.getElementById('receipt-prior-basis'),
  receiptNewBasis: document.getElementById('receipt-new-basis'),
  receiptDigest: document.getElementById('receipt-digest'),
  receiptReason: document.getElementById('receipt-reason'),
  traceCaption: document.getElementById('trace-caption'),
  traceCount: document.getElementById('trace-count'),
  traceEmpty: document.getElementById('trace-empty'),
  traceList: document.getElementById('trace-list'),
  cfgRouter: document.getElementById('cfg-router'),
  cfgModel: document.getElementById('cfg-model'),
  cfgOrigins: document.getElementById('cfg-origins'),
  consentDialog: document.getElementById('consent-dialog'),
  consentOrigin: document.getElementById('consent-origin'),
  consentPurpose: document.getElementById('consent-purpose'),
  consentRequest: document.getElementById('consent-request'),
  consentAllow: document.getElementById('consent-allow'),
  consentAlways: document.getElementById('consent-always'),
  consentDecline: document.getElementById('consent-decline')
};

function sanitizeText(value, maxLen = 220) {
  if (value === null || value === undefined) return '';
  const str = String(value)
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 1) + '…';
}

function sanitizeMultiline(value, maxLen = 2400) {
  if (value === null || value === undefined) return '';
  let raw = '';
  if (typeof value === 'string') {
    raw = value;
  } else {
    try {
      raw = JSON.stringify(value, null, 2);
    } catch {
      raw = String(value);
    }
  }
  const cleaned = raw.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '');
  if (cleaned.length <= maxLen) return cleaned;
  return cleaned.slice(0, maxLen - 1) + '…';
}

function sanitizeFailureReason(rawReason, fallback) {
  const text = sanitizeText(rawReason, 220);
  if (!text) return fallback;
  const lower = text.toLowerCase();
  if (
    lower.includes('sk-') ||
    lower.includes('bearer ') ||
    lower.includes('stack') ||
    lower.includes('at ') ||
    lower.includes('provider error') ||
    lower.includes('api key') ||
    text.includes('{') ||
    text.includes('<')
  ) {
    return fallback;
  }
  return text;
}

function announce(message) {
  el.announcer.textContent = '';
  window.requestAnimationFrame(() => {
    el.announcer.textContent = sanitizeText(message, 160);
  });
}

function formatSource(source) {
  if (!source) return '—';
  return SOURCE_LABELS[source] || sanitizeText(source, 48);
}

function extractReceiptMeta(receipt) {
  if (!receipt || typeof receipt !== 'object') {
    return { present: false, id: '', digest: '', basis: '', priorBasis: '' };
  }
  const payload = receipt.payload;
  if (!payload || typeof payload !== 'object') {
    return { present: false, id: '', digest: '', basis: '', priorBasis: '' };
  }
  const evidence = payload.providerEvidence;
  return {
    present: true,
    id: sanitizeText(evidence?.receiptId, 96),
    digest: sanitizeText(evidence?.receiptDigest || payload.dependencyDigest, 96),
    basis: sanitizeText(payload.dependencyDigest, 16),
    priorBasis: ''
  };
}

function formatIdDigestPreview(meta) {
  if (!meta.present) return 'Not present';
  const parts = [];
  if (meta.id) parts.push(`id:${meta.id.slice(0, 18)}${meta.id.length > 18 ? '…' : ''}`);
  if (meta.digest) parts.push(`digest:${meta.digest.slice(0, 18)}${meta.digest.length > 18 ? '…' : ''}`);
  return parts.length ? parts.join(' · ') : 'Not present';
}

function isQuoteEligible(quote) {
  const cost = Number(quote?.cost);
  const days = Number(quote?.days);
  if (!Number.isFinite(cost) || !Number.isFinite(days)) return false;
  return quote?.sku === 'EQ-CRIT-01' && cost >= 0 && days >= 0 && cost <= MAX_COST_USD && days <= MAX_DAYS;
}

function updateControlsDisabled() {
  const ready = Boolean(state.agent && state.config);
  const hostedOk = Boolean(state.config && state.config.hostedAvailable);
  const busy = state.running;

  for (const btn of el.phaseButtons) {
    btn.disabled = busy || !ready;
    btn.setAttribute('aria-pressed', btn.dataset.phase === state.activePhase ? 'true' : 'false');
  }
  for (const input of el.laneInputs) {
    if (input.value === 'hosted') {
      input.disabled = busy || !ready || !hostedOk;
    } else {
      input.disabled = busy || !ready;
    }
  }
  el.btnReset.disabled = busy || !ready;
  el.btnDownload.disabled = busy || !state.lastEvidence;
  el.runStatusPill.textContent = busy ? 'Running…' : (ready ? 'Ready' : 'Unconfigured');
  el.runStatusPill.className = busy ? 'status-pill status-running' : 'status-pill status-idle';
}

function renderLaneHeader() {
  const isHosted = state.lane === 'hosted';
  el.laneBadge.textContent = isHosted ? 'Hosted Evaluate' : 'Local fixture';
  el.laneBadge.className = isHosted ? 'badge badge-replanned' : 'badge badge-lane';
  const hostedOk = Boolean(state.config && state.config.hostedAvailable);
  el.hostedLabel.textContent = hostedOk ? 'Hosted Evaluate' : 'Hosted Evaluate (Unconfigured)';
}

function hideError() {
  el.errorPanel.hidden = true;
  el.errorMessage.textContent = '';
  el.errorActions.hidden = true;
}

function showError({ title, badgeText, message, allowConfigRetry = false }) {
  el.errorTitle.textContent = sanitizeText(title, 80);
  el.errorCodeBadge.textContent = sanitizeText(badgeText, 32);
  el.errorMessage.textContent = sanitizeText(message, 260);
  el.errorActions.hidden = !allowConfigRetry;
  el.errorPanel.hidden = false;
}

function resetOutcomeView() {
  el.outcomeStatusBadge.textContent = 'Awaiting run';
  el.outcomeStatusBadge.className = 'badge badge-neutral';
  el.outcomeReason.textContent = 'Run Review offers to inspect fictional supplier quotes and policy evaluation.';
  el.metricSource.textContent = '—';
  el.metricBaseline.textContent = '—';
  el.metricCalls.textContent = '—';
  el.metricElapsed.textContent = '—';
  el.selectedCallout.hidden = true;
  el.selectedQuoteText.textContent = '';

  el.quotesList.replaceChildren();
  el.quotesList.hidden = true;
  el.quotesEmpty.hidden = false;

  el.receiptStateBadge.textContent = 'No receipt';
  el.receiptStateBadge.className = 'badge badge-neutral';
  el.receiptSource.textContent = '—';
  el.receiptPriorBasis.textContent = 'None';
  el.receiptNewBasis.textContent = 'None';
  el.receiptDigest.textContent = 'Not present';
  el.receiptReason.textContent = '—';
}

function renderQuotes(quotes, selectedQuote) {
  el.quotesList.replaceChildren();
  if (!Array.isArray(quotes) || quotes.length === 0) {
    el.quotesList.hidden = true;
    el.quotesEmpty.hidden = false;
    return;
  }
  el.quotesEmpty.hidden = true;
  el.quotesList.hidden = false;

  const selectedId = selectedQuote?.vendorId || null;
  for (const q of quotes) {
    const li = document.createElement('li');
    const isSelected = Boolean(selectedId && q.vendorId === selectedId);
    li.className = isSelected ? 'quote-card is-selected' : 'quote-card';

    const top = document.createElement('div');
    top.className = 'quote-top';

    const title = document.createElement('div');
    title.className = 'quote-title';
    const name = sanitizeText(q.name || q.vendorId || 'Supplier', 80);
    const vendorId = sanitizeText(q.vendorId || '', 32);
    title.textContent = vendorId && vendorId !== name ? `${name} (${vendorId})` : name;

    const badges = document.createElement('div');
    badges.className = 'quote-badges';

    const eligible = isQuoteEligible(q);
    const eligBadge = document.createElement('span');
    eligBadge.className = eligible ? 'badge badge-eligible' : 'badge badge-ineligible';
    eligBadge.textContent = q.sku !== 'EQ-CRIT-01' ? 'Outside request' : eligible ? 'Eligible' : 'Ineligible';
    badges.appendChild(eligBadge);

    if (isSelected) {
      const selBadge = document.createElement('span');
      selBadge.className = 'badge badge-selected';
      selBadge.textContent = 'Selected';
      badges.appendChild(selBadge);
    }

    top.appendChild(title);
    top.appendChild(badges);

    const meta = document.createElement('div');
    meta.className = 'quote-meta';
    const skuSpan = document.createElement('span');
    skuSpan.className = 'mono';
    skuSpan.textContent = `SKU ${sanitizeText(q.sku || '—', 40)}`;

    const revSpan = document.createElement('span');
    revSpan.textContent = `Version ${q.revision !== undefined && q.revision !== null ? sanitizeText(q.revision, 24) : '—'}`;

    const costSpan = document.createElement('span');
    const costNum = Number(q.cost);
    costSpan.textContent = Number.isFinite(costNum) ? `$${costNum} USD` : 'USD —';

    const daysSpan = document.createElement('span');
    const daysNum = Number(q.days);
    daysSpan.textContent = Number.isFinite(daysNum) ? `${daysNum} ${daysNum === 1 ? 'day' : 'days'}` : 'Days —';

    meta.append(skuSpan, revSpan, costSpan, daysSpan);
    li.append(top, meta);
    el.quotesList.appendChild(li);
  }
}

function renderTrace() {
  el.traceList.replaceChildren();
  const count = state.traceEvents.length;
  if (count === 0) {
    el.traceList.hidden = true;
    el.traceEmpty.hidden = false;
    el.traceCount.textContent = '0 events';
    el.traceCaption.textContent = 'Structured events emitted by the browser relay agent.';
    return;
  }

  el.traceEmpty.hidden = true;
  el.traceList.hidden = false;
  el.traceCount.textContent = `${count} ${count === 1 ? 'event' : 'events'}`;
  if (state.totalTraceEvents > count) {
    el.traceCaption.textContent = `Showing latest ${count} of ${state.totalTraceEvents} structured events.`;
  } else {
    el.traceCaption.textContent = 'Structured events emitted by the browser relay agent.';
  }

  for (const ev of state.traceEvents) {
    const li = document.createElement('li');
    li.className = 'trace-item';

    const top = document.createElement('div');
    top.className = 'trace-top';

    const name = document.createElement('span');
    name.className = 'trace-name';
    const labels = {
      relay_buyer: 'Buyer agent',
      relay_supplier: 'Supplier agent',
      fulfillment_agent: 'Fulfillment agent',
      remote_call: 'Supplier network ran in the browser',
      grounded_snapshot: 'Versioned supplier quotes',
      consent: 'Supplier origin consent',
      receipt_review: 'Receipt verification'
    };
    name.textContent = labels[ev.kind] || labels[ev.agent] || 'Browser agent event';

    const badge = document.createElement('span');
    const stLower = (ev.status || '').toLowerCase();
    let badgeClass = 'badge badge-neutral';
    if (stLower === 'approved' || stLower === 'ok' || stLower === 'selected' || stLower === 'received') {
      badgeClass = 'badge badge-eligible';
    } else if (stLower === 'reused') {
      badgeClass = 'badge badge-reused';
    } else if (stLower === 'replanned' || stLower === 'drift') {
      badgeClass = 'badge badge-replanned';
    } else if (stLower === 'declined' || stLower === 'refused' || stLower === 'error') {
      badgeClass = 'badge badge-refused';
    }
    badge.className = badgeClass;
    badge.textContent = ev.status || 'recorded';

    top.append(name, badge);

    const metaParts = [];
    if (ev.phase) metaParts.push(`phase=${ev.phase}`);
    if (ev.network) metaParts.push(`network=${ev.network}`);
    if (ev.origin && ev.peerOrigin) {
      metaParts.push(`${ev.origin} -> ${ev.peerOrigin}`);
    } else if (ev.origin) {
      metaParts.push(`origin=${ev.origin}`);
    } else if (ev.peerOrigin) {
      metaParts.push(`peer=${ev.peerOrigin}`);
    }

    li.appendChild(top);
    if (metaParts.length > 0) {
      const meta = document.createElement('div');
      meta.className = 'trace-meta';
      meta.textContent = metaParts.join(' | ');
      li.appendChild(meta);
    }
    el.traceList.appendChild(li);
  }
}

function emitEvent(rawEvent) {
  if (!rawEvent || typeof rawEvent !== 'object') return;
  const ev = {
    kind: sanitizeText(rawEvent.kind, 40),
    phase: sanitizeText(rawEvent.phase, 40),
    status: sanitizeText(rawEvent.status, 40),
    network: sanitizeText(rawEvent.network, 40),
    agent: sanitizeText(rawEvent.agent, 40),
    origin: sanitizeText(rawEvent.origin, 100),
    peerOrigin: sanitizeText(rawEvent.peerOrigin, 100),
    method: sanitizeText(rawEvent.method, 60)
  };
  state.totalTraceEvents += 1;
  state.traceEvents.push(ev);
  if (state.traceEvents.length > MAX_TRACE_EVENTS) {
    state.traceEvents.shift();
  }
  renderTrace();
}

function askConsent(req) {
  const origin = sanitizeText(
    req?.origin || req?.peerOrigin || req?.supplierOrigin || state.config?.supplierOrigin || 'Unknown origin',
    140
  );
  const purpose = sanitizeText(
    req?.purpose || req?.reason || req?.summary || 'Delegated supplier quote request',
    180
  );
  const method = sanitizeText(req?.method || req?.kind || '', 60);
  const sessionKey = `${origin}|${purpose}|${method}`;

  if (state.sessionConsent.has(sessionKey)) {
    return Promise.resolve("always");
  }

  const payloadToShow = req?.requestText ?? req?.request ?? req?.delegatedRequest ?? req?.payload ?? req?.scope ?? req;
  el.consentOrigin.textContent = origin;
  el.consentPurpose.textContent = purpose;
  el.consentRequest.textContent = sanitizeMultiline(payloadToShow, 2400);

  return new Promise((resolve) => {
    let settled = false;
    const finish = (decision) => {
      if (settled) return;
      settled = true;
      el.consentAllow.removeEventListener('click', onAllow);
      el.consentAlways.removeEventListener('click', onAlways);
      el.consentDecline.removeEventListener('click', onDecline);
      el.consentDialog.removeEventListener('cancel', onCancel);
      if (el.consentDialog.open) {
        el.consentDialog.close();
      }
      resolve(decision);
    };
    const onAllow = () => finish("allow");
    const onAlways = () => {
      state.sessionConsent.add(sessionKey);
      finish("always");
    };
    const onDecline = () => finish("decline");
    const onCancel = (e) => {
      e.preventDefault();
      finish("decline");
    };

    el.consentAllow.addEventListener('click', onAllow);
    el.consentAlways.addEventListener('click', onAlways);
    el.consentDecline.addEventListener('click', onDecline);
    el.consentDialog.addEventListener('cancel', onCancel);
    el.consentDialog.showModal();
    el.consentAllow.focus();
  });
}

async function submitReceipt(payload) {
  const response = await fetch('/api/decision', {
    method: 'POST',
    signal: AbortSignal.timeout(27000),
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });

  let data = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }

  if (!response.ok) {
    if (data && typeof data === 'object' && (data.decision || data.status === 'refused')) {
      return data;
    }
    const safeReason = sanitizeFailureReason(data?.reason || data?.error, `Decision endpoint returned HTTP ${response.status}.`);
    const err = new Error(safeReason);
    err.isSafeUserError = true;
    throw err;
  }

  if (!data || typeof data !== 'object') {
    const err = new Error('Decision endpoint returned an invalid response.');
    err.isSafeUserError = true;
    throw err;
  }
  return data;
}

function renderRunResult(phase, priorReceipt, result) {
  const decision = (result?.decision && typeof result.decision === 'object') ? result.decision : (result || {});
  const status = STATUS_LABELS[decision.status] ? decision.status : 'unknown';
  const decState = STATE_LABELS[decision.state] ? decision.state : null;
  const source = decision.source || result?.source || (state.lane === 'hosted' ? 'hosted-evaluate' : 'local-fixture');
  const plainReason = sanitizeFailureReason(decision.reason || result?.summary, 'No reason provided.');

  const quotes = Array.isArray(decision.quotes) ? decision.quotes : [];
  const selectedQuote = decision.selectedQuote && typeof decision.selectedQuote === 'object' ? decision.selectedQuote : null;
  const baseline = decision.baseline && typeof decision.baseline === 'object' ? decision.baseline : null;
  const providerCalls = typeof decision.providerCalls === 'number' ? decision.providerCalls : null;
  const elapsedMs = typeof result?.elapsedMs === 'number' ? result.elapsedMs : null;

  const priorMeta = extractReceiptMeta(priorReceipt);
  const nextReceipt = decision.receipt !== undefined ? decision.receipt : result?.receipt;
  const newMeta = extractReceiptMeta(nextReceipt);

  if (nextReceipt && typeof nextReceipt === 'object') {
    state.cachedReceipts[state.lane] = nextReceipt;
  } else if (nextReceipt === null) {
    state.cachedReceipts[state.lane] = null;
  }

  if (status === 'refused') {
    resetOutcomeView();
    renderQuotes(quotes, null);
    showError({
      title: 'Delegated Request Refused',
      badgeText: 'Refused',
      message: plainReason
    });
    el.receiptStateBadge.textContent = decState ? STATE_LABELS[decState] : 'Stopped';
    el.receiptStateBadge.className = 'badge badge-refused';
    el.receiptSource.textContent = formatSource(source);
    el.receiptPriorBasis.textContent = priorMeta.present ? (priorMeta.basis || priorMeta.digest || priorMeta.id || 'Cached receipt') : 'None';
    el.receiptNewBasis.textContent = newMeta.present ? (newMeta.basis || newMeta.digest || newMeta.id || 'Issued') : 'None';
    el.receiptDigest.textContent = formatIdDigestPreview(newMeta);
    el.receiptReason.textContent = plainReason;

    state.lastEvidence = buildEvidence(phase, status, decState, source, plainReason, baseline, providerCalls, elapsedMs, quotes, selectedQuote, priorMeta, newMeta);
    announce(`Refused: ${plainReason}`);
    return;
  }

  hideError();

  el.outcomeStatusBadge.textContent = STATUS_LABELS[status];
  el.outcomeStatusBadge.className = `badge badge-${status === 'selected' ? 'selected' : status === 'unknown' ? 'neutral' : status}`;
  el.outcomeReason.textContent = plainReason;
  el.metricSource.textContent = formatSource(source);

  if (baseline) {
    const bStatus = sanitizeText(baseline.status || 'unknown', 32);
    const bVendor = sanitizeText(baseline.selectedVendorId || 'none', 40);
    el.metricBaseline.textContent = `${bVendor} (${bStatus})`;
  } else {
    el.metricBaseline.textContent = 'Not provided';
  }
  el.metricCalls.textContent = providerCalls !== null ? String(providerCalls) : '—';
  el.metricElapsed.textContent = elapsedMs !== null ? `${Math.round(elapsedMs)} ms` : '—';

  if (selectedQuote) {
    const qName = sanitizeText(selectedQuote.name || selectedQuote.vendorId || 'Vendor', 60);
    const qCost = Number.isFinite(Number(selectedQuote.cost)) ? `$${Number(selectedQuote.cost)}` : '—';
    const qDays = Number.isFinite(Number(selectedQuote.days)) ? `${Number(selectedQuote.days)}d` : '—';
    const qRev = selectedQuote.revision !== undefined ? `rev ${sanitizeText(selectedQuote.revision, 20)}` : '';
    el.selectedQuoteText.textContent = [qName, qCost, qDays, qRev].filter(Boolean).join(' · ');
    el.selectedCallout.hidden = false;
  } else {
    el.selectedCallout.hidden = true;
    el.selectedQuoteText.textContent = '';
  }

  renderQuotes(quotes, selectedQuote);

  el.receiptStateBadge.textContent = decState ? STATE_LABELS[decState] : (newMeta.present ? 'Issued' : 'No receipt');
  el.receiptStateBadge.className = decState ? `badge badge-${decState === 'new' ? 'selected' : decState}` : 'badge badge-neutral';
  el.receiptSource.textContent = formatSource(source);
  el.receiptPriorBasis.textContent = newMeta.priorBasis || (priorMeta.present ? (priorMeta.basis || priorMeta.digest || priorMeta.id || 'Cached receipt') : 'None');
  el.receiptNewBasis.textContent = newMeta.present ? (newMeta.basis || newMeta.digest || newMeta.id || 'Issued') : 'None';
  el.receiptDigest.textContent = formatIdDigestPreview(newMeta);
  el.receiptReason.textContent = plainReason;

  state.lastEvidence = buildEvidence(phase, status, decState, source, plainReason, baseline, providerCalls, elapsedMs, quotes, selectedQuote, priorMeta, newMeta);
  announce(`${PHASE_LABELS[phase] || phase}: ${STATUS_LABELS[status]}. ${plainReason}`);
}

function buildEvidence(phase, status, decState, source, reason, baseline, providerCalls, elapsedMs, quotes, selectedQuote, priorMeta, newMeta) {
  return {
    exportedAt: new Date().toISOString(),
    fictionalScenario: true,
    lane: state.lane,
    phase,
    outcome: {
      status,
      state: decState,
      source,
      reason,
      baseline,
      providerCalls,
      elapsedMs,
      selectedQuote: selectedQuote ? {
        vendorId: sanitizeText(selectedQuote.vendorId, 40),
        name: sanitizeText(selectedQuote.name, 60),
        sku: sanitizeText(selectedQuote.sku, 40),
        cost: selectedQuote.cost,
        days: selectedQuote.days,
        revision: selectedQuote.revision
      } : null
    },
    quotes: quotes.map((q) => ({
      vendorId: sanitizeText(q.vendorId, 40),
      name: sanitizeText(q.name, 60),
      sku: sanitizeText(q.sku, 40),
      cost: q.cost,
      days: q.days,
      revision: q.revision,
      eligibleUnder450And3d: isQuoteEligible(q)
    })),
    receipt: {
      present: newMeta.present,
      priorBasis: newMeta.priorBasis || priorMeta.basis || null,
      newBasis: newMeta.basis || null,
      idPreview: newMeta.id ? newMeta.id.slice(0, 24) : null,
      digestPreview: newMeta.digest ? newMeta.digest.slice(0, 24) : null
    },
    traceEvents: state.traceEvents.slice()
  };
}

async function runCoordinatorPhase(phase) {
  if (state.running || !state.agent) return;
  state.running = true;
  state.activePhase = phase;
  state.traceEvents = [];
  state.totalTraceEvents = 0;
  renderTrace();
  hideError();
  updateControlsDisabled();
  announce(`Running ${PHASE_LABELS[phase] || phase} on ${state.lane === 'hosted' ? 'Hosted Evaluate' : 'Local fixture'}.`);

  const priorReceipt = state.cachedReceipts[state.lane];
  try {
    const result = await state.agent.runPhase(phase, {
      receipt: priorReceipt,
      kind: state.lane
    });
    renderRunResult(phase, priorReceipt, result);
  } catch (err) {
    resetOutcomeView();
    const fallback = 'The relay run could not be completed. No supplier was selected.';
    const safeMsg = err?.isSafeUserError
      ? sanitizeText(err.message, 220)
      : sanitizeFailureReason(err?.message, fallback);
    showError({
      title: 'Execution Error',
      badgeText: 'Error',
      message: safeMsg
    });
    announce(`Error: ${safeMsg}`);
  } finally {
    state.running = false;
    updateControlsDisabled();
  }
}

function resetActiveLane() {
  if (state.running) return;
  state.cachedReceipts[state.lane] = null;
  state.activePhase = null;
  state.traceEvents = [];
  state.totalTraceEvents = 0;
  state.lastEvidence = null;
  hideError();
  resetOutcomeView();
  renderTrace();
  updateControlsDisabled();
  announce(`Cleared cached receipt and view for ${state.lane === 'hosted' ? 'Hosted Evaluate' : 'Local fixture'} lane.`);
}

function downloadEvidence() {
  if (!state.lastEvidence) return;
  const blob = new Blob([JSON.stringify(state.lastEvidence, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `deltax-evidence-${state.lane}-${state.lastEvidence.phase || 'run'}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function selectAgentLane() {
  const routerMode = state.lane === 'hosted' ? state.config.routerMode : 'fixture';
  const cfg = { ...state.config, routerMode };
  state.agent = createRelayAgent({ emit: emitEvent, askConsent, config: cfg, submitReceipt });
  el.cfgRouter.textContent = routerMode === 'provider' ? 'Otari' : 'Browser fixture';
  el.cfgModel.textContent = routerMode === 'provider' ? (state.config.model || 'Configured model') : 'Deterministic replay';
}

async function loadConfig() {
  hideError();
  state.agent = null;
  state.config = null;
  updateControlsDisabled();

  try {
    const res = await fetch('/api/config', { cache: 'no-store' });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    const cfg = await res.json();
    if (!cfg || typeof cfg !== 'object') {
      throw new Error('Invalid config');
    }
    state.config = {
      buyerOrigin: sanitizeText(cfg.buyerOrigin || window.location.origin, 120),
      supplierOrigin: sanitizeText(cfg.supplierOrigin || '', 120),
      model: sanitizeText(cfg.model || '', 80),
      routerMode: cfg.routerMode === 'provider' ? 'provider' : 'fixture',
      relayRouterTag: sanitizeText(cfg.relayRouterTag || '', 60),
      hostedAvailable: Boolean(cfg.hostedAvailable)
    };

    if (!state.config.hostedAvailable && state.lane === 'hosted') {
      state.lane = 'replay';
    }
    for (const input of el.laneInputs) {
      input.checked = input.value === state.lane;
    }

    document.getElementById('link-supplier').href = new URL('/', state.config.supplierOrigin).href;
    el.cfgOrigins.textContent = state.config.supplierOrigin
      ? `${state.config.buyerOrigin} <-> ${state.config.supplierOrigin}`
      : state.config.buyerOrigin;

    selectAgentLane();
    renderLaneHeader();
    updateControlsDisabled();
  } catch {
    el.cfgRouter.textContent = 'Unconfigured';
    el.cfgModel.textContent = 'Unconfigured';
    el.cfgOrigins.textContent = window.location.origin;
    renderLaneHeader();
    showError({
      title: 'Configuration Unavailable',
      badgeText: 'Unconfigured',
      message: 'Could not load relay configuration from /api/config. Retry once the local server is ready.',
      allowConfigRetry: true
    });
    updateControlsDisabled();
  }
}

function bindEvents() {
  for (const btn of el.phaseButtons) {
    btn.addEventListener('click', () => {
      const phase = btn.dataset.phase;
      if (phase) runCoordinatorPhase(phase);
    });
  }

  for (const input of el.laneInputs) {
    input.addEventListener('change', () => {
      if (state.running || !input.checked) return;
      if (input.value === 'hosted' && !state.config?.hostedAvailable) {
        input.checked = false;
        el.laneInputs.find((i) => i.value === 'replay').checked = true;
        return;
      }
      state.lane = input.value;
      selectAgentLane();
      state.activePhase = null;
      state.traceEvents = [];
      state.totalTraceEvents = 0;
      hideError();
      resetOutcomeView();
      renderTrace();
      renderLaneHeader();
      updateControlsDisabled();
      announce(`Switched lane to ${state.lane === 'hosted' ? 'Hosted Evaluate' : 'Local fixture'}.`);
    });
  }

  el.btnReset.addEventListener('click', resetActiveLane);
  el.btnDownload.addEventListener('click', downloadEvidence);
  el.btnRetryConfig.addEventListener('click', loadConfig);
}

bindEvents();
resetOutcomeView();
renderTrace();
loadConfig();
