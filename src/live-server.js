import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { buildAgentArtifacts } from './agent-artifacts.js';
import { createHostedEvaluate } from './hosted-evaluate.js';
import { createLedger } from './hosted-ledger.js';
import { createReviewer } from './review.js';
import { createRouter } from './router.js';
import { createSupplier } from './supplier.js';

const DEFAULT_BUYER_PORT = 19170;
const DEFAULT_SUPPLIER_PORT = 19171;
const MAX_REQUEST_BYTES = 64 * 1024;
const SERVER_TIMEOUT_MS = 15000;
const SESSION_COOKIE_NAME = 'relay_session';
const RELAY_ROUTER_TAG = 'relay-publisher-session';
const SAFE_SEGMENT_RE = /^[a-zA-Z0-9._-]+$/;
const HEX_KEY_RE = /^[0-9a-f]{32,}$/i;
const DECISION_BODY_KEYS = ['phase', 'snapshot', 'receipt', 'kind'];

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.txt': 'text/plain; charset=utf-8'
};

export function isLoopbackOrigin(origin) {
  try {
    const url = new URL(origin);
    return (
      url.protocol === 'http:' &&
      (url.hostname === '127.0.0.1' || url.hostname === 'localhost' || url.hostname === '[::1]')
    );
  } catch {
    return false;
  }
}

export function validateOrigin(origin, label = 'origin') {
  if (typeof origin !== 'string' || !origin) {
    throw new Error(`${label} must be a non-empty origin URL`);
  }
  let parsed;
  try {
    parsed = new URL(origin);
  } catch {
    throw new Error(`${label} is not a valid URL`);
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== '/') {
    throw new Error(`${label} must be a clean origin without path, query, or credentials`);
  }
  if (parsed.protocol === 'https:') {
    return parsed.origin;
  }
  if (isLoopbackOrigin(parsed.origin)) {
    return parsed.origin;
  }
  throw new Error(`${label} must use HTTPS or local loopback HTTP`);
}

function parsePort(raw, fallback) {
  if (raw === undefined || raw === null || raw === '') {
    return fallback;
  }
  const num = Number(raw);
  if (!Number.isInteger(num) || num < 0 || num > 65535) {
    throw new Error(`Invalid port value: ${raw}`);
  }
  return num;
}

function parsePositiveInt(raw, name) {
  const num = Number(raw);
  if (!Number.isInteger(num) || num <= 0) {
    throw new Error(`${name} must be an integer > 0`);
  }
  return num;
}

function parseUtcCutoff(raw) {
  if (typeof raw !== 'string' || !raw.trim()) {
    throw new Error('RELAY_CUTOFF must be a UTC ISO timestamp');
  }
  const trimmed = raw.trim();
  if (!/(Z|\+00:00)$/i.test(trimmed) || Number.isNaN(Date.parse(trimmed))) {
    throw new Error('RELAY_CUTOFF must be a valid UTC ISO-8601 timestamp ending in Z or +00:00');
  }
  return trimmed;
}

function validateHexKey(raw, name) {
  if (typeof raw !== 'string' || !HEX_KEY_RE.test(raw) || raw.length % 2 !== 0) {
    throw new Error(`${name} must be an even-length hex key of at least 32 characters`);
  }
  return raw.toLowerCase();
}

function isFlagEnabled(val) {
  return val === true || val === '1' || val === 'true' || val === 'yes' || val === 'enabled';
}

export function parseConfigFromEnv(env = process.env) {
  const isProduction = env.NODE_ENV === 'production';
  const buyerPort = parsePort(env.BUYER_PORT, DEFAULT_BUYER_PORT);
  const supplierPort = parsePort(env.SUPPLIER_PORT, DEFAULT_SUPPLIER_PORT);

  const rawBuyerOrigin = env.BUYER_ORIGIN;
  const rawSupplierOrigin = env.SUPPLIER_ORIGIN;
  if (isProduction && (!rawBuyerOrigin || !rawSupplierOrigin)) {
    throw new Error('BUYER_ORIGIN and SUPPLIER_ORIGIN are required in production');
  }
  const buyerOrigin = validateOrigin(rawBuyerOrigin || `http://127.0.0.1:${buyerPort}`, 'BUYER_ORIGIN');
  const supplierOrigin = validateOrigin(rawSupplierOrigin || `http://localhost:${supplierPort}`, 'SUPPLIER_ORIGIN');
  if (isProduction && (!buyerOrigin.startsWith('https://') || !supplierOrigin.startsWith('https://') || buyerOrigin === supplierOrigin)) {
    throw new Error('Production requires two distinct HTTPS origins');
  }


  const hostedFlag = isFlagEnabled(env.RELAY_HOSTED_MODE);
  const evaluateClientId = env.RELAY_EVALUATE_CLIENT_ID?.trim() || '';
  const evaluateClientSecret = env.RELAY_EVALUATE_CLIENT_SECRET?.trim() || '';
  const hasEvaluateCredentials = Boolean(evaluateClientId && evaluateClientSecret);
  const hostedAvailable = hostedFlag && hasEvaluateCredentials;

  let evidenceKey = env.RELAY_EVIDENCE_KEY?.trim() || '';
  let receiptKey = env.RELAY_RECEIPT_KEY?.trim() || '';

  if (hostedAvailable) {
    if (!env.RELAY_EVALUATE_LEDGER_FILE?.trim()) {
      throw new Error('RELAY_EVALUATE_LEDGER_FILE is required when hosted mode is active');
    }
    evidenceKey = validateHexKey(evidenceKey, 'RELAY_EVIDENCE_KEY');
    receiptKey = validateHexKey(receiptKey, 'RELAY_RECEIPT_KEY');
  } else if (isProduction) {
    evidenceKey = validateHexKey(evidenceKey, 'RELAY_EVIDENCE_KEY');
    receiptKey = validateHexKey(receiptKey, 'RELAY_RECEIPT_KEY');
  } else {
    evidenceKey = evidenceKey ? validateHexKey(evidenceKey, 'RELAY_EVIDENCE_KEY') : crypto.randomBytes(32).toString('hex');
    receiptKey = receiptKey ? validateHexKey(receiptKey, 'RELAY_RECEIPT_KEY') : crypto.randomBytes(32).toString('hex');
  }

  let hostedBudget = null;
  let hostedWindowLimit = null;
  let cutoff = null;
  if (hostedAvailable) {
    const rawBudget = env.RELAY_HOSTED_BUDGET ?? env.RELAY_EVALUATE_BUDGET ?? env.RELAY_BUDGET;
    hostedBudget = parsePositiveInt(rawBudget, 'Hosted budget');
    const rawWindow = env.RELAY_HOSTED_WINDOW_LIMIT ?? env.RELAY_WINDOW_LIMIT;
    hostedWindowLimit = rawWindow !== undefined && rawWindow !== '' ? parsePositiveInt(rawWindow, 'Window limit') : hostedBudget;
    cutoff = parseUtcCutoff(env.RELAY_CUTOFF);
  }

  const otariApiKey = env.RELAY_OTARI_API_KEY?.trim() || '';
  const otariModel = env.RELAY_OTARI_MODEL?.trim() || '';
  const routerEnabled = Boolean(otariApiKey && otariModel);
  let routerLedgerFile = env.RELAY_OTARI_LEDGER_FILE?.trim() || env.RELAY_ROUTER_LEDGER_FILE?.trim() || '';
  let routerBudget = null;
  let routerWindowLimit = null;
  if (routerEnabled) {
    if (!routerLedgerFile) {
      throw new Error('RELAY_OTARI_LEDGER_FILE is required when router provider mode is active');
    }
    routerBudget = parsePositiveInt(env.RELAY_OTARI_BUDGET ?? env.RELAY_ROUTER_BUDGET ?? '10', 'Router budget');
    routerWindowLimit = parsePositiveInt(env.RELAY_OTARI_WINDOW_LIMIT ?? String(routerBudget), 'Router window limit');
    cutoff = cutoff ?? parseUtcCutoff(env.RELAY_CUTOFF);
  }

  return {
    isProduction,
    buyerPort,
    supplierPort,
    buyerOrigin,
    supplierOrigin,
    hostedAvailable,
    evaluateClientId: hostedAvailable ? evaluateClientId : '',
    evaluateClientSecret: hostedAvailable ? evaluateClientSecret : '',
    evaluateLedgerFile: hostedAvailable ? env.RELAY_EVALUATE_LEDGER_FILE.trim() : '',
    hostedBudget,
    hostedWindowLimit,
    cutoff,
    evidenceKey,
    receiptKey,
    otariApiKey: routerEnabled ? otariApiKey : '',
    otariModel,
    routerLedgerFile,
    routerBudget,
    routerWindowLimit
  };
}

function sendFixedJson(res, status, body, extraHeaders = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    ...extraHeaders
  });
  res.end(JSON.stringify(body));
}

function parseCookies(cookieHeader) {
  const out = new Map();
  if (typeof cookieHeader !== 'string' || !cookieHeader) return out;
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx <= 0) continue;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if (key && val) out.set(key, val);
  }
  return out;
}

function buildSessionCookieHeader(token, isHttps) {
  const parts = [`${SESSION_COOKIE_NAME}=${token}`, 'Path=/', 'HttpOnly', 'SameSite=Strict', 'Max-Age=604800'];
  if (isHttps) {
    parts.push('Secure');
  }
  return parts.join('; ');
}

function buildArtifactMap(entries) {
  const map = new Map();
  if (!entries || typeof entries !== 'object') return map;
  for (const [rawKey, rawVal] of Object.entries(entries)) {
    const clean = String(rawKey).replace(/^\/+/, '');
    if (!clean || clean.includes('..') || clean.includes('\\') || clean.includes('\0')) continue;
    if (clean.startsWith('.git') || clean.startsWith('.env')) continue;
    const segments = clean.split('/');
    if (segments.some((s) => !s || !SAFE_SEGMENT_RE.test(s) || s === '.' || s === '..')) continue;
    const text = typeof rawVal === 'string' ? rawVal : JSON.stringify(rawVal, null, 2);
    map.set(`/${clean}`, text);
  }
  return map;
}

function validateRelativeAssetPath(pathname, defaultFile = null) {
  if (typeof pathname !== 'string' || !pathname.startsWith('/') || pathname.includes('\0')) {
    return null;
  }
  let decoded;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return null;
  }
  if (/[^\x20-\x7e]/.test(decoded) || decoded.includes('\\') || decoded.includes('..')) {
    return null;
  }
  const rel = decoded === '/' ? defaultFile : decoded.slice(1);
  if (!rel) return null;
  const segments = rel.split('/');
  for (const seg of segments) {
    if (!seg || seg === '.' || seg === '..' || !SAFE_SEGMENT_RE.test(seg)) {
      return null;
    }
    if (seg === '.git' || seg.startsWith('.env')) {
      return null;
    }
  }
  return rel;
}

function tryReadStaticFile(rootDir, relPath) {
  if (!rootDir || !relPath) return null;
  let realRoot;
  try {
    realRoot = fs.realpathSync(rootDir);
  } catch {
    return null;
  }
  const candidate = path.resolve(realRoot, relPath);
  if (candidate !== realRoot && !candidate.startsWith(realRoot + path.sep)) {
    return null;
  }
  try {
    const stat = fs.lstatSync(candidate);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      return null;
    }
    const realTarget = fs.realpathSync(candidate);
    if (!realTarget.startsWith(realRoot + path.sep)) {
      return null;
    }
    const ext = path.extname(realTarget).toLowerCase();
    const contentType = MIME_TYPES[ext] ?? 'application/octet-stream';
    const data = fs.readFileSync(realTarget);
    return { contentType, data };
  } catch {
    return null;
  }
}

async function readJsonBody(req, maxBytes) {
  const contentLength = Number(req.headers['content-length']);
  if (Number.isFinite(contentLength) && contentLength > maxBytes) {
    return { ok: false, status: 413, code: 'PAYLOAD_TOO_LARGE', message: 'Request body too large.' };
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBytes) {
      return { ok: false, status: 413, code: 'PAYLOAD_TOO_LARGE', message: 'Request body too large.' };
    }
    chunks.push(chunk);
  }
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    return { ok: true, body: parsed };
  } catch {
    return { ok: false, status: 400, code: 'INVALID_JSON', message: 'Invalid JSON request body.' };
  }
}

function hasExactDecisionKeys(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return false;
  const keys = Object.keys(body);
  if (keys.length !== DECISION_BODY_KEYS.length) return false;
  return DECISION_BODY_KEYS.every((k) => Object.prototype.hasOwnProperty.call(body, k));
}

function listenLoopback(server, port) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolve(server.address());
    });
  });
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    if (!server.listening) {
      resolve();
      return;
    }
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

/**
 * Start the isolated Buyer and Supplier HTTP servers bound to loopback ports.
 */
export async function createRelayPair(options = {}) {
  const baseConfig = options.fromEnv ? options : { ...parseConfigFromEnv(options.env ?? process.env), ...options };
  const isProduction = Boolean(baseConfig.isProduction);
  const buyerPort = baseConfig.buyerPort ?? DEFAULT_BUYER_PORT;
  const supplierPort = baseConfig.supplierPort ?? DEFAULT_SUPPLIER_PORT;

  let buyerOrigin = validateOrigin(baseConfig.buyerOrigin ?? `http://127.0.0.1:${buyerPort}`, 'buyerOrigin');
  let supplierOrigin = validateOrigin(baseConfig.supplierOrigin ?? `http://localhost:${supplierPort}`, 'supplierOrigin');

  const hostedAvailable = Boolean(baseConfig.hostedAvailable);
  const evidenceKey = validateHexKey(baseConfig.evidenceKey, 'evidenceKey');
  const receiptKey = validateHexKey(baseConfig.receiptKey, 'receiptKey');

  if (hostedAvailable) {
    if (!baseConfig.evaluateClientId || !baseConfig.evaluateClientSecret || !baseConfig.evaluateLedgerFile) {
      throw new Error('Hosted mode requires client credentials and ledger file');
    }
    parsePositiveInt(baseConfig.hostedBudget, 'hostedBudget');
    parseUtcCutoff(baseConfig.cutoff);
  }

  const cwd = options.cwd ?? process.cwd();
  const publicBuyerDir = options.publicBuyerDir ?? path.resolve(cwd, 'public/buyer');
  const publicSupplierDir = options.publicSupplierDir ?? path.resolve(cwd, 'public/supplier');

  let evaluateLedger = options.evaluateLedger ?? null;
  let evaluateFn = options.evaluate ?? null;
  let routerLedger = options.routerLedger ?? null;

  if (hostedAvailable) {
    if (!evaluateLedger) {
      evaluateLedger = createLedger({
        file: baseConfig.evaluateLedgerFile,
        totalLimit: baseConfig.hostedBudget,
        cutoff: baseConfig.cutoff,
        windowLimit: baseConfig.hostedWindowLimit ?? baseConfig.hostedBudget
      });
    }
    if (!evaluateFn) {
      const hostedEvaluator = createHostedEvaluate({
        clientId: baseConfig.evaluateClientId,
        clientSecret: baseConfig.evaluateClientSecret,
        fetchImpl: options.evaluateFetchImpl ?? globalThis.fetch,
        timeoutMs: options.evaluateTimeoutMs ?? 22000
      });
      evaluateFn = hostedEvaluator;
    }
  }

  const hasRouterCredentials = Boolean(baseConfig.otariApiKey && baseConfig.otariModel);
  if (hasRouterCredentials && !routerLedger) {
    routerLedger = createLedger({
      file: baseConfig.routerLedgerFile,
      totalLimit: baseConfig.routerBudget,
      cutoff: baseConfig.cutoff,
      windowLimit: baseConfig.routerWindowLimit ?? baseConfig.routerBudget,
      mode: 'inference'
    });
  }

  // Bind servers on 127.0.0.1 first so dynamic port 0 resolves real origins before wiring artifacts/CORS.
  let buyerHandler;
  let supplierHandler;
  const buyerServer = http.createServer((req, res) => buyerHandler(req, res));
  const supplierServer = http.createServer((req, res) => supplierHandler(req, res));

  for (const srv of [buyerServer, supplierServer]) {
    srv.requestTimeout = SERVER_TIMEOUT_MS;
    srv.headersTimeout = 10000;
    srv.keepAliveTimeout = 5000;
  }

  const [buyerAddr, supplierAddr] = await Promise.all([
    listenLoopback(buyerServer, buyerPort),
    listenLoopback(supplierServer, supplierPort)
  ]);

  if (buyerPort === 0 && isLoopbackOrigin(buyerOrigin)) {
    const u = new URL(buyerOrigin);
    u.port = String(buyerAddr.port);
    buyerOrigin = u.origin;
  }
  if (supplierPort === 0 && isLoopbackOrigin(supplierOrigin)) {
    const u = new URL(supplierOrigin);
    u.port = String(supplierAddr.port);
    supplierOrigin = u.origin;
  }

  const expectedBuyerHost = new URL(buyerOrigin).host.toLowerCase();
  const expectedSupplierHost = new URL(supplierOrigin).host.toLowerCase();
  const buyerIsHttps = new URL(buyerOrigin).protocol === 'https:';
  const loopbackPair = !isProduction && isLoopbackOrigin(buyerOrigin) && isLoopbackOrigin(supplierOrigin);

  const router = createRouter({
    apiKey: baseConfig.otariApiKey,
    model: baseConfig.otariModel,
    buyerOrigin,
    ledger: routerLedger,
    fetchImpl: options.routerFetchImpl ?? globalThis.fetch,
    fixtureOnly: isProduction
  });

  const supplier = createSupplier({
    evidenceKey,
    buyerOrigin,
    supplierOrigin
  });

  const reviewer = createReviewer({
    supplier,
    signingKey: receiptKey,
    evaluate: hostedAvailable ? evaluateFn : null,
    ledger: hostedAvailable ? evaluateLedger : null
  });

  const artifacts = buildAgentArtifacts({
    buyerOrigin,
    supplierOrigin,
    routerMode: router.mode,
    model: router.model
  });
  const buyerArtifacts = buildArtifactMap(artifacts?.buyer);
  const supplierArtifacts = buildArtifactMap(artifacts?.supplier);

  function sessionMac(id, expires) {
    return crypto.createHmac('sha256', Buffer.from(receiptKey, 'hex'))
      .update(`relay-browser-cookie-v1:${id}:${expires}`).digest('hex');
  }

  function getVerifiedSession(req) {
    const token = parseCookies(req.headers.cookie).get(SESSION_COOKIE_NAME);
    const parts = /^([A-Za-z0-9_-]{32})\.(\d{10})\.([0-9a-f]{64})$/.exec(token ?? '');
    if (!parts) return null;
    const [, id, expires, mac] = parts;
    if (Number(expires) <= Math.floor(Date.now() / 1000)) return null;
    const expected = Buffer.from(sessionMac(id, expires), 'hex');
    return crypto.timingSafeEqual(expected, Buffer.from(mac, 'hex')) ? id : null;
  }

  function ensureSessionCookie(req) {
    const existing = getVerifiedSession(req);
    if (existing) return { session: existing, setCookieHeader: null };
    const id = crypto.randomBytes(24).toString('base64url');
    const expires = Math.floor(Date.now() / 1000) + 604800;
    const token = `${id}.${expires}.${sessionMac(id, expires)}`;
    return { session: id, setCookieHeader: buildSessionCookieHeader(token, buyerIsHttps) };
  }

  buyerHandler = async (req, res) => {
    try {
      const hostHeader = String(req.headers.host ?? '').toLowerCase();
      if (hostHeader !== expectedBuyerHost) {
        sendFixedJson(res, 403, { error: { code: 'INVALID_HOST', message: 'Forbidden host.' } });
        return;
      }

      const reqUrl = new URL(req.url || '/', buyerOrigin);
      const pathname = reqUrl.pathname;

      if (pathname === '/api/router/v1/chat/completions') {
        if (req.method === 'POST') {
          if (req.headers.origin !== buyerOrigin) {
            sendFixedJson(res, 403, { error: { code: 'FORBIDDEN_ORIGIN', message: 'Invalid request origin.' } });
            return;
          }
          const session = getVerifiedSession(req);
          if (!session) {
            sendFixedJson(res, 403, { error: { code: 'MISSING_SESSION', message: 'Valid session cookie required.' } });
            return;
          }
          await router.handleRequest(req, res, { session });
          return;
        }
        if (req.method === 'OPTIONS') {
          await router.handleRequest(req, res, {});
          return;
        }
        sendFixedJson(res, 405, { error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed.' } });
        return;
      }

      if (req.method === 'GET' && pathname === '/api/status') {
        const evaluateStatus = evaluateLedger?.status();
        const routerStatus = routerLedger?.status();
        sendFixedJson(res, 200, {
          replayReady: true,
          hostedConfigured: hostedAvailable,
          hostedRemaining: evaluateStatus?.totalRemaining ?? 0,
          modelConfigured: router.mode === 'provider',
          modelRemaining: routerStatus?.totalRemaining ?? 0,
          cutoff: evaluateStatus ? new Date(evaluateStatus.cutoffAt).toISOString() : null,
          open: Boolean(hostedAvailable && !evaluateStatus?.cutoffReached && !routerStatus?.cutoffReached)
        });
        return;
      }

      if (pathname === '/api/config') {
        if (req.method !== 'GET') {
          sendFixedJson(res, 405, { error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed.' } });
          return;
        }
        const { setCookieHeader } = ensureSessionCookie(req);
        const extra = setCookieHeader ? { 'Set-Cookie': setCookieHeader } : {};
        sendFixedJson(
          res,
          200,
          {
            buyerOrigin,
            supplierOrigin,
            model: router.model,
            routerMode: router.mode,
            relayRouterTag: RELAY_ROUTER_TAG,
            hostedAvailable
          },
          extra
        );
        return;
      }

      if (pathname === '/api/decision') {
        if (req.method !== 'POST') {
          sendFixedJson(res, 405, { error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed.' } });
          return;
        }
        if (req.headers.origin !== buyerOrigin) {
          sendFixedJson(res, 403, { error: { code: 'FORBIDDEN_ORIGIN', message: 'Invalid request origin.' } });
          return;
        }
        const session = getVerifiedSession(req);
        if (!session) {
          sendFixedJson(res, 403, { error: { code: 'MISSING_SESSION', message: 'Valid session cookie required.' } });
          return;
        }

        const parsed = await readJsonBody(req, MAX_REQUEST_BYTES);
        if (!parsed.ok) {
          sendFixedJson(res, parsed.status, { error: { code: parsed.code, message: parsed.message } });
          return;
        }
        if (!hasExactDecisionKeys(parsed.body)) {
          sendFixedJson(res, 400, {
            error: { code: 'INVALID_BODY', message: 'Request body must have exact fields: phase, snapshot, receipt, kind.' }
          });
          return;
        }

        const { phase, snapshot, receipt, kind } = parsed.body;
        if (kind === 'hosted' && !hostedAvailable) {
          sendFixedJson(res, 403, {
            error: { code: 'HOSTED_DISABLED', message: 'Hosted evaluation is disabled.' },
            status: 'refused',
            reason: 'Hosted evaluation is disabled.',
            selectedQuote: null,
            receipt: null,
            state: 'stopped',
            source: 'local-policy',
            providerCalls: 0,
            quotes: [],
            baseline: { status: 'abstained', selectedVendorId: null }
          });
          return;
        }
        if (kind === 'hosted-no-reuse' && (!hostedAvailable || !loopbackPair)) {
          sendFixedJson(res, 403, {
            error: {
              code: 'HOSTED_NO_REUSE_FORBIDDEN',
              message: 'hosted-no-reuse requires enabled hosted mode on loopback configuration.'
            },
            status: 'refused',
            reason: 'hosted-no-reuse requires enabled hosted mode on loopback configuration.',
            selectedQuote: null,
            receipt: null,
            state: 'stopped',
            source: 'local-policy',
            providerCalls: 0,
            quotes: [],
            baseline: { status: 'abstained', selectedVendorId: null }
          });
          return;
        }

        const decision = await reviewer.decide({ session, phase, snapshot, receipt, kind });
        sendFixedJson(res, 200, decision);
        return;
      }

      if (req.method !== 'GET' && req.method !== 'HEAD') {
        sendFixedJson(res, 405, { error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed.' } });
        return;
      }

      const relPath = validateRelativeAssetPath(pathname, 'index.html');
      if (!relPath) {
        sendFixedJson(res, 403, { error: { code: 'FORBIDDEN_PATH', message: 'Invalid asset path.' } });
        return;
      }

      const normalizedPath = `/${relPath}`;
      if (buyerArtifacts.has(normalizedPath)) {
        const bodyText = buyerArtifacts.get(normalizedPath);
        res.writeHead(200, {
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff',
          'Referrer-Policy': 'no-referrer'
        });
        res.end(req.method === 'HEAD' ? undefined : bodyText);
        return;
      }

      const asset = tryReadStaticFile(publicBuyerDir, relPath);
      if (!asset) {
        sendFixedJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Asset not found.' } });
        return;
      }

      const headers = {
        'Content-Type': asset.contentType,
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer'
      };
      if (relPath === 'index.html') {
        headers['Content-Security-Policy'] = `default-src 'self'; connect-src 'self' ${supplierOrigin}; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`;
        const { setCookieHeader } = ensureSessionCookie(req);
        if (setCookieHeader) {
          headers['Set-Cookie'] = setCookieHeader;
        }
      }
      res.writeHead(200, headers);
      res.end(req.method === 'HEAD' ? undefined : asset.data);
    } catch {
      if (!res.headersSent) {
        sendFixedJson(res, 500, { error: { code: 'INTERNAL_ERROR', message: 'Internal buyer server error.' } });
      } else {
        res.end();
      }
    }
  };

  supplierHandler = async (req, res) => {
    try {
      const hostHeader = String(req.headers.host ?? '').toLowerCase();
      if (hostHeader !== expectedSupplierHost) {
        sendFixedJson(res, 403, { error: { code: 'INVALID_HOST', message: 'Forbidden host.' } });
        return;
      }

      const reqUrl = new URL(req.url || '/', supplierOrigin);
      const pathname = reqUrl.pathname;

      if (pathname === '/mcp') {
        const reqOrigin = req.headers.origin;
        if (req.method === 'OPTIONS') {
          if (reqOrigin !== buyerOrigin) {
            sendFixedJson(res, 403, { error: { code: 'FORBIDDEN_ORIGIN', message: 'Origin not allowed for MCP.' } });
            return;
          }
          res.writeHead(204, {
            'Access-Control-Allow-Origin': buyerOrigin,
            'Vary': 'Origin',
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'MCP-Protocol-Version, Content-Type',
            'X-Content-Type-Options': 'nosniff'
          });
          res.end();
          return;
        }

        if (req.method !== 'POST') {
          sendFixedJson(res, 405, { error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed.' } });
          return;
        }

        if (reqOrigin !== buyerOrigin) {
          sendFixedJson(res, 403, { error: { code: 'FORBIDDEN_ORIGIN', message: 'Origin not allowed for MCP.' } });
          return;
        }

        const parsed = await readJsonBody(req, MAX_REQUEST_BYTES);
        if (!parsed.ok) {
          sendFixedJson(res, parsed.status, { error: { code: parsed.code, message: parsed.message } });
          return;
        }

        const rpcRes = await supplier.handleRpc(parsed.body);
        const status = Number.isInteger(rpcRes?.status) ? rpcRes.status : 200;
        const body = rpcRes?.body ?? {};
        const corsHeaders = reqOrigin === buyerOrigin ? { 'Access-Control-Allow-Origin': buyerOrigin, 'Vary': 'Origin' } : {};
        sendFixedJson(res, status, body, corsHeaders);
        return;
      }

      if (req.method !== 'GET' && req.method !== 'HEAD') {
        sendFixedJson(res, 405, { error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed.' } });
        return;
      }

      const relPath = validateRelativeAssetPath(pathname, 'index.html');
      if (!relPath) {
        sendFixedJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Resource not found.' } });
        return;
      }

      const normalizedPath = `/${relPath}`;
      if (supplierArtifacts.has(normalizedPath)) {
        const text = supplierArtifacts.get(normalizedPath);
        res.writeHead(200, {
          'Content-Type': 'application/json; charset=utf-8',
          'Access-Control-Allow-Origin': '*',
          'Cross-Origin-Resource-Policy': 'cross-origin',
          'Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff'
        });
        res.end(req.method === 'HEAD' ? undefined : text);
        return;
      }

      const asset = tryReadStaticFile(publicSupplierDir, relPath);
      if (!asset) {
        sendFixedJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Resource not found.' } });
        return;
      }

      res.writeHead(200, {
        'Content-Type': asset.contentType,
        'Access-Control-Allow-Origin': '*',
        'Cross-Origin-Resource-Policy': 'cross-origin',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff'
      });
      res.end(req.method === 'HEAD' ? undefined : asset.data);
    } catch {
      if (!res.headersSent) {
        sendFixedJson(res, 500, { error: { code: 'INTERNAL_ERROR', message: 'Internal supplier server error.' } });
      } else {
        res.end();
      }
    }
  };

  return {
    buyerServer,
    supplierServer,
    buyerOrigin,
    supplierOrigin,
    buyerPort: buyerAddr.port,
    supplierPort: supplierAddr.port,
    hostedAvailable,
    routerMode: router.mode,
    async close() {
      await Promise.all([closeServer(buyerServer), closeServer(supplierServer)]);
    }
  };
}

async function main() {
  const config = parseConfigFromEnv(process.env);
  const pair = await createRelayPair({ ...config, fromEnv: true });
  console.log(
    JSON.stringify({
      event: 'relay-started',
      buyerOrigin: pair.buyerOrigin,
      supplierOrigin: pair.supplierOrigin,
      hostedAvailable: pair.hostedAvailable,
      routerMode: pair.routerMode
    })
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error(err?.message || 'Failed to start Decision Relay');
    process.exit(1);
  });
}
