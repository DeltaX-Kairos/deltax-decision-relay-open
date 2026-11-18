import crypto from 'node:crypto';
import { adaptLedgerReserve } from './review.js';

export const OTARI_UPSTREAM_URL = 'https://api.otari.ai/api/v1/chat/completions';
export const MAX_ROUTER_TOKENS = 800;

const ALLOWED_TOP_KEYS = new Set([
  'model',
  'messages',
  'max_tokens',
  'temperature',
  'stream',
  'tools',
  'tool_choice'
]);
const ALLOWED_MESSAGE_KEYS = new Set(['role', 'content', 'name', 'tool_call_id', 'tool_calls']);
const ALLOWED_ROLES = new Set(['system', 'user', 'assistant', 'tool']);
const ALLOWED_TOOL_KEYS = new Set(['type', 'function']);
const ALLOWED_FUNCTION_KEYS = new Set(['name', 'description', 'parameters', 'strict']);
const TOOL_NAME_RE = /^[a-zA-Z0-9_.-]{1,64}$/;
const MAX_MESSAGES = 24;
const MAX_TOOLS = 16;
const MAX_CONTENT_CHARS = 8000;

function isPlainObject(val) {
  if (!val || typeof val !== 'object' || Array.isArray(val)) {
    return false;
  }
  const proto = Object.getPrototypeOf(val);
  return proto === Object.prototype || proto === null;
}

function checkJsonDepth(val, depth = 0) {
  if (depth > 8) return false;
  if (val === null || typeof val !== 'object') return true;
  if (Array.isArray(val)) {
    if (val.length > 64) return false;
    return val.every((item) => checkJsonDepth(item, depth + 1));
  }
  const keys = Object.keys(val);
  if (keys.length > 64) return false;
  return keys.every((k) => checkJsonDepth(val[k], depth + 1));
}

function sendJson(res, status, body, corsHeaders = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...corsHeaders
  });
  res.end(payload);
}

function validateRouterPayload(raw, expectedModel) {
  if (!isPlainObject(raw)) {
    return { ok: false, code: 'INVALID_BODY', message: 'Request body must be a JSON object.' };
  }
  for (const key of Object.keys(raw)) {
    if (!ALLOWED_TOP_KEYS.has(key)) {
      return { ok: false, code: 'UNSUPPORTED_FIELD', message: `Unsupported field: ${key}.` };
    }
  }
  if (typeof raw.model !== 'string' || raw.model !== expectedModel) {
    return { ok: false, code: 'INVALID_MODEL', message: 'Model does not match configured router model.' };
  }

  let maxTokens = MAX_ROUTER_TOKENS;
  if (raw.max_tokens !== undefined) {
    if (!Number.isInteger(raw.max_tokens) || raw.max_tokens < 1 || raw.max_tokens > MAX_ROUTER_TOKENS) {
      return {
        ok: false,
        code: 'INVALID_MAX_TOKENS',
        message: `max_tokens must be an integer between 1 and ${MAX_ROUTER_TOKENS}.`
      };
    }
    maxTokens = raw.max_tokens;
  }

  let temperature;
  if (raw.temperature !== undefined) {
    if (typeof raw.temperature !== 'number' || !Number.isFinite(raw.temperature) || raw.temperature < 0 || raw.temperature > 2) {
      return { ok: false, code: 'INVALID_TEMPERATURE', message: 'temperature must be between 0 and 2.' };
    }
    temperature = raw.temperature;
  }

  let stream = false;
  if (raw.stream !== undefined) {
    if (typeof raw.stream !== 'boolean') {
      return { ok: false, code: 'INVALID_STREAM', message: 'stream must be a boolean.' };
    }
    stream = raw.stream;
  }

  if (!Array.isArray(raw.messages) || raw.messages.length === 0 || raw.messages.length > MAX_MESSAGES) {
    return { ok: false, code: 'INVALID_MESSAGES', message: 'messages must be a bounded non-empty array.' };
  }

  const messages = [];
  for (const msg of raw.messages) {
    if (!isPlainObject(msg)) {
      return { ok: false, code: 'INVALID_MESSAGES', message: 'Each message must be an object.' };
    }
    for (const k of Object.keys(msg)) {
      if (!ALLOWED_MESSAGE_KEYS.has(k)) {
        return { ok: false, code: 'INVALID_MESSAGES', message: `Unsupported message key: ${k}.` };
      }
    }
    if (typeof msg.role !== 'string' || !ALLOWED_ROLES.has(msg.role)) {
      return { ok: false, code: 'INVALID_MESSAGES', message: 'Invalid message role.' };
    }
    const cleanMsg = { role: msg.role };
    if (typeof msg.content === 'string') {
      if (msg.content.length > MAX_CONTENT_CHARS) {
        return { ok: false, code: 'INVALID_MESSAGES', message: 'Message content exceeds length limit.' };
      }
      cleanMsg.content = msg.content;
    } else if (msg.content === null && msg.role === 'assistant') {
      cleanMsg.content = null;
    } else if (Array.isArray(msg.content) && msg.content.length > 0 && msg.content.length <= 8) {
      const parts = [];
      for (const part of msg.content) {
        if (!isPlainObject(part) || part.type !== 'text' || typeof part.text !== 'string' || part.text.length > MAX_CONTENT_CHARS) {
          return { ok: false, code: 'INVALID_MESSAGES', message: 'Invalid structured message content.' };
        }
        parts.push({ type: 'text', text: part.text });
      }
      cleanMsg.content = parts;
    } else {
      return { ok: false, code: 'INVALID_MESSAGES', message: 'Invalid message content.' };
    }

    if (msg.name !== undefined) {
      if (typeof msg.name !== 'string' || !TOOL_NAME_RE.test(msg.name)) {
        return { ok: false, code: 'INVALID_MESSAGES', message: 'Invalid message name.' };
      }
      cleanMsg.name = msg.name;
    }
    if (msg.tool_call_id !== undefined) {
      if (typeof msg.tool_call_id !== 'string' || msg.tool_call_id.length === 0 || msg.tool_call_id.length > 128) {
        return { ok: false, code: 'INVALID_MESSAGES', message: 'Invalid tool_call_id.' };
      }
      cleanMsg.tool_call_id = msg.tool_call_id;
    }
    if (msg.tool_calls !== undefined) {
      if (msg.role !== 'assistant' || !Array.isArray(msg.tool_calls) || msg.tool_calls.length > 8 || !checkJsonDepth(msg.tool_calls)) {
        return { ok: false, code: 'INVALID_MESSAGES', message: 'Invalid assistant tool_calls.' };
      }
      cleanMsg.tool_calls = msg.tool_calls;
    }
    messages.push(cleanMsg);
  }

  const cleanBody = {
    model: expectedModel,
    messages,
    max_tokens: maxTokens,
    stream
  };
  if (temperature !== undefined) {
    cleanBody.temperature = temperature;
  }

  const declaredToolNames = new Set();
  if (raw.tools !== undefined) {
    if (!Array.isArray(raw.tools) || raw.tools.length === 0 || raw.tools.length > MAX_TOOLS) {
      return { ok: false, code: 'INVALID_TOOLS', message: 'tools must be a bounded non-empty array.' };
    }
    const tools = [];
    for (const tool of raw.tools) {
      if (!isPlainObject(tool)) {
        return { ok: false, code: 'INVALID_TOOLS', message: 'Each tool must be an object.' };
      }
      for (const k of Object.keys(tool)) {
        if (!ALLOWED_TOOL_KEYS.has(k)) {
          return { ok: false, code: 'INVALID_TOOLS', message: `Unsupported tool key: ${k}.` };
        }
      }
      if (tool.type !== 'function' || !isPlainObject(tool.function)) {
        return { ok: false, code: 'INVALID_TOOLS', message: 'Only function tools are permitted.' };
      }
      for (const fk of Object.keys(tool.function)) {
        if (!ALLOWED_FUNCTION_KEYS.has(fk)) {
          return { ok: false, code: 'INVALID_TOOLS', message: `Unsupported tool function key: ${fk}.` };
        }
      }
      if (typeof tool.function.name !== 'string' || !TOOL_NAME_RE.test(tool.function.name)) {
        return { ok: false, code: 'INVALID_TOOLS', message: 'Invalid tool function name.' };
      }
      declaredToolNames.add(tool.function.name);
      const cleanFn = { name: tool.function.name };
      if (tool.function.description !== undefined) {
        if (typeof tool.function.description !== 'string' || tool.function.description.length > 512) {
          return { ok: false, code: 'INVALID_TOOLS', message: 'Invalid tool function description.' };
        }
        cleanFn.description = tool.function.description;
      }
      if (tool.function.parameters !== undefined) {
        if (!isPlainObject(tool.function.parameters) || !checkJsonDepth(tool.function.parameters) || JSON.stringify(tool.function.parameters).length > 8192) {
          return { ok: false, code: 'INVALID_TOOLS', message: 'Invalid tool parameters schema.' };
        }
        cleanFn.parameters = tool.function.parameters;
      }
      if (tool.function.strict !== undefined) {
        if (typeof tool.function.strict !== 'boolean') {
          return { ok: false, code: 'INVALID_TOOLS', message: 'Invalid tool strict flag.' };
        }
        cleanFn.strict = tool.function.strict;
      }
      tools.push({ type: 'function', function: cleanFn });
    }
    cleanBody.tools = tools;
  }

  if (raw.tool_choice !== undefined) {
    if (typeof raw.tool_choice === 'string') {
      if (!['none', 'auto', 'required'].includes(raw.tool_choice)) {
        return { ok: false, code: 'INVALID_TOOL_CHOICE', message: 'Invalid tool_choice value.' };
      }
      cleanBody.tool_choice = raw.tool_choice;
    } else if (isPlainObject(raw.tool_choice)) {
      if (
        raw.tool_choice.type !== 'function' ||
        !isPlainObject(raw.tool_choice.function) ||
        typeof raw.tool_choice.function.name !== 'string' ||
        !declaredToolNames.has(raw.tool_choice.function.name)
      ) {
        return { ok: false, code: 'INVALID_TOOL_CHOICE', message: 'tool_choice must reference a declared tool.' };
      }
      cleanBody.tool_choice = {
        type: 'function',
        function: { name: raw.tool_choice.function.name }
      };
    } else {
      return { ok: false, code: 'INVALID_TOOL_CHOICE', message: 'Invalid tool_choice.' };
    }
  }

  return { ok: true, payload: cleanBody };
}

async function readBoundedJson(req, maxBytes) {
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
    const text = Buffer.concat(chunks).toString('utf8');
    return { ok: true, body: JSON.parse(text) };
  } catch {
    return { ok: false, status: 400, code: 'INVALID_JSON', message: 'Malformed JSON body.' };
  }
}

/**
 * Create the optional bounded Otari chat-completions router.
 * Uses browser-runtime fixture mock signaling when disabled, and enforces
 * strict schema, exact model, token cap, stripped client Authorization, and durable budget when enabled.
 */
export function createRouter({
  apiKey,
  model,
  buyerOrigin,
  ledger = null,
  fetchImpl = globalThis.fetch,
  timeoutMs = 15000,
  maxOutputBytes = 256 * 1024,
  maxBodyBytes = 32 * 1024,
  fixtureOnly = false
}) {
  if (typeof buyerOrigin !== 'string' || !buyerOrigin) {
    throw new TypeError('createRouter requires buyerOrigin');
  }
  const configuredKey = typeof apiKey === 'string' && apiKey.trim() ? apiKey.trim() : null;
  const configuredModel = typeof model === 'string' && model.trim() ? model.trim() : null;
  const enabled = Boolean(configuredKey && configuredModel);
  const mode = enabled ? 'provider' : 'fixture';

  function buildCorsHeaders(req) {
    const origin = req.headers.origin;
    if (!origin) {
      return { valid: true, headers: {} };
    }
    if (origin !== buyerOrigin) {
      return { valid: false, headers: {} };
    }
    return {
      valid: true,
      headers: {
        'Access-Control-Allow-Origin': buyerOrigin,
        'Vary': 'Origin',
        'Access-Control-Allow-Credentials': 'true'
      }
    };
  }

  async function handleRequest(req, res, { session = 'router-session' } = {}) {
    const cors = buildCorsHeaders(req);
    if (!cors.valid) {
      sendJson(res, 403, {
        error: { code: 'FORBIDDEN_ORIGIN', message: 'Origin not permitted.' }
      });
      return;
    }

    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        ...cors.headers,
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
      });
      res.end();
      return;
    }

    if (req.method !== 'POST') {
      sendJson(
        res,
        405,
        { error: { code: 'METHOD_NOT_ALLOWED', message: 'Only POST is supported.' } },
        cors.headers
      );
      return;
    }

    if (!enabled) {
      sendJson(
        res,
        503,
        {
          error: {
            code: 'ROUTER_DISABLED_FIXTURE_MODE',
            mode: 'fixture',
            message: 'Router provider mode is disabled; client should use browser-runtime fixture mock.'
          }
        },
        cors.headers
      );
      return;
    }

    if (!ledger || typeof fetchImpl !== 'function') {
      sendJson(
        res,
        503,
        {
          error: {
            code: 'ROUTER_UNCONFIGURED',
            message: 'Router ledger or fetch transport is unavailable.'
          }
        },
        cors.headers
      );
      return;
    }

    const parsed = await readBoundedJson(req, maxBodyBytes);
    if (!parsed.ok) {
      sendJson(res, parsed.status, { error: { code: parsed.code, message: parsed.message } }, cors.headers);
      return;
    }

    const validated = validateRouterPayload(parsed.body, configuredModel);
    if (!validated.ok) {
      sendJson(res, 400, { error: { code: validated.code, message: validated.message } }, cors.headers);
      return;
    }

    if (fixtureOnly) {
      const prompt = /^Read fictional quote for EQ-CRIT-01 x1 us-west in case (initial|unchanged|unrelated|delay|unavailable)[.]$/;
      const knownTools = new Set(['relay_supplier', 'fulfillment_agent', 'mcp_get_quote_snapshot', 'website_read_workflow']);
      const messages = validated.payload.messages;
      const requests = messages.filter(message => message.role === 'user');
      const hasUnexpectedTool = (validated.payload.tools ?? []).some(tool => !knownTools.has(tool.function.name));
      if (requests.length !== 1 || typeof requests[0].content !== 'string' || !prompt.test(requests[0].content) ||
          hasUnexpectedTool || messages.length > 14) {
        sendJson(res, 400, { error: { code: 'OUTSIDE_RELAY_CASE', message: 'Request is outside the fictional relay case.' } }, cors.headers);
        return;
      }
    }

    const idempotencyKey = `router-${crypto.randomUUID()}`;
    const reserve = adaptLedgerReserve(await ledger.reserve({ session, idempotencyKey }));
    if (!reserve.ok) {
      sendJson(
        res,
        429,
        {
          error: {
            code: reserve.code || 'ROUTER_BUDGET_EXCEEDED',
            message: 'Router budget limit or UTC cutoff exceeded.'
          }
        },
        cors.headers
      );
      return;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error('ROUTER_TIMEOUT')), timeoutMs);

    try {
      // Strip any incoming Authorization header and forward only server-owned bearer credentials.
      const upstreamRes = await fetchImpl(OTARI_UPSTREAM_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${configuredKey}`,
          'Accept': validated.payload.stream ? 'text/event-stream' : 'application/json'
        },
        body: JSON.stringify(validated.payload),
        signal: controller.signal
      });

      if (!upstreamRes.ok) {
        try {
          await ledger.result(idempotencyKey, 'refused');
        } catch {
          // Best-effort ledger update.
        }
        sendJson(
          res,
          upstreamRes.status >= 400 && upstreamRes.status < 500 ? 400 : 502,
          {
            error: {
              code: 'ROUTER_UPSTREAM_ERROR',
              status: upstreamRes.status,
              message: 'Upstream router provider rejected or failed the request.'
            }
          },
          cors.headers
        );
        return;
      }

      const upstreamType = String(upstreamRes.headers?.get?.('content-type') ?? '').toLowerCase();
      const isSse = validated.payload.stream || upstreamType.includes('text/event-stream');

      if (isSse && upstreamRes.body && typeof upstreamRes.body.getReader === 'function') {
        res.writeHead(200, {
          'Content-Type': 'text/event-stream; charset=utf-8',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
          'X-Content-Type-Options': 'nosniff',
          ...cors.headers
        });
        const reader = upstreamRes.body.getReader();
        let totalBytes = 0;
        let truncated = false;
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          totalBytes += value.byteLength;
          if (totalBytes > maxOutputBytes) {
            truncated = true;
            controller.abort(new Error('ROUTER_OUTPUT_LIMIT_EXCEEDED'));
            break;
          }
          res.write(value);
        }
        if (truncated) {
          try {
            await ledger.result(idempotencyKey, 'unknown');
          } catch {
            // Best-effort ledger update.
          }
          res.write('event: error\ndata: {"code":"ROUTER_OUTPUT_LIMIT_EXCEEDED"}\n\n');
          res.end();
          return;
        }
        try {
          await ledger.result(idempotencyKey, 'selected');
        } catch {
          // Best-effort ledger update.
        }
        res.end();
        return;
      }

      const text = await upstreamRes.text();
      if (Buffer.byteLength(text, 'utf8') > maxOutputBytes) {
        try {
          await ledger.result(idempotencyKey, 'unknown');
        } catch {
          // Best-effort ledger update.
        }
        sendJson(
          res,
          502,
          {
            error: {
              code: 'ROUTER_OUTPUT_LIMIT_EXCEEDED',
              message: 'Upstream router response exceeded output limit.'
            }
          },
          cors.headers
        );
        return;
      }

      try {
        await ledger.result(idempotencyKey, 'selected');
      } catch {
        // Best-effort ledger update.
      }
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        ...cors.headers
      });
      res.end(text);
    } catch (err) {
      try {
        await ledger.result(idempotencyKey, 'unknown');
      } catch {
        // Best-effort ledger update.
      }
      const timedOut = err?.name === 'AbortError' || controller.signal.aborted;
      sendJson(
        res,
        timedOut ? 504 : 502,
        {
          error: {
            code: timedOut ? 'ROUTER_TIMEOUT' : 'ROUTER_NETWORK_ERROR',
            message: timedOut ? 'Router upstream request timed out.' : 'Router upstream request failed.'
          }
        },
        cors.headers
      );
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    mode,
    enabled,
    model: configuredModel ?? 'fixture-browser-mock',
    handleRequest
  };
}
