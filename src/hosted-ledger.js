import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const WINDOW_MS = 24 * 60 * 60 * 1000;
const MIN_TOTAL_LIMIT = 0;
const MAX_TOTAL_LIMIT = 100;
const DEFAULT_TOTAL_LIMIT = 20;
const MIN_WINDOW_LIMIT = 0;
const MAX_WINDOW_LIMIT = 20;
const DEFAULT_WINDOW_LIMIT = 4;
const MAX_CUTOFF_HORIZON_MS = 365 * 24 * 60 * 60 * 1000;

const MIN_IDENTIFIER_LEN = 16;
const MAX_IDENTIFIER_LEN = 128;
const MIN_DISTINCT_CHARS = 8;
const MIN_SHANNON_ENTROPY = 2.8;
const IDENTIFIER_RE = /^[A-Za-z0-9._~+/-]{16,128}$/;

const VALID_FINAL_STATUSES = new Set(["selected", "refused", "unknown", "rejected"]);

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function shannonEntropy(value) {
  const counts = new Map();
  for (const ch of value) {
    counts.set(ch, (counts.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function isHighEntropyIdentifier(value) {
  if (typeof value !== "string" || !IDENTIFIER_RE.test(value)) {
    return false;
  }
  if (value.length < MIN_IDENTIFIER_LEN || value.length > MAX_IDENTIFIER_LEN) {
    return false;
  }
  const distinct = new Set(value).size;
  if (distinct < MIN_DISTINCT_CHARS) {
    return false;
  }
  return shannonEntropy(value) >= MIN_SHANNON_ENTROPY;
}

function clampInt(value, min, max, fallback) {
  if (value === undefined) {
    return fallback;
  }
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return min;
  }
  return Math.min(Math.max(min, Math.floor(value)), max);
}

function parseAndClampCutoff(cutoff, currentMs) {
  let ms;
  if (cutoff instanceof Date) {
    ms = cutoff.getTime();
  } else if (typeof cutoff === "string") {
    ms = Date.parse(cutoff);
  } else if (typeof cutoff === "number") {
    ms = cutoff;
  } else {
    return 0;
  }
  if (!Number.isFinite(ms)) {
    return 0;
  }
  return Math.min(ms, currentMs + MAX_CUTOFF_HORIZON_MS);
}

function ensurePrivateFile(filePath) {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  if (fs.existsSync(filePath)) {
    const stat = fs.lstatSync(filePath);
    if (stat.isSymbolicLink() || !stat.isFile()) {
      throw new Error("LEDGER_INVALID_FILE");
    }
    fs.chmodSync(filePath, 0o600);
  } else {
    const fd = fs.openSync(filePath, fs.constants.O_CREAT | fs.constants.O_WRONLY | fs.constants.O_APPEND, 0o600);
    try {
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.chmodSync(filePath, 0o600);
  }
}

function appendRecordSync(filePath, record) {
  const payload = Buffer.from(`${JSON.stringify(record)}\n`, "utf8");
  const fd = fs.openSync(filePath, fs.constants.O_CREAT | fs.constants.O_WRONLY | fs.constants.O_APPEND, 0o600);
  try {
    let offset = 0;
    while (offset < payload.length) {
      offset += fs.writeSync(fd, payload, offset, payload.length - offset);
    }
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Creates a durable, append-only hosted evaluation budget ledger.
 *
 * Synchronous API: `createLedger`, `reserve`, `result`, and `status` are all
 * synchronous so reservation durability (`openSync` / `writeSync` / `fsyncSync`)
 * completes atomically before any remote dispatch begins.
 */
export function createLedger({
  file,
  totalLimit,
  cutoff,
  windowLimit = DEFAULT_WINDOW_LIMIT,
  now = Date.now,
  mode = "evaluate"
} = {}) {
  if (typeof file !== "string" || file.trim().length === 0) {
    throw new TypeError("file must be a non-empty path");
  }
  if (typeof now !== "function") {
    throw new TypeError("now must be a function");
  }

  const resolvedFile = path.resolve(file);
  const inferenceBudget = mode === "inference";
  const effectiveTotalLimit = clampInt(totalLimit, MIN_TOTAL_LIMIT, inferenceBudget ? 4096 : MAX_TOTAL_LIMIT, DEFAULT_TOTAL_LIMIT);
  const effectiveWindowLimit = clampInt(windowLimit, MIN_WINDOW_LIMIT, inferenceBudget ? 160 : MAX_WINDOW_LIMIT, DEFAULT_WINDOW_LIMIT);
  const startupMs = now();
  const effectiveCutoff = parseAndClampCutoff(cutoff, Number.isFinite(startupMs) ? startupMs : 0);

  ensurePrivateFile(resolvedFile);

  const reservations = new Map();
  const sessionTimestamps = new Map();
  let activeKeyHash = null;
  let recoveredUnknownCount = 0;

  const rawContent = fs.readFileSync(resolvedFile, "utf8");
  const lines = rawContent.split("\n");
  for (const line of lines) {
    if (line.length === 0) {
      continue;
    }
    let rec;
    try {
      rec = JSON.parse(line);
    } catch {
      throw new Error("LEDGER_CORRUPTED");
    }

    if (rec?.type === "reserve") {
      if (
        typeof rec.keyHash !== "string" ||
        typeof rec.sessionHash !== "string" ||
        typeof rec.ts !== "number" ||
        !Number.isFinite(rec.ts) ||
        reservations.has(rec.keyHash)
      ) {
        throw new Error("LEDGER_CORRUPTED");
      }
      reservations.set(rec.keyHash, {
        status: "pending",
        ts: rec.ts,
        sessionHash: rec.sessionHash
      });
      const history = sessionTimestamps.get(rec.sessionHash) ?? [];
      history.push(rec.ts);
      sessionTimestamps.set(rec.sessionHash, history);
      activeKeyHash = rec.keyHash;
    } else if (rec?.type === "result") {
      if (
        typeof rec.keyHash !== "string" ||
        !VALID_FINAL_STATUSES.has(rec.status) ||
        !reservations.has(rec.keyHash)
      ) {
        throw new Error("LEDGER_CORRUPTED");
      }
      const entry = reservations.get(rec.keyHash);
      entry.status = rec.status;
      if (rec.recovered === true) {
        recoveredUnknownCount += 1;
      }
      if (activeKeyHash === rec.keyHash) {
        activeKeyHash = null;
      }
    } else {
      throw new Error("LEDGER_CORRUPTED");
    }
  }

  // Recover any orphaned pending reservation as counted `unknown` on startup.
  for (const [keyHash, entry] of reservations.entries()) {
    if (entry.status === "pending") {
      const recoveryTs = Number.isFinite(now()) ? now() : entry.ts;
      appendRecordSync(resolvedFile, {
        type: "result",
        ts: recoveryTs,
        keyHash,
        status: "unknown",
        recovered: true
      });
      entry.status = "unknown";
      recoveredUnknownCount += 1;
      if (activeKeyHash === keyHash) {
        activeKeyHash = null;
      }
    }
  }
  activeKeyHash = null;

  function countSessionWindow(sessionHash, currentMs) {
    const history = sessionTimestamps.get(sessionHash);
    if (!history) {
      return 0;
    }
    const windowStart = currentMs - WINDOW_MS;
    let count = 0;
    for (const ts of history) {
      if (ts > windowStart && ts <= currentMs) {
        count += 1;
      }
    }
    return count;
  }

  function reserve({ session, idempotencyKey } = {}) {
    if (!isHighEntropyIdentifier(session) || !isHighEntropyIdentifier(idempotencyKey) || session === idempotencyKey) {
      return { ok: false, allowed: false, code: "INVALID_IDENTITY_OR_KEY" };
    }
    if (activeKeyHash !== null) {
      return { ok: false, allowed: false, code: "ACTIVE_IN_FLIGHT" };
    }

    const keyHash = sha256Hex(idempotencyKey);
    if (reservations.has(keyHash)) {
      return { ok: false, allowed: false, code: "DUPLICATE_IDEMPOTENCY_KEY" };
    }

    const currentMs = now();
    if (!Number.isFinite(currentMs) || currentMs >= effectiveCutoff) {
      return { ok: false, allowed: false, code: "CUTOFF_EXCEEDED" };
    }

    if (reservations.size >= effectiveTotalLimit) {
      return { ok: false, allowed: false, code: "TOTAL_LIMIT_EXCEEDED" };
    }

    const sessionHash = sha256Hex(session);
    const sessionWindowUsed = countSessionWindow(sessionHash, currentMs);
    if (sessionWindowUsed >= effectiveWindowLimit) {
      return { ok: false, allowed: false, code: "SESSION_WINDOW_LIMIT_EXCEEDED" };
    }

    appendRecordSync(resolvedFile, {
      type: "reserve",
      ts: currentMs,
      sessionHash,
      keyHash
    });

    reservations.set(keyHash, {
      status: "pending",
      ts: currentMs,
      sessionHash
    });
    const history = sessionTimestamps.get(sessionHash) ?? [];
    history.push(currentMs);
    sessionTimestamps.set(sessionHash, history);
    activeKeyHash = keyHash;

    return {
      ok: true,
      allowed: true,
      code: "RESERVED",
      remainingTotal: Math.max(0, effectiveTotalLimit - reservations.size),
      remainingWindow: Math.max(0, effectiveWindowLimit - (sessionWindowUsed + 1))
    };
  }

  function result(idempotencyKey, outcomeStatus) {
    if (typeof idempotencyKey !== "string" || idempotencyKey.length === 0) {
      return { ok: false, code: "INVALID_KEY" };
    }
    if (!VALID_FINAL_STATUSES.has(outcomeStatus)) {
      return { ok: false, code: "INVALID_STATUS" };
    }

    const keyHash = sha256Hex(idempotencyKey);
    const entry = reservations.get(keyHash);
    if (!entry) {
      return { ok: false, code: "UNKNOWN_IDEMPOTENCY_KEY" };
    }
    if (entry.status !== "pending") {
      return { ok: false, code: "ALREADY_FINALIZED" };
    }

    const currentMs = now();
    const ts = Number.isFinite(currentMs) ? currentMs : entry.ts;
    appendRecordSync(resolvedFile, {
      type: "result",
      ts,
      keyHash,
      status: outcomeStatus
    });

    entry.status = outcomeStatus;
    if (activeKeyHash === keyHash) {
      activeKeyHash = null;
    }

    return {
      ok: true,
      code: "RECORDED",
      status: outcomeStatus
    };
  }

  function status() {
    const counts = {
      pending: 0,
      selected: 0,
      refused: 0,
      unknown: 0,
      rejected: 0
    };
    for (const entry of reservations.values()) {
      if (Object.hasOwn(counts, entry.status)) {
        counts[entry.status] += 1;
      }
    }
    const currentMs = now();
    const totalUsed = reservations.size;

    return {
      active: activeKeyHash !== null,
      totalUsed,
      totalLimit: effectiveTotalLimit,
      totalRemaining: Math.max(0, effectiveTotalLimit - totalUsed),
      windowLimit: effectiveWindowLimit,
      windowSeconds: WINDOW_MS / 1000,
      cutoffAt: effectiveCutoff,
      cutoffReached: !Number.isFinite(currentMs) || currentMs >= effectiveCutoff,
      recoveredUnknownCount,
      counts
    };
  }

  return {
    reserve,
    result,
    status
  };
}
