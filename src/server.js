import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { runBenchmark, runComparison, runTamperProbes } from "./relay.js";

const SRC_DIR = path.dirname(fileURLToPath(import.meta.url));

const STATIC_ALLOWLIST = new Map([
  ["/", { file: "index.html", contentType: "text/html; charset=utf-8" }]
]);

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "Cache-Control": "no-store",
  "Referrer-Policy": "no-referrer"
};

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    ...SECURITY_HEADERS,
    "Content-Type": "application/json; charset=utf-8"
  });
  res.end(body);
}

function parseBoundedNumber(raw, name) {
  if (raw === undefined || raw === null || raw === "") {
    return undefined;
  }
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0 || n > 1000000) {
    throw new RangeError(`${name} must be a positive finite number <= 1000000`);
  }
  return n;
}

async function readJsonBody(req, maxBytes = 4096) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBytes) {
      const err = new Error("Request body too large");
      err.statusCode = 413;
      throw err;
    }
    chunks.push(chunk);
  }
  if (chunks.length === 0) {
    return {};
  }
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("Expected JSON object");
    }
    return parsed;
  } catch {
    const err = new Error("Invalid JSON body");
    err.statusCode = 400;
    throw err;
  }
}

export function createRelayServer() {
  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");

      if (req.method === "GET" && STATIC_ALLOWLIST.has(url.pathname)) {
        const entry = STATIC_ALLOWLIST.get(url.pathname);
        const html = await readFile(path.join(SRC_DIR, entry.file), "utf8");
        res.writeHead(200, {
          ...SECURITY_HEADERS,
          "Content-Type": entry.contentType,
          "Content-Security-Policy": "default-src 'self' 'unsafe-inline'"
        });
        res.end(html);
        return;
      }

      if (req.method === "GET" && url.pathname === "/health") {
        sendJson(res, 200, {
          ok: true,
          mode: "local-fixture-replay",
          outboundNetwork: false
        });
        return;
      }

      if (url.pathname === "/api/replay" && (req.method === "GET" || req.method === "POST")) {
        const params = req.method === "POST"
          ? await readJsonBody(req)
          : Object.fromEntries(url.searchParams.entries());
        const maxCost = parseBoundedNumber(params.maxCost, "maxCost");
        const maxDays = parseBoundedNumber(params.maxDays, "maxDays");
        const comparison = runComparison({ maxCost, maxDays });
        const tamperProbe = runTamperProbes({ maxCost, maxDays });
        sendJson(res, 200, { ...comparison, tamperProbe });
        return;
      }

      if (req.method === "GET" && url.pathname === "/api/benchmark") {
        const roundsRaw = url.searchParams.get("rounds");
        const rounds = roundsRaw ? parseBoundedNumber(roundsRaw, "rounds") : 200;
        if (!Number.isInteger(rounds) || rounds > 10000) {
          throw new RangeError("rounds must be an integer between 1 and 10000");
        }
        sendJson(res, 200, runBenchmark({ rounds }));
        return;
      }

      sendJson(res, 404, { error: "Not found" });
    } catch (err) {
      const statusCode = err instanceof RangeError ? 400 : (err.statusCode ?? 500);
      sendJson(res, statusCode, { error: err.message });
    }
  });
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const port = Number(process.env.PORT ?? 4173);
  const host = "127.0.0.1";
  const server = createRelayServer();
  server.listen(port, host, () => {
    process.stdout.write(`DeltaX Decision Relay listening on http://${host}:${port} (local-fixture-replay)\n`);
  });
}
