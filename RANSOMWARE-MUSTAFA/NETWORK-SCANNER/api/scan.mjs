import { randomUUID } from "node:crypto";
import { runScan } from "../server/scanner.mjs";

const CLOUD_SCAN_ENABLED = process.env.ENABLE_CLOUD_SCANNER === "true";

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    res.status(405).json({ ok: false, message: "Method not allowed." });
    return;
  }

  const options = await readBody(req);

  if (!CLOUD_SCAN_ENABLED) {
    const result = createDemoResult(options);
    res.status(200).json({
      ok: true,
      mode: "cloud-demo",
      message: "Cloud demo mode is active. Live TCP scanning is available when running the app locally.",
      events: [
        {
          type: "scan-started",
          payload: {
            scanId: result.scanId,
            startedAt: result.startedAt,
            options,
            totals: { hosts: 1, ports: result.hosts[0].openPorts.length, checks: result.hosts[0].openPorts.length }
          }
        },
        {
          type: "scan-complete",
          payload: result
        }
      ],
      result
    });
    return;
  }

  const scanId = randomUUID();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20_000);
  const events = [];
  let result = null;

  try {
    await runScan({
      scanId,
      options,
      signal: controller.signal,
      emit: (event) => {
        events.push(event);
        if (event.type === "scan-complete") {
          result = event.payload;
        }
      }
    });

    res.status(200).json({ ok: true, mode: "cloud-live", events, result });
  } catch (error) {
    res.status(400).json({
      ok: false,
      mode: "cloud-live",
      message: error instanceof Error ? error.message : "Scan failed."
    });
  } finally {
    clearTimeout(timeout);
  }
}

async function readBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString("utf-8");
  return raw ? JSON.parse(raw) : {};
}

function createDemoResult(options = {}) {
  const now = new Date();
  const target = String(options.target || "demo.local").split(/[\s,]+/).find(Boolean) || "demo.local";
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(target);
  const ip = isIp ? target : "203.0.113.10";
  const hostname = isIp ? null : target;
  const ports = demoPorts(options);
  const openPorts = ports.map((port) => demoPort(ip, port));
  const host = {
    ip,
    input: target,
    hostname,
    reverseName: hostname,
    status: "up",
    latencyMs: 24,
    openPorts,
    closedPorts: Math.max(0, ports.length * 2),
    filteredPorts: 0,
    riskScore: openPorts.reduce((sum, item) => sum + (item.risk === "elevated" ? 20 : item.risk === "medium" ? 10 : 3), 0)
  };

  return {
    scanId: randomUUID(),
    startedAt: now.toISOString(),
    endedAt: new Date(now.getTime() + 420).toISOString(),
    durationMs: 420,
    cancelled: false,
    hosts: [host],
    summary: {
      hosts: 1,
      liveHosts: 1,
      openPorts: openPorts.length,
      elevatedHosts: host.riskScore >= 20 ? 1 : 0,
      totalChecks: ports.length,
      completed: ports.length,
      durationMs: 420
    }
  };
}

function demoPorts(options) {
  if (options.portMode === "web") return [80, 443, 8080];
  if (options.portMode === "infra") return [22, 80, 443, 5432];
  if (options.portMode === "custom") {
    return String(options.customPorts || "80,443")
      .split(/[\s,]+/)
      .map((item) => Number(item.split("-")[0]))
      .filter((port) => Number.isInteger(port) && port > 0 && port <= 65535)
      .slice(0, 4);
  }
  return [80, 443, 22];
}

function demoPort(host, port) {
  const service = port === 443 ? "HTTPS" : port === 22 ? "SSH" : port === 5432 ? "Postgres" : "HTTP";
  const risk = port === 22 || port === 5432 ? "elevated" : "medium";
  return {
    host,
    port,
    protocol: "tcp",
    state: "open",
    service,
    product: port === 443 ? "demo edge" : port === 22 ? "OpenSSH demo" : null,
    banner: service === "HTTP" ? "HTTP/1.1 200 OK\r\nServer: Sentinel cloud demo\r\n" : "",
    latencyMs: 24,
    errorCode: null,
    tls:
      port === 443
        ? {
            authorized: true,
            protocol: "TLSv1.3",
            cipher: "TLS_AES_256_GCM_SHA384",
            subject: "sentinel-demo.local",
            issuer: "Sentinel Demo CA",
            validFrom: "May 30 00:00:00 2026 GMT",
            validTo: "May 30 00:00:00 2027 GMT"
          }
        : null,
    risk,
    advice:
      port === 22 || port === 5432
        ? "Cloud demo signal: restrict administrative and data services to trusted networks."
        : "Cloud demo signal: review ownership, TLS, and headers before exposure."
  };
}
