import { spawn } from "node:child_process";
import dns from "node:dns/promises";
import net from "node:net";
import tls from "node:tls";
import { performance } from "node:perf_hooks";
import ipaddr from "ipaddr.js";

export const PORT_PRESETS = {
  quick: [22, 80, 443, 445, 3389, 8080, 8443, 53, 139, 21, 25, 110, 143, 587, 993, 995, 3306, 5432, 6379, 27017],
  web: [80, 443, 8080, 8443, 8000, 3000, 3001, 4200, 5000, 5173, 5601, 7001, 8008, 8081, 8888, 9000, 9443],
  infra: [21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 135, 137, 138, 139, 143, 161, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 9200, 9300, 11211, 27017],
  top100: [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427,
    443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
    1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
    5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888,
    9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157
  ]
};

const SERVICE_NAMES = new Map([
  [21, "FTP"],
  [22, "SSH"],
  [23, "Telnet"],
  [25, "SMTP"],
  [53, "DNS"],
  [80, "HTTP"],
  [110, "POP3"],
  [123, "NTP"],
  [135, "MS RPC"],
  [139, "NetBIOS"],
  [143, "IMAP"],
  [161, "SNMP"],
  [389, "LDAP"],
  [443, "HTTPS"],
  [445, "SMB"],
  [465, "SMTPS"],
  [587, "SMTP"],
  [636, "LDAPS"],
  [993, "IMAPS"],
  [995, "POP3S"],
  [1433, "MSSQL"],
  [1521, "Oracle"],
  [2049, "NFS"],
  [3000, "Dev HTTP"],
  [3306, "MySQL"],
  [3389, "RDP"],
  [5432, "Postgres"],
  [5601, "Kibana"],
  [5900, "VNC"],
  [5985, "WinRM"],
  [5986, "WinRM TLS"],
  [6379, "Redis"],
  [8000, "HTTP Alt"],
  [8080, "HTTP Proxy"],
  [8443, "HTTPS Alt"],
  [9200, "Elasticsearch"],
  [11211, "Memcached"],
  [27017, "MongoDB"]
]);

const TLS_PORTS = new Set([443, 465, 636, 993, 995, 8443, 9443, 5986]);
const HTTP_PORTS = new Set([80, 443, 8080, 8081, 8000, 8008, 8443, 8888, 9000, 9443, 3000, 3001, 4200, 5000, 5173, 5601]);
const ADMIN_PORTS = new Set([22, 23, 3389, 5900, 5985, 5986, 445, 139, 161, 6379, 9200, 11211, 27017]);

export async function runScan({ scanId, options, signal, emit }) {
  const startedAt = new Date();
  const scanOptions = normalizeOptions(options);
  const targets = await parseTargets(scanOptions.target);
  const ports = parsePorts(scanOptions);
  enforceScope({ targets, ports, options: scanOptions });

  const hosts = new Map(
    targets.map((target) => [
      target.ip,
      {
        ip: target.ip,
        input: target.input,
        hostname: target.hostname,
        reverseName: null,
        status: "unknown",
        latencyMs: null,
        openPorts: [],
        closedPorts: 0,
        filteredPorts: 0,
        riskScore: 0
      }
    ])
  );

  emit({
    type: "scan-started",
    payload: {
      scanId,
      startedAt: startedAt.toISOString(),
      options: scanOptions,
      totals: {
        hosts: targets.length,
        ports: ports.length,
        checks: targets.length * ports.length
      }
    }
  });

  emitLog(emit, scanId, "info", `Prepared ${targets.length} host(s) and ${ports.length} port(s).`);

  if (scanOptions.hostDiscovery) {
    await runPool(
      targets,
      Math.min(scanOptions.concurrency, 64),
      async (target) => {
        if (signal.aborted) return;
        const liveness = await pingHost(target.ip, Math.min(scanOptions.timeoutMs, 1000));
        const host = hosts.get(target.ip);
        if (!host) return;
        host.status = liveness.alive ? "up" : "silent";
        host.latencyMs = liveness.latencyMs;
        emit({
          type: "host-liveness",
          payload: {
            scanId,
            host: { ...host }
          }
        });
      },
      signal
    );
  }

  await runPool(
    targets,
    Math.min(scanOptions.concurrency, 48),
    async (target) => {
      if (signal.aborted) return;
      try {
        const result = await dns.reverse(target.ip);
        const host = hosts.get(target.ip);
        if (host && result.length > 0) {
          host.reverseName = result[0];
          emit({ type: "host-liveness", payload: { scanId, host: { ...host } } });
        }
      } catch {
        // Reverse DNS is optional signal.
      }
    },
    signal
  );

  let completed = 0;
  const totalChecks = targets.length * ports.length;
  const lastProgress = { time: 0 };

  const tasks = [];
  for (const target of targets) {
    for (const port of ports) {
      tasks.push({ target, port });
    }
  }

  await runPool(
    tasks,
    scanOptions.concurrency,
    async ({ target, port }) => {
      if (signal.aborted) return;
      const result = await scanPort(target.ip, port, scanOptions);
      completed += 1;

      const host = hosts.get(target.ip);
      if (host) {
        if (result.state === "open") {
          host.status = "up";
          host.openPorts.push(result);
          host.riskScore = scoreHost(host.openPorts);
          emit({
            type: "port-result",
            payload: {
              scanId,
              host: host.ip,
              result
            }
          });
        } else if (result.state === "closed") {
          host.closedPorts += 1;
        } else {
          host.filteredPorts += 1;
        }
      }

      const now = Date.now();
      if (now - lastProgress.time > 110 || completed === totalChecks) {
        lastProgress.time = now;
        emit({
          type: "scan-progress",
          payload: {
            scanId,
            completed,
            total: totalChecks,
            percent: totalChecks === 0 ? 100 : Math.round((completed / totalChecks) * 100)
          }
        });
      }
    },
    signal
  );

  const endedAt = new Date();
  const durationMs = endedAt.getTime() - startedAt.getTime();
  const finalHosts = Array.from(hosts.values()).map((host) => ({
    ...host,
    openPorts: host.openPorts.sort((a, b) => a.port - b.port)
  }));

  emit({
    type: "scan-complete",
    payload: {
      scanId,
      startedAt: startedAt.toISOString(),
      endedAt: endedAt.toISOString(),
      durationMs,
      cancelled: signal.aborted,
      hosts: finalHosts,
      summary: summarize(finalHosts, totalChecks, completed, durationMs)
    }
  });
}

function normalizeOptions(input = {}) {
  return {
    target: String(input.target || "").trim(),
    portMode: String(input.portMode || "quick"),
    customPorts: String(input.customPorts || "").trim(),
    timeoutMs: clamp(Number(input.timeoutMs || 900), 200, 5000),
    concurrency: clamp(Number(input.concurrency || 80), 1, 250),
    hostDiscovery: Boolean(input.hostDiscovery ?? true),
    bannerGrab: Boolean(input.bannerGrab ?? true),
    tlsInspect: Boolean(input.tlsInspect ?? true),
    authorized: Boolean(input.authorized),
    allowPublic: Boolean(input.allowPublic)
  };
}

function enforceScope({ targets, ports, options }) {
  if (!options.authorized) {
    throw new Error("Authorization confirmation is required before scanning.");
  }
  if (targets.length === 0) {
    throw new Error("Add at least one valid target.");
  }
  if (ports.length === 0) {
    throw new Error("Add at least one valid port.");
  }

  const publicTargets = targets.filter((target) => !isPrivateOrLocal(target.ip));
  if (publicTargets.length > 0 && !options.allowPublic) {
    throw new Error("Public targets require the public-scope opt-in.");
  }

  const maxHosts = publicTargets.length > 0 ? 32 : 512;
  const maxPorts = publicTargets.length > 0 ? 256 : 2000;
  const maxChecks = publicTargets.length > 0 ? 8192 : 90000;

  if (targets.length > maxHosts) {
    throw new Error(`Target list is too large for this safety profile. Limit: ${maxHosts} hosts.`);
  }
  if (ports.length > maxPorts) {
    throw new Error(`Port list is too large for this safety profile. Limit: ${maxPorts} ports.`);
  }
  if (targets.length * ports.length > maxChecks) {
    throw new Error(`Scan plan is too large. Limit: ${maxChecks} TCP checks.`);
  }
}

async function parseTargets(rawTarget) {
  if (!rawTarget) return [];
  const entries = rawTarget
    .split(/[\s,]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);

  const seen = new Set();
  const targets = [];

  for (const entry of entries) {
    const resolved = await resolveTargetEntry(entry);
    for (const target of resolved) {
      if (!seen.has(target.ip)) {
        seen.add(target.ip);
        targets.push(target);
      }
    }
  }

  return targets;
}

async function resolveTargetEntry(entry) {
  if (entry.includes("/")) {
    return expandCidr(entry).map((ip) => ({ ip, input: entry, hostname: null }));
  }

  if (entry.includes("-")) {
    return expandRange(entry).map((ip) => ({ ip, input: entry, hostname: null }));
  }

  if (isIPv4(entry)) {
    return [{ ip: entry, input: entry, hostname: null }];
  }

  const hostname = entry.toLowerCase();
  if (!/^[a-z0-9.-]+$/i.test(hostname)) {
    throw new Error(`Unsupported target: ${entry}`);
  }

  const records = await dns.lookup(hostname, { family: 4, all: true });
  if (records.length === 0) {
    throw new Error(`No IPv4 address found for ${entry}.`);
  }
  return records.map((record) => ({ ip: record.address, input: entry, hostname }));
}

function expandCidr(value) {
  const [addr, prefix] = ipaddr.IPv4.parseCIDR(value);
  const base = ipToLong(addr.toString());
  const hostCount = 2 ** (32 - prefix);
  if (hostCount > 65536) {
    throw new Error("CIDR range is too large. Use a narrower range.");
  }

  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (base & mask) >>> 0;
  const ips = [];
  const start = hostCount > 2 ? network + 1 : network;
  const end = hostCount > 2 ? network + hostCount - 2 : network + hostCount - 1;

  for (let valueLong = start; valueLong <= end; valueLong += 1) {
    ips.push(longToIp(valueLong >>> 0));
  }
  return ips;
}

function expandRange(value) {
  const [left, right] = value.split("-", 2).map((part) => part.trim());
  if (!isIPv4(left)) {
    throw new Error(`Invalid range start: ${left}`);
  }

  let endIp = right;
  if (/^\d{1,3}$/.test(right)) {
    const prefix = left.split(".").slice(0, 3).join(".");
    endIp = `${prefix}.${right}`;
  }

  if (!isIPv4(endIp)) {
    throw new Error(`Invalid range end: ${right}`);
  }

  const start = ipToLong(left);
  const end = ipToLong(endIp);
  if (end < start) {
    throw new Error(`Invalid descending range: ${value}`);
  }
  if (end - start > 65535) {
    throw new Error("IP range is too large. Use a narrower range.");
  }

  const ips = [];
  for (let current = start; current <= end; current += 1) {
    ips.push(longToIp(current >>> 0));
  }
  return ips;
}

function parsePorts(options) {
  if (options.portMode !== "custom") {
    return dedupeAndSort(PORT_PRESETS[options.portMode] || PORT_PRESETS.quick);
  }

  const chunks = options.customPorts
    .split(/[\s,]+/)
    .map((part) => part.trim())
    .filter(Boolean);

  const ports = [];
  for (const chunk of chunks) {
    if (chunk.includes("-")) {
      const [startRaw, endRaw] = chunk.split("-", 2);
      const start = Number(startRaw);
      const end = Number(endRaw);
      validatePort(start);
      validatePort(end);
      if (end < start) throw new Error(`Invalid port range: ${chunk}`);
      if (end - start > 5000) throw new Error(`Port range is too large: ${chunk}`);
      for (let port = start; port <= end; port += 1) ports.push(port);
    } else {
      const port = Number(chunk);
      validatePort(port);
      ports.push(port);
    }
  }
  return dedupeAndSort(ports);
}

async function scanPort(host, port, options) {
  if (options.tlsInspect && TLS_PORTS.has(port)) {
    const tlsResult = await tlsProbe(host, port, options);
    if (tlsResult.state !== "filtered" || tlsResult.errorCode !== "TLS_HANDSHAKE") {
      return tlsResult;
    }
  }
  return tcpProbe(host, port, options);
}

function tcpProbe(host, port, options) {
  return new Promise((resolve) => {
    const started = performance.now();
    const socket = net.createConnection({ host, port });
    let settled = false;
    let connected = false;
    let banner = "";
    let timer;

    const finish = (state, extra = {}) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      const latencyMs = Math.max(1, Math.round(performance.now() - started));
      resolve(classifyResult({ host, port, state, latencyMs, banner, ...extra }));
    };

    timer = setTimeout(() => finish("filtered", { errorCode: "TIMEOUT" }), options.timeoutMs);

    socket.once("connect", () => {
      connected = true;
      if (!options.bannerGrab) {
        finish("open");
        return;
      }

      const waitMs = Math.min(900, Math.max(240, Math.round(options.timeoutMs * 0.6)));
      const bannerTimer = setTimeout(() => finish("open"), waitMs);
      socket.once("close", () => finish("open"));
      socket.once("end", () => finish("open"));
      socket.on("data", (chunk) => {
        banner += sanitizeBanner(chunk);
        if (banner.length >= 260 || /(\r?\n){1,2}/.test(banner)) {
          clearTimeout(bannerTimer);
          finish("open");
        }
      });

      if (HTTP_PORTS.has(port)) {
        socket.write(`HEAD / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: SentinelScanner/0.1\r\nConnection: close\r\n\r\n`);
      }
    });

    socket.once("error", (error) => {
      const code = error?.code || "SOCKET_ERROR";
      if (connected) {
        finish("open", { errorCode: code });
        return;
      }
      finish(code === "ECONNREFUSED" ? "closed" : "filtered", { errorCode: code });
    });
  });
}

function tlsProbe(host, port, options) {
  return new Promise((resolve) => {
    const started = performance.now();
    const socket = tls.connect({
      host,
      port,
      servername: isPrivateOrLocal(host) ? undefined : host,
      rejectUnauthorized: false,
      timeout: options.timeoutMs
    });
    let settled = false;
    let connected = false;
    let banner = "";
    let timer;

    const finish = (state, extra = {}) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      const latencyMs = Math.max(1, Math.round(performance.now() - started));
      resolve(classifyResult({ host, port, state, latencyMs, banner, ...extra }));
    };

    timer = setTimeout(() => finish("filtered", { errorCode: "TIMEOUT" }), options.timeoutMs);

    socket.once("secureConnect", () => {
      connected = true;
      const cert = socket.getPeerCertificate();
      const tlsInfo = {
        authorized: socket.authorized,
        protocol: socket.getProtocol(),
        cipher: socket.getCipher()?.standardName || socket.getCipher()?.name || null,
        subject: cert?.subject?.CN || null,
        issuer: cert?.issuer?.CN || null,
        validFrom: cert?.valid_from || null,
        validTo: cert?.valid_to || null
      };

      if (!options.bannerGrab || !HTTP_PORTS.has(port)) {
        finish("open", { tls: tlsInfo });
        return;
      }

      const waitMs = Math.min(1000, Math.max(260, Math.round(options.timeoutMs * 0.7)));
      const bannerTimer = setTimeout(() => finish("open", { tls: tlsInfo }), waitMs);
      socket.on("data", (chunk) => {
        banner += sanitizeBanner(chunk);
        if (banner.length >= 320 || /(\r?\n){1,2}/.test(banner)) {
          clearTimeout(bannerTimer);
          finish("open", { tls: tlsInfo });
        }
      });
      socket.write(`HEAD / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: SentinelScanner/0.1\r\nConnection: close\r\n\r\n`);
    });

    socket.once("timeout", () => finish("filtered", { errorCode: "TIMEOUT" }));
    socket.once("error", (error) => {
      const code = error?.code || "TLS_HANDSHAKE";
      if (connected) {
        finish("open", { errorCode: code });
        return;
      }
      finish(code === "ECONNREFUSED" ? "closed" : "filtered", { errorCode: code === "ECONNREFUSED" ? code : "TLS_HANDSHAKE" });
    });
  });
}

function classifyResult(input) {
  const banner = input.banner ? input.banner.slice(0, 500) : "";
  const inferred = inferService(input.port, banner, input.tls);
  const risk = riskForPort(input.port, inferred.name);
  return {
    host: input.host,
    port: input.port,
    protocol: "tcp",
    state: input.state,
    service: inferred.name,
    product: inferred.product,
    banner,
    latencyMs: input.latencyMs,
    errorCode: input.errorCode || null,
    tls: input.tls || null,
    risk,
    advice: adviceFor(input.port, inferred.name, risk)
  };
}

function inferService(port, banner, tlsInfo) {
  const normalized = banner.toLowerCase();
  if (banner.startsWith("SSH-")) {
    return { name: "SSH", product: banner.split(/\s+/)[0] };
  }
  if (normalized.includes("http/") || normalized.includes("server:")) {
    const server = banner.match(/^server:\s*(.+)$/im)?.[1]?.trim() || null;
    return { name: tlsInfo ? "HTTPS" : "HTTP", product: server };
  }
  if (normalized.includes("smtp")) return { name: "SMTP", product: firstLine(banner) };
  if (normalized.includes("ftp")) return { name: "FTP", product: firstLine(banner) };
  if (normalized.includes("mysql")) return { name: "MySQL", product: firstLine(banner) };
  if (tlsInfo) return { name: SERVICE_NAMES.get(port) || "TLS Service", product: tlsInfo.subject };
  return { name: SERVICE_NAMES.get(port) || "Unknown", product: firstLine(banner) || null };
}

function riskForPort(port, service) {
  if (ADMIN_PORTS.has(port)) return "elevated";
  if (/telnet/i.test(service)) return "critical";
  if (/http|https/i.test(service)) return "medium";
  if ([25, 53, 123, 389, 636].includes(port)) return "medium";
  return "low";
}

function adviceFor(port, service, risk) {
  if (risk === "critical") return "Replace plaintext remote administration with encrypted access.";
  if ([3389, 5900, 5985, 5986].includes(port)) return "Restrict remote administration to trusted networks or VPN.";
  if ([445, 139].includes(port)) return "Avoid exposing file sharing beyond trusted LAN segments.";
  if ([6379, 9200, 11211, 27017].includes(port)) return "Bind data services privately and require authentication.";
  if (/http|https/i.test(service)) return "Review TLS, headers, and application ownership.";
  if (port === 22) return "Use key-based auth and allowlist management sources.";
  return "Confirm ownership and intended exposure.";
}

function scoreHost(openPorts) {
  return openPorts.reduce((score, port) => {
    if (port.risk === "critical") return score + 35;
    if (port.risk === "elevated") return score + 20;
    if (port.risk === "medium") return score + 10;
    return score + 3;
  }, 0);
}

function summarize(hosts, totalChecks, completed, durationMs) {
  const openPorts = hosts.reduce((sum, host) => sum + host.openPorts.length, 0);
  const liveHosts = hosts.filter((host) => host.status === "up").length;
  const elevatedHosts = hosts.filter((host) => host.riskScore >= 20).length;
  return {
    hosts: hosts.length,
    liveHosts,
    openPorts,
    elevatedHosts,
    totalChecks,
    completed,
    durationMs
  };
}

async function pingHost(host, timeoutMs) {
  const started = performance.now();
  const args = process.platform === "win32" ? ["-n", "1", "-w", String(timeoutMs), host] : ["-c", "1", "-W", String(Math.ceil(timeoutMs / 1000)), host];

  return new Promise((resolve) => {
    const child = spawn("ping", args, { windowsHide: true });
    const timer = setTimeout(() => {
      child.kill();
      resolve({ alive: false, latencyMs: null });
    }, timeoutMs + 300);

    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({
        alive: code === 0,
        latencyMs: code === 0 ? Math.max(1, Math.round(performance.now() - started)) : null
      });
    });

    child.on("error", () => {
      clearTimeout(timer);
      resolve({ alive: false, latencyMs: null });
    });
  });
}

async function runPool(items, limit, worker, signal) {
  let index = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    while (index < items.length && !signal.aborted) {
      const current = items[index];
      index += 1;
      await worker(current);
    }
  });
  await Promise.all(workers);
}

function emitLog(emit, scanId, level, text) {
  emit({
    type: "scan-log",
    payload: {
      scanId,
      level,
      text,
      timestamp: new Date().toISOString()
    }
  });
}

function validatePort(port) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid port: ${port}`);
  }
}

function dedupeAndSort(values) {
  return Array.from(new Set(values)).sort((a, b) => a - b);
}

function clamp(value, min, max) {
  if (Number.isNaN(value)) return min;
  return Math.min(max, Math.max(min, value));
}

function isIPv4(value) {
  return ipaddr.IPv4.isValid(value);
}

function ipToLong(ip) {
  return ip
    .split(".")
    .map(Number)
    .reduce((acc, octet) => ((acc << 8) + octet) >>> 0, 0);
}

function longToIp(long) {
  return [24, 16, 8, 0].map((shift) => (long >>> shift) & 255).join(".");
}

function isPrivateOrLocal(ip) {
  try {
    const range = ipaddr.parse(ip).range();
    return ["private", "loopback", "linkLocal", "uniqueLocal", "carrierGradeNat", "unspecified"].includes(range);
  } catch {
    return false;
  }
}

function sanitizeBanner(chunk) {
  return chunk
    .toString("utf-8")
    .replace(/[^\x09\x0a\x0d\x20-\x7e]/g, ".")
    .slice(0, 500);
}

function firstLine(value) {
  return value.split(/\r?\n/).find(Boolean)?.trim() || null;
}
