import {
  Activity,
  CheckCircle2,
  ChevronRight,
  Cpu,
  Download,
  FileJson,
  Gauge,
  Globe2,
  ListFilter,
  LockKeyhole,
  Network,
  Play,
  Radar,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Square,
  Timer,
  Wifi,
  WifiOff,
  XCircle
} from "lucide-react";
import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import type { HostResult, PortResult, Risk, ScanMeta, ScanOptions, ScanSummary, TimelineEntry } from "./types";

const defaultOptions: ScanOptions = {
  target: "127.0.0.1",
  portMode: "quick",
  customPorts: "22,80,443,3000,5173,8080",
  timeoutMs: 900,
  concurrency: 80,
  hostDiscovery: true,
  bannerGrab: true,
  tlsInspect: true,
  authorized: false,
  allowPublic: false
};

const initialMeta: ScanMeta = {
  scanId: null,
  status: "idle",
  startedAt: null,
  endedAt: null,
  completed: 0,
  total: 0,
  percent: 0,
  summary: null,
  error: null
};

const portModes = [
  { key: "quick", label: "Quick" },
  { key: "web", label: "Web" },
  { key: "infra", label: "Infra" },
  { key: "top100", label: "Top 100" },
  { key: "custom", label: "Custom" }
] as const;

function App() {
  const [options, setOptions] = useState<ScanOptions>(defaultOptions);
  const [meta, setMeta] = useState<ScanMeta>(initialMeta);
  const [hosts, setHosts] = useState<HostResult[]>([]);
  const [timeline, setTimeline] = useState<TimelineEntry[]>([
    makeTimeline("info", "Scanner ready. Authorization is required before a scan.")
  ]);
  const [connection, setConnection] = useState<"connecting" | "online" | "offline">("connecting");
  const [selectedHost, setSelectedHost] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const socketRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    let reconnectTimer: number | undefined;
    let stopped = false;

    const connect = () => {
      const protocol = window.location.protocol === "https:" ? "wss" : "ws";
      const socket = new WebSocket(`${protocol}://${window.location.host}/ws`);
      socketRef.current = socket;
      setConnection("connecting");

      socket.addEventListener("open", () => setConnection("online"));
      socket.addEventListener("close", () => {
        setConnection("offline");
        if (!stopped) {
          reconnectTimer = window.setTimeout(connect, 1200);
        }
      });
      socket.addEventListener("message", (event) => {
        const message = JSON.parse(event.data);
        handleServerMessage(message);
      });
    };

    connect();
    return () => {
      stopped = true;
      window.clearTimeout(reconnectTimer);
      socketRef.current?.close();
    };
  }, []);

  const handleServerMessage = (message: any) => {
    if (message.type === "hello") {
      addTimeline("success", "Realtime scanner channel online.");
      return;
    }

    if (message.type === "scan-started") {
      const payload = message.payload;
      setHosts([]);
      setSelectedHost(null);
      setMeta({
        scanId: payload.scanId,
        status: "running",
        startedAt: payload.startedAt,
        endedAt: null,
        completed: 0,
        total: payload.totals.checks,
        percent: 0,
        summary: null,
        error: null
      });
      setTimeline([
        makeTimeline("success", `Scan ${payload.scanId.slice(0, 8)} started.`),
        makeTimeline("info", `${payload.totals.hosts} host(s), ${payload.totals.ports} port(s), ${payload.totals.checks} TCP check(s).`)
      ]);
      return;
    }

    if (message.type === "host-liveness") {
      upsertHost(message.payload.host);
      return;
    }

    if (message.type === "port-result") {
      const result = message.payload.result as PortResult;
      upsertPortResult(message.payload.host, result);
      addTimeline(riskToTimeline(result.risk), `${result.host}:${result.port} open ${result.service}`);
      return;
    }

    if (message.type === "scan-progress") {
      const payload = message.payload;
      setMeta((current) => ({
        ...current,
        completed: payload.completed,
        total: payload.total,
        percent: payload.percent
      }));
      return;
    }

    if (message.type === "scan-log") {
      addTimeline(message.payload.level === "warn" ? "warn" : "info", message.payload.text);
      return;
    }

    if (message.type === "scan-error") {
      setMeta((current) => ({
        ...current,
        status: "error",
        error: message.payload.message
      }));
      addTimeline("error", message.payload.message);
      return;
    }

    if (message.type === "scan-complete") {
      const payload = message.payload;
      setHosts(payload.hosts);
      setMeta((current) => ({
        ...current,
        status: payload.cancelled ? "cancelled" : "complete",
        endedAt: payload.endedAt,
        completed: payload.summary.completed,
        total: payload.summary.totalChecks,
        percent: payload.summary.totalChecks === 0 ? 100 : Math.round((payload.summary.completed / payload.summary.totalChecks) * 100),
        summary: payload.summary
      }));
      addTimeline(payload.cancelled ? "warn" : "success", payload.cancelled ? "Scan cancelled." : "Scan complete.");
    }
  };

  const addTimeline = (level: TimelineEntry["level"], text: string) => {
    setTimeline((current) => [makeTimeline(level, text), ...current].slice(0, 80));
  };

  const upsertHost = (host: HostResult) => {
    setHosts((current) => {
      const index = current.findIndex((item) => item.ip === host.ip);
      if (index === -1) return [...current, host].sort(sortHosts);
      const next = [...current];
      next[index] = { ...next[index], ...host, openPorts: next[index].openPorts || host.openPorts || [] };
      return next.sort(sortHosts);
    });
  };

  const upsertPortResult = (hostIp: string, result: PortResult) => {
    setHosts((current) => {
      const index = current.findIndex((host) => host.ip === hostIp);
      const existing: HostResult =
        index === -1
          ? {
              ip: hostIp,
              input: hostIp,
              hostname: null,
              reverseName: null,
              status: "up",
              latencyMs: null,
              openPorts: [],
              closedPorts: 0,
              filteredPorts: 0,
              riskScore: 0
            }
          : current[index];

      const ports = [...existing.openPorts.filter((port) => port.port !== result.port), result].sort((a, b) => a.port - b.port);
      const updated = {
        ...existing,
        status: "up" as const,
        openPorts: ports,
        riskScore: scoreHost(ports)
      };
      const next = index === -1 ? [...current, updated] : current.map((host, hostIndex) => (hostIndex === index ? updated : host));
      return next.sort(sortHosts);
    });
  };

  const startScan = (event: FormEvent) => {
    event.preventDefault();
    if (meta.status === "running") return;

    if (socketRef.current?.readyState === WebSocket.OPEN) {
      socketRef.current.send(JSON.stringify({ type: "start-scan", payload: options }));
      return;
    }

    void runHttpScan();
  };

  const runHttpScan = async () => {
    const fallbackId = makeId();
    setHosts([]);
    setSelectedHost(null);
    setMeta({
      scanId: fallbackId,
      status: "running",
      startedAt: new Date().toISOString(),
      endedAt: null,
      completed: 0,
      total: 0,
      percent: 10,
      summary: null,
      error: null
    });
    setTimeline([makeTimeline("info", "Realtime channel unavailable. Using HTTP scan fallback.")]);

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(options)
      });
      const payload = await response.json();
      if (!response.ok || !payload.ok) {
        throw new Error(payload.message || "HTTP scan failed.");
      }

      const result = payload.result;
      if (!result) throw new Error("Scan completed without a result payload.");

      setHosts(result.hosts);
      setSelectedHost(result.hosts[0]?.ip || null);
      setMeta({
        scanId: result.scanId,
        status: result.cancelled ? "cancelled" : "complete",
        startedAt: result.startedAt,
        endedAt: result.endedAt,
        completed: result.summary.completed,
        total: result.summary.totalChecks,
        percent: 100,
        summary: result.summary,
        error: null
      });
      setTimeline([
        makeTimeline("success", result.cancelled ? "Scan cancelled." : "Scan complete."),
        ...(payload.message ? [makeTimeline("warn", payload.message)] : []),
        makeTimeline("info", `${result.summary.hosts} host(s), ${result.summary.openPorts} open port(s).`)
      ]);
    } catch (error) {
      const message = error instanceof Error ? error.message : "HTTP scan failed.";
      setMeta((current) => ({ ...current, status: "error", error: message, percent: 0 }));
      addTimeline("error", message);
    }
  };

  const cancelScan = () => {
    if (!meta.scanId) return;
    socketRef.current?.send(JSON.stringify({ type: "cancel-scan", payload: { scanId: meta.scanId } }));
  };

  const filteredHosts = useMemo(() => {
    const query = filter.trim().toLowerCase();
    if (!query) return hosts;
    return hosts.filter((host) => {
      const haystack = [
        host.ip,
        host.hostname,
        host.reverseName,
        host.status,
        ...host.openPorts.flatMap((port) => [String(port.port), port.service, port.product, port.banner])
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return haystack.includes(query);
    });
  }, [hosts, filter]);

  const selected = useMemo(() => {
    return hosts.find((host) => host.ip === selectedHost) || filteredHosts[0] || null;
  }, [hosts, selectedHost, filteredHosts]);

  const summary = useMemo(() => deriveSummary(hosts, meta), [hosts, meta]);
  const openPorts = useMemo(() => hosts.flatMap((host) => host.openPorts), [hosts]);
  const serviceMix = useMemo(() => getServiceMix(openPorts), [openPorts]);

  return (
    <div className="app-shell">
      <aside className="control-rail">
        <div className="brand-lockup">
          <div className="brand-mark">
            <Radar size={24} strokeWidth={2.2} />
          </div>
          <div>
            <h1>Sentinel</h1>
            <span>Network Scanner</span>
          </div>
        </div>

        <form className="scan-form" onSubmit={startScan}>
          <section className="control-section">
            <div className="section-title">
              <Network size={17} />
              <span>Target</span>
            </div>
            <label className="field-label" htmlFor="target">
              Scope
            </label>
            <input
              id="target"
              className="text-input"
              value={options.target}
              onChange={(event) => setOptions({ ...options, target: event.target.value })}
              placeholder="127.0.0.1 or 192.168.1.0/24"
              spellCheck={false}
            />

            <div className="toggle-grid">
              <Switch
                label="Authorized"
                checked={options.authorized}
                onChange={(authorized) => setOptions({ ...options, authorized })}
                icon={<ShieldCheck size={16} />}
              />
              <Switch
                label="Public scope"
                checked={options.allowPublic}
                onChange={(allowPublic) => setOptions({ ...options, allowPublic })}
                icon={<Globe2 size={16} />}
              />
            </div>
          </section>

          <section className="control-section">
            <div className="section-title">
              <SlidersHorizontal size={17} />
              <span>Profile</span>
            </div>
            <div className="segments" role="tablist" aria-label="Port profile">
              {portModes.map((mode) => (
                <button
                  key={mode.key}
                  type="button"
                  aria-label={`Port profile ${mode.label}`}
                  data-testid={`port-mode-${mode.key}`}
                  className={options.portMode === mode.key ? "segment is-active" : "segment"}
                  onClick={() => setOptions({ ...options, portMode: mode.key })}
                >
                  {mode.label}
                </button>
              ))}
            </div>
            {options.portMode === "custom" && (
              <>
                <label className="field-label" htmlFor="ports">
                  Ports
                </label>
                <input
                  id="ports"
                  className="text-input"
                  value={options.customPorts}
                  onChange={(event) => setOptions({ ...options, customPorts: event.target.value })}
                  placeholder="22,80,443,8000-8100"
                  spellCheck={false}
                />
              </>
            )}
          </section>

          <section className="control-section">
            <div className="section-title">
              <Gauge size={17} />
              <span>Engine</span>
            </div>
            <RangeControl
              label="Timeout"
              value={options.timeoutMs}
              min={200}
              max={5000}
              step={100}
              unit="ms"
              onChange={(timeoutMs) => setOptions({ ...options, timeoutMs })}
            />
            <RangeControl
              label="Concurrency"
              value={options.concurrency}
              min={1}
              max={250}
              step={1}
              unit=""
              onChange={(concurrency) => setOptions({ ...options, concurrency })}
            />

            <div className="toggle-grid">
              <Switch
                label="Discovery"
                checked={options.hostDiscovery}
                onChange={(hostDiscovery) => setOptions({ ...options, hostDiscovery })}
                icon={<Wifi size={16} />}
              />
              <Switch
                label="Banners"
                checked={options.bannerGrab}
                onChange={(bannerGrab) => setOptions({ ...options, bannerGrab })}
                icon={<ListFilter size={16} />}
              />
              <Switch
                label="TLS"
                checked={options.tlsInspect}
                onChange={(tlsInspect) => setOptions({ ...options, tlsInspect })}
                icon={<LockKeyhole size={16} />}
              />
            </div>
          </section>

          <div className="action-row">
            <button className="primary-action" type="submit" disabled={meta.status === "running"}>
              <Play size={18} fill="currentColor" />
              <span>Launch</span>
            </button>
            <button className="icon-action danger" type="button" onClick={cancelScan} disabled={meta.status !== "running"} title="Cancel scan">
              <Square size={18} fill="currentColor" />
            </button>
          </div>
        </form>

        <div className="connection-chip" data-state={connection}>
          {connection === "online" ? <CheckCircle2 size={16} /> : connection === "connecting" ? <Activity size={16} /> : <XCircle size={16} />}
          <span>{connection === "offline" ? "api fallback" : connection}</span>
        </div>
      </aside>

      <main className="workspace">
        <StatusStrip summary={summary} meta={meta} />

        {meta.error && (
          <div className="error-ribbon">
            <ShieldAlert size={17} />
            <span>{meta.error}</span>
          </div>
        )}

        <div className="dashboard-grid">
          <section className="panel topology-panel">
            <PanelHeader icon={<Network size={18} />} title="Topology" right={<ProgressDial percent={meta.percent} status={meta.status} />} />
            <TopologyView hosts={filteredHosts} status={meta.status} onSelect={setSelectedHost} selectedHost={selected?.ip || null} />
          </section>

          <section className="panel signal-panel">
            <PanelHeader icon={<Cpu size={18} />} title="Signal" />
            <ServiceMix mix={serviceMix} />
            <RiskStack hosts={hosts} />
          </section>

          <section className="panel host-panel">
            <PanelHeader
              icon={<Server size={18} />}
              title="Hosts"
              right={
                <label className="search-box">
                  <Search size={15} />
                  <input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter" />
                </label>
              }
            />
            <HostTable hosts={filteredHosts} selected={selected?.ip || null} onSelect={setSelectedHost} />
          </section>

          <section className="panel detail-panel">
            <PanelHeader
              icon={<ShieldCheck size={18} />}
              title="Inspector"
              right={<ExportActions hosts={hosts} meta={meta} options={options} />}
            />
            <HostInspector host={selected} />
          </section>

          <section className="panel timeline-panel">
            <PanelHeader icon={<Activity size={18} />} title="Timeline" />
            <Timeline entries={timeline} />
          </section>
        </div>
      </main>
    </div>
  );
}

function StatusStrip({ summary, meta }: { summary: ScanSummary; meta: ScanMeta }) {
  const elapsed = meta.startedAt ? formatDuration((meta.endedAt ? new Date(meta.endedAt).getTime() : Date.now()) - new Date(meta.startedAt).getTime()) : "0s";
  return (
    <header className="status-strip">
      <div className="status-title">
        <span className={`scan-dot ${meta.status}`} />
        <div>
          <strong>{statusLabel(meta.status)}</strong>
          <span>{meta.scanId ? meta.scanId.slice(0, 8) : "no active scan"}</span>
        </div>
      </div>
      <Metric icon={<Server size={17} />} label="Hosts" value={summary.hosts} />
      <Metric icon={<Wifi size={17} />} label="Live" value={summary.liveHosts} />
      <Metric icon={<ShieldAlert size={17} />} label="Open" value={summary.openPorts} />
      <Metric icon={<Gauge size={17} />} label="Risk" value={summary.elevatedHosts} />
      <Metric icon={<Timer size={17} />} label="Elapsed" value={elapsed} />
    </header>
  );
}

function Metric({ icon, label, value }: { icon: React.ReactNode; label: string; value: string | number }) {
  return (
    <div className="metric">
      <div className="metric-icon">{icon}</div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
    </div>
  );
}

function PanelHeader({ icon, title, right }: { icon: React.ReactNode; title: string; right?: React.ReactNode }) {
  return (
    <div className="panel-header">
      <div>
        {icon}
        <h2>{title}</h2>
      </div>
      {right}
    </div>
  );
}

function TopologyView({
  hosts,
  selectedHost,
  status,
  onSelect
}: {
  hosts: HostResult[];
  selectedHost: string | null;
  status: ScanMeta["status"];
  onSelect: (host: string) => void;
}) {
  const nodes = useMemo(() => {
    const count = Math.max(hosts.length, 1);
    const centerX = 50;
    const centerY = 49;
    const radius = count < 6 ? 30 : 36;
    return hosts.map((host, index) => {
      const angle = (Math.PI * 2 * index) / count - Math.PI / 2;
      const weight = Math.min(8, 4 + host.openPorts.length * 0.9);
      return {
        host,
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius * 0.72,
        r: weight
      };
    });
  }, [hosts]);

  return (
    <div className="topology-stage">
      <svg viewBox="0 0 100 100" role="img" aria-label="Network topology">
        <defs>
          <filter id="nodeGlow" x="-30%" y="-30%" width="160%" height="160%">
            <feGaussianBlur stdDeviation="1.3" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        <g className="grid-rings">
          <circle cx="50" cy="49" r="37" />
          <circle cx="50" cy="49" r="24" />
          <line x1="12" x2="88" y1="49" y2="49" />
          <line x1="50" x2="50" y1="16" y2="82" />
        </g>
        {nodes.map((node) => (
          <line
            key={`link-${node.host.ip}`}
            className={`topology-link ${node.host.openPorts.length ? "is-open" : ""}`}
            x1="50"
            y1="49"
            x2={node.x}
            y2={node.y}
          />
        ))}
        <g className={`scanner-core ${status === "running" ? "is-running" : ""}`}>
          <circle cx="50" cy="49" r="9.5" />
          <circle cx="50" cy="49" r="4.1" />
        </g>
        {nodes.map((node) => (
          <g key={node.host.ip} className="topology-node-wrap" onClick={() => onSelect(node.host.ip)}>
            <circle
              className={`topology-node risk-${hostRisk(node.host)} ${selectedHost === node.host.ip ? "is-selected" : ""}`}
              cx={node.x}
              cy={node.y}
              r={node.r}
              filter="url(#nodeGlow)"
            />
            <text x={node.x} y={node.y + node.r + 5.2} textAnchor="middle">
              {node.host.ip.split(".").slice(-2).join(".")}
            </text>
          </g>
        ))}
      </svg>
      {hosts.length === 0 && (
        <div className="empty-state">
          <Radar size={26} />
          <span>Awaiting scan data</span>
        </div>
      )}
    </div>
  );
}

function ServiceMix({ mix }: { mix: Array<{ service: string; count: number }> }) {
  if (mix.length === 0) {
    return (
      <div className="quiet-block">
        <WifiOff size={22} />
        <span>No services detected yet</span>
      </div>
    );
  }

  const max = Math.max(...mix.map((item) => item.count), 1);
  return (
    <div className="service-mix">
      {mix.slice(0, 7).map((item) => (
        <div className="bar-row" key={item.service}>
          <span>{item.service}</span>
          <div className="bar-track">
            <div style={{ width: `${Math.max(10, (item.count / max) * 100)}%` }} />
          </div>
          <strong>{item.count}</strong>
        </div>
      ))}
    </div>
  );
}

function RiskStack({ hosts }: { hosts: HostResult[] }) {
  const bands = [
    { label: "Critical", value: hosts.filter((host) => hostRisk(host) === "critical").length, className: "critical" },
    { label: "Elevated", value: hosts.filter((host) => hostRisk(host) === "elevated").length, className: "elevated" },
    { label: "Medium", value: hosts.filter((host) => hostRisk(host) === "medium").length, className: "medium" },
    { label: "Low", value: hosts.filter((host) => hostRisk(host) === "low").length, className: "low" }
  ];

  return (
    <div className="risk-stack">
      {bands.map((band) => (
        <div className="risk-pill" key={band.label}>
          <span className={band.className} />
          <label>{band.label}</label>
          <strong>{band.value}</strong>
        </div>
      ))}
    </div>
  );
}

function HostTable({ hosts, selected, onSelect }: { hosts: HostResult[]; selected: string | null; onSelect: (host: string) => void }) {
  if (hosts.length === 0) {
    return (
      <div className="table-empty">
        <Server size={24} />
        <span>No hosts in view</span>
      </div>
    );
  }

  return (
    <div className="host-table">
      <div className="host-row host-head">
        <span>Host</span>
        <span>Status</span>
        <span>Open ports</span>
        <span>Risk</span>
      </div>
      {hosts.map((host) => (
        <button key={host.ip} className={`host-row ${selected === host.ip ? "is-selected" : ""}`} onClick={() => onSelect(host.ip)} type="button">
          <span className="host-identity">
            <strong>{host.ip}</strong>
            <small>{host.reverseName || host.hostname || host.input}</small>
          </span>
          <span className={`status-badge ${host.status}`}>{host.status}</span>
          <span className="port-pills">
            {host.openPorts.slice(0, 5).map((port) => (
              <span className={`port-pill risk-${port.risk}`} key={port.port}>
                {port.port}
              </span>
            ))}
            {host.openPorts.length > 5 && <span className="port-more">+{host.openPorts.length - 5}</span>}
            {host.openPorts.length === 0 && <span className="muted-text">none</span>}
          </span>
          <span className={`risk-badge risk-${hostRisk(host)}`}>{hostRisk(host)}</span>
        </button>
      ))}
    </div>
  );
}

function HostInspector({ host }: { host: HostResult | null }) {
  if (!host) {
    return (
      <div className="inspector-empty">
        <ShieldCheck size={26} />
        <span>Select a host</span>
      </div>
    );
  }

  return (
    <div className="inspector">
      <div className="inspector-hero">
        <div>
          <span className="eyebrow">Host</span>
          <h3>{host.ip}</h3>
          <p>{host.reverseName || host.hostname || host.input}</p>
        </div>
        <span className={`risk-badge risk-${hostRisk(host)}`}>{hostRisk(host)}</span>
      </div>

      <div className="mini-stats">
        <div>
          <span>Open</span>
          <strong>{host.openPorts.length}</strong>
        </div>
        <div>
          <span>Closed</span>
          <strong>{host.closedPorts}</strong>
        </div>
        <div>
          <span>Filtered</span>
          <strong>{host.filteredPorts}</strong>
        </div>
      </div>

      <div className="service-list">
        {host.openPorts.length === 0 && <div className="quiet-block">No open TCP ports captured</div>}
        {host.openPorts.map((port) => (
          <article className="service-item" key={port.port}>
            <div className="service-topline">
              <div>
                <strong>
                  {port.port}/tcp <span>{port.service}</span>
                </strong>
                <small>{port.product || "fingerprint pending"}</small>
              </div>
              <span className={`risk-badge risk-${port.risk}`}>{port.risk}</span>
            </div>
            {port.tls && (
              <div className="tls-strip">
                <LockKeyhole size={14} />
                <span>{[port.tls.protocol, port.tls.subject, port.tls.validTo].filter(Boolean).join(" / ")}</span>
              </div>
            )}
            {port.banner && <pre>{port.banner}</pre>}
            <p>{port.advice}</p>
          </article>
        ))}
      </div>
    </div>
  );
}

function Timeline({ entries }: { entries: TimelineEntry[] }) {
  return (
    <div className="timeline">
      {entries.map((entry) => (
        <div className={`timeline-entry ${entry.level}`} key={entry.id}>
          <span />
          <div>
            <strong>{formatClock(entry.timestamp)}</strong>
            <p>{entry.text}</p>
          </div>
        </div>
      ))}
    </div>
  );
}

function ExportActions({ hosts, meta, options }: { hosts: HostResult[]; meta: ScanMeta; options: ScanOptions }) {
  const disabled = hosts.length === 0;
  return (
    <div className="export-actions">
      <button
        type="button"
        className="icon-action"
        disabled={disabled}
        title="Export JSON"
        onClick={() => downloadJson({ meta, options, hosts }, `sentinel-scan-${Date.now()}.json`)}
      >
        <FileJson size={17} />
      </button>
      <button type="button" className="icon-action" disabled={disabled} title="Export CSV" onClick={() => downloadCsv(hosts)}>
        <Download size={17} />
      </button>
    </div>
  );
}

function ProgressDial({ percent, status }: { percent: number; status: ScanMeta["status"] }) {
  return (
    <div className={`progress-dial ${status}`}>
      <svg viewBox="0 0 42 42">
        <circle cx="21" cy="21" r="17" />
        <circle cx="21" cy="21" r="17" style={{ strokeDashoffset: 107 - (107 * percent) / 100 }} />
      </svg>
      <span>{percent}%</span>
    </div>
  );
}

function RangeControl({
  label,
  value,
  min,
  max,
  step,
  unit,
  onChange
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  step: number;
  unit: string;
  onChange: (value: number) => void;
}) {
  return (
    <label className="range-control">
      <span>
        {label}
        <strong>
          {value}
          {unit}
        </strong>
      </span>
      <input type="range" value={value} min={min} max={max} step={step} onChange={(event) => onChange(Number(event.target.value))} />
    </label>
  );
}

function Switch({
  label,
  checked,
  onChange,
  icon
}: {
  label: string;
  checked: boolean;
  onChange: (value: boolean) => void;
  icon: React.ReactNode;
}) {
  return (
    <label className={`switch ${checked ? "is-on" : ""}`}>
      <input
        type="checkbox"
        aria-label={label}
        data-testid={`switch-${label.toLowerCase().replace(/\s+/g, "-")}`}
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
      />
      <span className="switch-track">
        <span className="switch-thumb">{icon}</span>
      </span>
      <strong>{label}</strong>
    </label>
  );
}

function deriveSummary(hosts: HostResult[], meta: ScanMeta): ScanSummary {
  if (meta.summary) return meta.summary;
  return {
    hosts: hosts.length,
    liveHosts: hosts.filter((host) => host.status === "up").length,
    openPorts: hosts.reduce((sum, host) => sum + host.openPorts.length, 0),
    elevatedHosts: hosts.filter((host) => hostRisk(host) === "critical" || hostRisk(host) === "elevated").length,
    totalChecks: meta.total,
    completed: meta.completed,
    durationMs: 0
  };
}

function getServiceMix(ports: PortResult[]) {
  const counts = new Map<string, number>();
  ports.forEach((port) => counts.set(port.service, (counts.get(port.service) || 0) + 1));
  return Array.from(counts.entries())
    .map(([service, count]) => ({ service, count }))
    .sort((a, b) => b.count - a.count || a.service.localeCompare(b.service));
}

function riskToTimeline(risk: Risk): TimelineEntry["level"] {
  if (risk === "critical" || risk === "elevated") return "warn";
  if (risk === "medium") return "info";
  return "success";
}

function hostRisk(host: HostResult): Risk {
  if (host.openPorts.some((port) => port.risk === "critical")) return "critical";
  if (host.riskScore >= 35 || host.openPorts.some((port) => port.risk === "elevated")) return "elevated";
  if (host.riskScore >= 10 || host.openPorts.some((port) => port.risk === "medium")) return "medium";
  return "low";
}

function scoreHost(ports: PortResult[]) {
  return ports.reduce((score, port) => {
    if (port.risk === "critical") return score + 35;
    if (port.risk === "elevated") return score + 20;
    if (port.risk === "medium") return score + 10;
    return score + 3;
  }, 0);
}

function sortHosts(a: HostResult, b: HostResult) {
  return ipSortValue(a.ip) - ipSortValue(b.ip);
}

function ipSortValue(ip: string) {
  return ip.split(".").reduce((acc, part) => acc * 256 + Number(part), 0);
}

function statusLabel(status: ScanMeta["status"]) {
  if (status === "running") return "Scanning";
  if (status === "complete") return "Complete";
  if (status === "cancelled") return "Cancelled";
  if (status === "error") return "Needs attention";
  return "Standing by";
}

function formatDuration(ms: number) {
  const safe = Math.max(0, ms);
  const seconds = Math.floor(safe / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${seconds % 60}s`;
}

function formatClock(timestamp: string) {
  return new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date(timestamp));
}

function makeTimeline(level: TimelineEntry["level"], text: string): TimelineEntry {
  return {
    id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
    level,
    text,
    timestamp: new Date().toISOString()
  };
}

function makeId() {
  return globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function downloadJson(payload: unknown, filename: string) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  downloadBlob(blob, filename);
}

function downloadCsv(hosts: HostResult[]) {
  const rows = [["host", "status", "port", "service", "risk", "product", "advice"]];
  hosts.forEach((host) => {
    if (host.openPorts.length === 0) {
      rows.push([host.ip, host.status, "", "", "", "", ""]);
      return;
    }
    host.openPorts.forEach((port) => {
      rows.push([host.ip, host.status, String(port.port), port.service, port.risk, port.product || "", port.advice]);
    });
  });
  const csv = rows.map((row) => row.map(csvCell).join(",")).join("\n");
  downloadBlob(new Blob([csv], { type: "text/csv" }), `sentinel-scan-${Date.now()}.csv`);
}

function csvCell(value: string) {
  return `"${value.replace(/"/g, '""')}"`;
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export default App;
