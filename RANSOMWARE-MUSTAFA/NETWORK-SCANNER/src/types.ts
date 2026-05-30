export type Risk = "low" | "medium" | "elevated" | "critical";

export type ScanOptions = {
  target: string;
  portMode: "quick" | "web" | "infra" | "top100" | "custom";
  customPorts: string;
  timeoutMs: number;
  concurrency: number;
  hostDiscovery: boolean;
  bannerGrab: boolean;
  tlsInspect: boolean;
  authorized: boolean;
  allowPublic: boolean;
};

export type TlsInfo = {
  authorized: boolean;
  protocol: string | null;
  cipher: string | null;
  subject: string | null;
  issuer: string | null;
  validFrom: string | null;
  validTo: string | null;
};

export type PortResult = {
  host: string;
  port: number;
  protocol: "tcp";
  state: "open" | "closed" | "filtered";
  service: string;
  product: string | null;
  banner: string;
  latencyMs: number;
  errorCode: string | null;
  tls: TlsInfo | null;
  risk: Risk;
  advice: string;
};

export type HostResult = {
  ip: string;
  input: string;
  hostname: string | null;
  reverseName: string | null;
  status: "unknown" | "up" | "silent";
  latencyMs: number | null;
  openPorts: PortResult[];
  closedPorts: number;
  filteredPorts: number;
  riskScore: number;
};

export type ScanSummary = {
  hosts: number;
  liveHosts: number;
  openPorts: number;
  elevatedHosts: number;
  totalChecks: number;
  completed: number;
  durationMs: number;
};

export type TimelineEntry = {
  id: string;
  level: "info" | "warn" | "error" | "success";
  text: string;
  timestamp: string;
};

export type ScanMeta = {
  scanId: string | null;
  status: "idle" | "running" | "complete" | "cancelled" | "error";
  startedAt: string | null;
  endedAt: string | null;
  completed: number;
  total: number;
  percent: number;
  summary: ScanSummary | null;
  error: string | null;
};
