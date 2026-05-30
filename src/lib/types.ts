export type RiskLevel = "clear" | "guarded" | "elevated" | "high" | "critical";

export type IntelSource = {
  name: string;
  category: "breach" | "leak" | "database" | "platform" | "record";
  count?: number;
  lastSeen?: string;
};

export type IntelligenceReport = {
  email: string;
  scannedAt: string;
  durationMs: number;
  status: "clear" | "detected";
  breachStatus: string;
  riskLevel: RiskLevel;
  totalMatches: number;
  leakCount: number;
  breachCount: number;
  usernames: string[];
  domains: string[];
  platforms: string[];
  timestamps: string[];
  sources: IntelSource[];
  summary: string;
};

export type ScanResponse = {
  report: IntelligenceReport;
  cached?: boolean;
};

export type ScanErrorResponse = {
  error: string;
  code: string;
  diagnostics?: {
    egressIp: string | null;
    whitelistRequired: boolean;
    docsUrl: string;
  };
};

export type ScanHealthResponse = {
  ok: boolean;
  intelbase: {
    apiUrl: string;
    apiKeyConfigured: boolean;
    apiKeyLooksPlaceholder: boolean;
    upstreamVerification: "not_checked";
  };
  rateLimit: {
    maxRequests: number;
    windowMs: number;
  };
};
