import type { IntelligenceReport, IntelSource, RiskLevel } from "@/lib/types";

const API_URL = process.env.INTELBASE_API_URL ?? "https://api.intelbase.is";
const EMAIL_ENDPOINT = "/lookup/email";

type UnknownRecord = Record<string, unknown>;

function isRecord(value: unknown): value is UnknownRecord {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function unique(values: string[], limit = 12) {
  return Array.from(
    new Set(
      values
        .map((value) => value.trim())
        .filter(Boolean)
        .filter((value) => value.length <= 120),
    ),
  ).slice(0, limit);
}

function collectByKey(value: unknown, match: RegExp, output: string[] = []): string[] {
  if (Array.isArray(value)) {
    for (const item of value) {
      collectByKey(item, match, output);
    }
    return output;
  }

  if (!isRecord(value)) {
    return output;
  }

  for (const [key, item] of Object.entries(value)) {
    if (match.test(key)) {
      if (typeof item === "string" || typeof item === "number") {
        output.push(String(item));
      }

      if (Array.isArray(item)) {
        for (const nested of item) {
          if (typeof nested === "string" || typeof nested === "number") {
            output.push(String(nested));
          }
        }
      }
    }

    collectByKey(item, match, output);
  }

  return output;
}

function collectDates(value: unknown, output: string[] = []): string[] {
  if (Array.isArray(value)) {
    for (const item of value) {
      collectDates(item, output);
    }
    return output;
  }

  if (!isRecord(value)) {
    return output;
  }

  for (const [key, item] of Object.entries(value)) {
    const keyLooksTemporal = /date|time|timestamp|created|updated|breach|seen/i.test(key);

    if (keyLooksTemporal && (typeof item === "string" || typeof item === "number")) {
      const parsed = new Date(item);
      if (!Number.isNaN(parsed.getTime())) {
        output.push(parsed.toISOString());
      }
    }

    collectDates(item, output);
  }

  return output;
}

function countItems(value: unknown): number {
  if (Array.isArray(value)) {
    return value.length;
  }

  if (isRecord(value)) {
    return Object.keys(value).length;
  }

  if (typeof value === "number" && Number.isFinite(value)) {
    return Math.max(0, value);
  }

  return 0;
}

function findNumericTotal(raw: unknown): number {
  if (!isRecord(raw)) {
    return 0;
  }

  const preferredKeys = [
    "total_matches",
    "totalMatches",
    "matches_count",
    "match_count",
    "total",
    "count",
  ];

  for (const key of preferredKeys) {
    const value = raw[key];
    if (typeof value === "number" && Number.isFinite(value)) {
      return Math.max(0, value);
    }
  }

  const candidateArrays = ["results", "matches", "data", "records", "items"];
  for (const key of candidateArrays) {
    const value = raw[key];
    const count = countItems(value);
    if (count > 0) {
      return count;
    }
  }

  let nestedTotal = 0;
  for (const value of Object.values(raw)) {
    if (isRecord(value)) {
      nestedTotal += findNumericTotal(value);
    } else if (Array.isArray(value)) {
      nestedTotal += value.length;
    }
  }

  return nestedTotal;
}

function makeSource(name: string, category: IntelSource["category"], value: unknown): IntelSource {
  const lastSeen = unique(collectDates(value), 1)[0];
  const count = countItems(value);
  return {
    name,
    category,
    ...(count ? { count } : {}),
    ...(lastSeen ? { lastSeen } : {}),
  };
}

function collectSources(raw: unknown): IntelSource[] {
  const sources: IntelSource[] = [];

  function visit(value: unknown, path: string[] = []) {
    if (Array.isArray(value)) {
      value.forEach((item, index) => visit(item, [...path, String(index)]));
      return;
    }

    if (!isRecord(value)) {
      return;
    }

    for (const [key, item] of Object.entries(value)) {
      const label = key.replace(/_/g, " ");
      if (/breach/i.test(key)) {
        sources.push(makeSource(label, "breach", item));
      } else if (/leak|paste/i.test(key)) {
        sources.push(makeSource(label, "leak", item));
      } else if (/database|db/i.test(key)) {
        sources.push(makeSource(label, "database", item));
      } else if (/platform|service|module|source/i.test(key)) {
        sources.push(makeSource(label, "platform", item));
      } else if (/record|result|match/i.test(key) && countItems(item) > 0) {
        sources.push(makeSource(label, "record", item));
      }

      if (path.length < 4) {
        visit(item, [...path, key]);
      }
    }
  }

  visit(raw);

  const namedSources = sources.map((source) => ({
    ...source,
    name: source.name.replace(/\b\w/g, (char) => char.toUpperCase()),
  }));

  return Array.from(
    new Map(namedSources.map((source) => [`${source.category}:${source.name}`, source])).values(),
  ).slice(0, 8);
}

function riskFromCounts(totalMatches: number, leakCount: number, breachCount: number): RiskLevel {
  if (totalMatches <= 0) return "clear";
  if (breachCount >= 6 || leakCount >= 12 || totalMatches >= 25) return "critical";
  if (breachCount >= 3 || leakCount >= 6 || totalMatches >= 12) return "high";
  if (breachCount >= 1 || leakCount >= 2 || totalMatches >= 4) return "elevated";
  return "guarded";
}

function summaryFor(report: Omit<IntelligenceReport, "summary">): string {
  if (report.totalMatches <= 0) {
    return "No exposed records were detected in the Intelbase response. Continue monitoring this identity and rotate credentials after any suspicious activity.";
  }

  const platformText =
    report.platforms.length > 0 ? ` across ${report.platforms.slice(0, 3).join(", ")}` : "";

  return `${report.totalMatches} intelligence match${
    report.totalMatches === 1 ? "" : "es"
  } were correlated${platformText}. Treat this identity as exposed, review reused passwords, and prioritize credential rotation on related services.`;
}

export function normalizeIntelbaseResponse(
  raw: unknown,
  email: string,
  durationMs: number,
): IntelligenceReport {
  const totalMatches = findNumericTotal(raw);
  const sources = collectSources(raw);
  const breachCount = sources
    .filter((source) => source.category === "breach")
    .reduce((sum, source) => sum + (source.count ?? 1), 0);
  const leakCount = sources
    .filter((source) => source.category === "leak" || source.category === "database")
    .reduce((sum, source) => sum + (source.count ?? 1), 0);
  const riskLevel = riskFromCounts(totalMatches, leakCount, breachCount);

  const reportWithoutSummary: Omit<IntelligenceReport, "summary"> = {
    email,
    scannedAt: new Date().toISOString(),
    durationMs,
    status: totalMatches > 0 ? "detected" : "clear",
    breachStatus: totalMatches > 0 ? "Threat Signature Detected" : "No Indexed Exposure Detected",
    riskLevel,
    totalMatches,
    leakCount,
    breachCount,
    usernames: unique(collectByKey(raw, /user(name)?|login|handle|screen_name/i)),
    domains: unique(collectByKey(raw, /domain|host|website|site/i)),
    platforms: unique(collectByKey(raw, /platform|service|source|module|app|name/i)),
    timestamps: unique(collectDates(raw), 8),
    sources,
  };

  return {
    ...reportWithoutSummary,
    summary: summaryFor(reportWithoutSummary),
  };
}

export async function lookupEmail(email: string): Promise<unknown> {
  const apiKey = process.env.INTELBASE_API_KEY;

  if (!apiKey) {
    throw new Error("INTELBASE_API_KEY is not configured");
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);

  try {
    const response = await fetch(`${API_URL}${EMAIL_ENDPOINT}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": apiKey,
      },
      body: JSON.stringify({
        email,
        timeout_ms: 12000,
        include_data_breaches: true,
      }),
      cache: "no-store",
      signal: controller.signal,
    });

    const text = await response.text();
    const body = text ? (JSON.parse(text) as unknown) : null;

    if (!response.ok) {
      const error = isRecord(body) && typeof body.error === "string" ? body.error : response.statusText;
      throw new Error(`Intelbase request failed (${response.status}): ${error}`);
    }

    return body;
  } finally {
    clearTimeout(timeout);
  }
}
