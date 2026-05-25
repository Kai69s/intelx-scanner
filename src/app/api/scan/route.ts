import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { lookupEmail, normalizeIntelbaseResponse } from "@/lib/intelbase";
import { rateLimit } from "@/lib/rate-limit";
import type { ScanErrorResponse, ScanHealthResponse, ScanResponse } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const scanSchema = z.object({
  email: z.string().trim().toLowerCase().email().max(254),
});

const DEFAULT_RATE_LIMIT_MAX = 8;
const DEFAULT_RATE_LIMIT_WINDOW_MS = 60000;
const PLACEHOLDER_KEY_PATTERN = /replace|your_|example|test/i;

function envNumber(name: string, fallback: number) {
  const value = Number(process.env[name]);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

function rateLimitConfig() {
  return {
    maxRequests: envNumber("SCAN_RATE_LIMIT_MAX", DEFAULT_RATE_LIMIT_MAX),
    windowMs: envNumber("SCAN_RATE_LIMIT_WINDOW_MS", DEFAULT_RATE_LIMIT_WINDOW_MS),
  };
}

function clientKey(request: NextRequest) {
  const forwardedFor = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  const realIp = request.headers.get("x-real-ip")?.trim();
  return forwardedFor || realIp || "local";
}

function errorResponse(message: string, code: string, status: number) {
  return NextResponse.json<ScanErrorResponse>(
    { error: message, code },
    {
      status,
      headers: {
        "cache-control": "no-store",
      },
    },
  );
}

export async function GET() {
  const apiKey = process.env.INTELBASE_API_KEY?.trim() ?? "";
  const config = rateLimitConfig();

  return NextResponse.json<ScanHealthResponse>(
    {
      ok: Boolean(apiKey) && !PLACEHOLDER_KEY_PATTERN.test(apiKey),
      intelbase: {
        apiUrl: (process.env.INTELBASE_API_URL ?? "https://api.intelbase.is").trim(),
        apiKeyConfigured: Boolean(apiKey),
        apiKeyLooksPlaceholder: PLACEHOLDER_KEY_PATTERN.test(apiKey),
        upstreamVerification: "not_checked",
      },
      rateLimit: config,
    },
    {
      headers: {
        "cache-control": "no-store",
      },
    },
  );
}

export async function POST(request: NextRequest) {
  const config = rateLimitConfig();
  const limit = rateLimit(clientKey(request), config.maxRequests, config.windowMs);

  if (!limit.allowed) {
    return NextResponse.json<ScanErrorResponse>(
      {
        error: `Scan window saturated. Retry in ${limit.retryAfterSeconds}s.`,
        code: "RATE_LIMITED",
      },
      {
        status: 429,
        headers: {
          "cache-control": "no-store",
          "retry-after": String(limit.retryAfterSeconds),
        },
      },
    );
  }

  let payload: unknown;
  try {
    payload = await request.json();
  } catch {
    return errorResponse("Malformed scan packet.", "BAD_JSON", 400);
  }

  const parsed = scanSchema.safeParse(payload);
  if (!parsed.success) {
    return errorResponse("Enter a valid email address to initialize the scan.", "INVALID_EMAIL", 400);
  }

  const startedAt = performance.now();

  try {
    const raw = await lookupEmail(parsed.data.email);
    const durationMs = Math.max(1, Math.round(performance.now() - startedAt));
    const report = normalizeIntelbaseResponse(raw, parsed.data.email, durationMs);

    return NextResponse.json<ScanResponse>(
      { report },
      {
        headers: {
          "cache-control": "no-store",
        },
      },
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown scan failure";

    if (message.includes("INTELBASE_API_KEY")) {
      return errorResponse("Intelbase credentials are not configured on the server.", "SERVER_CONFIG", 500);
    }

    if (message.includes("(401)") || message.includes("(403)")) {
      return errorResponse(
        "Intelbase rejected the server credential or IP whitelist. Update the server API key and whitelist the deployment IP.",
        "UPSTREAM_AUTH",
        502,
      );
    }

    if (message.includes("aborted")) {
      return errorResponse("Intelbase scan timed out before completing.", "UPSTREAM_TIMEOUT", 504);
    }

    return errorResponse("Scan relay failed. Try again after the upstream service stabilizes.", "SCAN_FAILED", 502);
  }
}
