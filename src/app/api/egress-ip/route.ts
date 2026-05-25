import { NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type EgressIpResponse = {
  ip: string | null;
  checkedAt: string;
  source: "api.ipify.org";
  note: string;
};

export async function GET() {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    const response = await fetch("https://api.ipify.org?format=json", {
      cache: "no-store",
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`IP check failed (${response.status})`);
    }

    const body = (await response.json()) as { ip?: unknown };
    const ip = typeof body.ip === "string" ? body.ip : null;

    return NextResponse.json<EgressIpResponse>(
      {
        ip,
        checkedAt: new Date().toISOString(),
        source: "api.ipify.org",
        note: "Use this as a diagnostic only. Vercel outbound IPs can change unless Static IPs are enabled for the project.",
      },
      {
        headers: {
          "cache-control": "no-store",
        },
      },
    );
  } catch {
    return NextResponse.json<EgressIpResponse>(
      {
        ip: null,
        checkedAt: new Date().toISOString(),
        source: "api.ipify.org",
        note: "The deployment could not resolve its current outbound IP.",
      },
      {
        status: 502,
        headers: {
          "cache-control": "no-store",
        },
      },
    );
  } finally {
    clearTimeout(timeout);
  }
}
