import { NextResponse } from "next/server";
import { getCurrentEgressIp } from "@/lib/egress";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type EgressIpResponse = {
  ip: string | null;
  checkedAt: string;
  source: "api.ipify.org";
  note: string;
};

export async function GET() {
  const ip = await getCurrentEgressIp();

  if (ip) {
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
  }

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
}
