export async function getCurrentEgressIp(): Promise<string | null> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    const response = await fetch("https://api.ipify.org?format=json", {
      cache: "no-store",
      signal: controller.signal,
    });

    if (!response.ok) {
      return null;
    }

    const body = (await response.json()) as { ip?: unknown };
    return typeof body.ip === "string" ? body.ip : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}
