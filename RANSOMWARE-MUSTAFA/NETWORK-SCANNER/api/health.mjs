import { PORT_PRESETS } from "../server/scanner.mjs";

export default function handler(_req, res) {
  res.status(200).json({
    ok: true,
    name: "sentinel-network-scanner",
    mode: "cloud-demo",
    presets: PORT_PRESETS
  });
}
