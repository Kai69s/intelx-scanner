# Sentinel Network Scanner

A defensive network scanning dashboard inspired by Nmap. It provides a local web UI with a Node-based scanner for authorized networks.

## What it does

- Parses single IPs, CIDR ranges, compact IP ranges, and hostnames.
- Runs TCP connect scans with configurable timeout and concurrency.
- Performs optional ICMP host discovery, banner grabbing, and TLS certificate inspection.
- Streams live progress to a React dashboard over WebSocket.
- Exports scan results to JSON or CSV.
- Includes guardrails: explicit authorization is required, public targets require an extra opt-in, and scan size is capped.

## Run it

```bash
npm install
npm run dev
```

Open `http://127.0.0.1:5173`.

## Deploy it

The Vercel deployment serves the dashboard and a safe cloud demo endpoint. Live TCP scanning stays enabled for local runs by default. To intentionally enable cloud-side live scanning, set `ENABLE_CLOUD_SCANNER=true` in a protected deployment with real authentication.

Only scan systems you own or have permission to assess.
