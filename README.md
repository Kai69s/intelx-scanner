# IntelX Scanner

IntelX Scanner is a cinematic OSINT-style email exposure dashboard built with Next.js, TypeScript, Tailwind CSS, Framer Motion, and a secure Intelbase API relay.

The app keeps the Intelbase API key on the server, validates and rate-limits scan requests, normalizes upstream intelligence into a polished report, and provides local investigation history plus PDF export.

## Stack

- Next.js 16 app router
- React 19 and TypeScript
- Tailwind CSS v4
- Framer Motion
- Lucide React icons
- Zod validation
- jsPDF report export

## Environment

Create `.env.local` from `.env.example`:

```bash
INTELBASE_API_KEY=your_intelbase_api_key
INTELBASE_API_URL=https://api.intelbase.is
SCAN_RATE_LIMIT_MAX=8
SCAN_RATE_LIMIT_WINDOW_MS=60000
```

Intelbase also requires the deployment IP to be whitelisted in the Intelbase dashboard.

## Local Development

```bash
npm install
npm run dev
```

Open `http://localhost:3000`.

If PowerShell blocks `npm.ps1` on Windows, use the `.cmd` shim:

```powershell
npm.cmd install
npm.cmd run dev
```

## Validation

```bash
npm run lint
npm run typecheck
npm run build
```

## API Integration

Frontend requests are sent to:

```text
POST /api/scan
```

A non-secret configuration check is available at:

```text
GET /api/scan
```

It reports whether the server has an Intelbase key configured and which rate-limit values are active. It does not verify the key with Intelbase or expose the key value.

To inspect the current server outbound IP for Intelbase whitelisting:

```text
GET /api/egress-ip
```

Use this as a diagnostic only. Vercel outbound IPs can change unless Static IPs are enabled for the project.

Request body:

```json
{
  "email": "analyst@example.com"
}
```

The server route validates the email, applies an in-memory rate limit, then calls:

```text
POST https://api.intelbase.is/lookup/email
```

The Intelbase API key is sent as `x-api-key` from server-side environment variables only. The browser never receives the key or raw upstream errors.

## Deployment

1. Push the repository to GitHub.
2. Import the repo in Vercel.
3. Add these Vercel environment variables for Production, plus Preview or Development if you use those targets:
   - `INTELBASE_API_KEY`
   - `INTELBASE_API_URL`
   - `SCAN_RATE_LIMIT_MAX`
   - `SCAN_RATE_LIMIT_WINDOW_MS`
4. Never commit `.env.local` or API keys to GitHub. Vercel must receive secrets through Project Settings or the Vercel CLI.
5. Deploy.
6. Whitelist the Vercel deployment egress IP or use a network configuration compatible with Intelbase IP whitelisting.

## Security Notes

- `.env.local` is ignored by Git.
- Secrets are used only inside `src/lib/intelbase.ts`.
- `/api/scan` returns sanitized errors.
- Responses use `cache-control: no-store`.
- Basic security headers are configured in `next.config.ts`.
- Local investigation history is stored in the browser for convenience.
