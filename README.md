# ipinfo

A minimal, fast IP info service written in TypeScript, deployable to both
**Cloudflare Workers** and **Vercel**.

Like `ifconfig.me` or `icanhazip.com` — but self-hosted, open source, and
running at the edge.

## Usage

```bash
# Just your IP (curl / CLI)
curl ip.example.com

# Just your IP (explicit)
curl ip.example.com/ip

# Full info as plain text
curl ip.example.com/text

# Full info as JSON
curl ip.example.com/json
```

Open in a browser for a styled dark-mode dashboard showing your IP, geo
location, and all request headers.

## Features

- **Content negotiation** — HTML dashboard for browsers, raw IP for `curl` / CLI
- **Endpoints** — `/` (HTML or IP), `/ip` (plain IP), `/text` (full text), `/json` (structured)
- **Geo info** — from Cloudflare headers (`cf-ip*`, `cf-ray`) and Vercel headers (`x-vercel-ip-*`, `x-vercel-id`)
- **All request headers** displayed
- **Proxy IP filtering** — skips Cloudflare proxy and private/loopback IPs to find the real client IP
- **One shared core** — the same Web-standard handler runs on workerd and on Vercel
- **~11 KB** Cloudflare Worker bundle (~3.7 KB gzipped)

## Project Structure

```
src/core.ts         — platform-agnostic logic (IP extraction, filtering, geo, routes, HTML)
src/version.ts      — version constant, stamped from the git tag on release
src/cloudflare.ts   — Cloudflare Workers entry (export default { fetch })
api/root.ts         — Vercel function for /
api/ip.ts           — Vercel function for /ip
api/text.ts         — Vercel function for /text
api/json.ts         — Vercel function for /json
test/core.test.ts   — unit tests (Vitest)
wrangler.toml       — Cloudflare Workers config
vercel.json         — Vercel rewrites mapping public paths to functions
tsconfig.json       — TypeScript config
```

## Development

```bash
npm install
npm run dev        # wrangler dev (local Cloudflare runtime)
npm test           # vitest
npm run typecheck  # tsc --noEmit
npm run build      # wrangler deploy --dry-run
```

## Deploy

### Cloudflare Workers

```bash
npx wrangler login
npm run deploy
```

### Vercel

```bash
npm run deploy:vercel
```

Both platforms import the exact same `src/core.ts`; only the thin entry points differ.

## CI/CD (GitHub Actions)

- **CI** (`ci.yml`) runs typecheck, tests, and a Worker build on every push/PR.
- **Deploy** (`deploy.yml`) runs on tags (`v*`) and deploys to Cloudflare Workers.
  It also deploys to Vercel when a `VERCEL_TOKEN` secret is configured.

Required secrets:

| Secret | Platform | Notes |
|--------|----------|-------|
| `CLOUDFLARE_API_TOKEN` | Cloudflare | Token with **Edit Cloudflare Workers** permission |
| `VERCEL_TOKEN` | Vercel | Optional; enables the Vercel deploy job |
| `VERCEL_ORG_ID` | Vercel | Optional; required by the Vercel CLI for non-interactive deploys |
| `VERCEL_PROJECT_ID` | Vercel | Optional; required by the Vercel CLI for non-interactive deploys |

## License

MIT
