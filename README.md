# ipinfo

A minimal, fast IP info service built with Rust + WebAssembly, running on Cloudflare Workers edge network.

Like `ifconfig.me` or `icanhazip.com` — but self-hosted, open source, and running at the edge in ~200 cities worldwide.

## Usage

```bash
# Your IP
curl ip.example.com

# Just the IP (for scripts)
curl ip.example.com/ip

# Full info as JSON
curl ip.example.com/json
```

Open in a browser for a styled dark-mode dashboard showing your IP, geo location, and all request headers.

## Features

- **Content negotiation** — HTML for browsers, plain text for `curl` / CLI
- **Three endpoints** — `/` (auto), `/ip` (plain IP), `/json` (structured)
- **Geo info** from Cloudflare headers (country, city, region, timezone, colo)
- **All request headers** displayed
- **Cloudflare IP filtering** — skips CF proxy and private IPs to find the real client IP
- **Zero JavaScript** on the page — pure Rust compiled to Wasm
- **~18KB** worker bundle

## Deploy Your Own

### Prerequisites

- [Rust](https://rustup.rs/) with `wasm32-unknown-unknown` target
- [worker-build](https://crates.io/crates/worker-build): `cargo install worker-build`
- [wrangler](https://developers.cloudflare.com/workers/wrangler/): `npm install -g wrangler`
- A [Cloudflare account](https://dash.cloudflare.com) (free tier works)

### Local Development

```bash
git clone https://github.com/YOUR_USER/ipinfo.git
cd ipinfo
npx wrangler dev
```

### Manual Deploy

```bash
npx wrangler login
npx wrangler deploy
```

### CI/CD (GitHub Actions)

Push to `main` triggers automatic deployment. Set up the required secret:

1. Go to [Cloudflare Dashboard → API Tokens](https://dash.cloudflare.com/profile/api-tokens)
2. Create a token with **Edit Cloudflare Workers** permission
3. Add it as `CLOUDFLARE_API_TOKEN` in your repo's **Settings → Secrets → Actions**

## Project Structure

```
src/lib.rs                      — All application logic
Cargo.toml                      — Rust dependencies
wrangler.toml                   — Cloudflare Workers config
.github/workflows/ci.yml        — Check, lint, build
.github/workflows/deploy.yml    — Deploy to CF Workers on push to main
```

## License

MIT
