# ipinfo

Minimal IP info service built with **Rust + WebAssembly**, deployed on **Cloudflare Workers**.

## Features

- Content negotiation: HTML for browsers, plain text for `curl`/CLI
- `/json` endpoint for structured JSON output
- `/ip` endpoint for just the IP
- Geo info from Cloudflare headers (country, city, region, timezone, colo)
- All request headers displayed
- Zero JavaScript — pure Rust compiled to Wasm

## Usage

```bash
# Just the IP
curl https://ip.YOUR_DOMAIN/ip

# Full info (plain text)
curl https://ip.YOUR_DOMAIN/

# JSON
curl https://ip.YOUR_DOMAIN/json
```

## Development

```bash
# Prerequisites
rustup target add wasm32-unknown-unknown
cargo install worker-build
npm install -g wrangler

# Build
worker-build --release

# Local dev
npx wrangler dev

# Deploy
npx wrangler deploy
```

## Project Structure

```
src/lib.rs       — All application logic
Cargo.toml       — Rust dependencies
wrangler.toml    — Cloudflare Workers config
```
