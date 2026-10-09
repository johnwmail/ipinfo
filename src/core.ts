import { VERSION } from "./version.js";

// Cloudflare published IP ranges: https://www.cloudflare.com/ips/
const CF_IPV4_CIDRS: Array<[string, number]> = [
  ["173.245.48.0", 20],
  ["103.21.244.0", 22],
  ["103.22.200.0", 22],
  ["103.31.4.0", 22],
  ["141.101.64.0", 18],
  ["108.162.192.0", 18],
  ["190.93.240.0", 20],
  ["188.114.96.0", 20],
  ["197.234.240.0", 22],
  ["198.41.128.0", 17],
  ["162.158.0.0", 15],
  ["104.16.0.0", 13],
  ["104.24.0.0", 14],
  ["172.64.0.0", 13],
  ["131.0.72.0", 22],
];

const CF_IPV6_CIDRS: Array<[string, number]> = [
  ["2400:cb00::", 32],
  ["2606:4700::", 32],
  ["2803:f800::", 32],
  ["2405:b500::", 32],
  ["2405:8100::", 32],
  ["2a06:98c0::", 29],
  ["2c0f:f248::", 32],
];

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = (value << 8) | octet;
  }
  return value >>> 0;
}

function parseIpv6(input: string): bigint | null {
  let ip = input;
  const zone = ip.indexOf("%");
  if (zone !== -1) ip = ip.slice(0, zone);

  // Handle an embedded IPv4 address (e.g. ::ffff:192.168.0.1).
  if (ip.includes(".")) {
    const lastColon = ip.lastIndexOf(":");
    if (lastColon === -1) return null;
    const embedded = ipv4ToInt(ip.slice(lastColon + 1));
    if (embedded === null) return null;
    const hi = ((embedded >>> 16) & 0xffff).toString(16);
    const lo = (embedded & 0xffff).toString(16);
    ip = `${ip.slice(0, lastColon)}:${hi}:${lo}`;
  }

  const parseGroups = (segment: string): number[] | null => {
    if (segment === "") return [];
    const groups: number[] = [];
    for (const group of segment.split(":")) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
      groups.push(parseInt(group, 16));
    }
    return groups;
  };

  const halves = ip.split("::");
  if (halves.length > 2) return null;

  let groups: number[];
  if (halves.length === 2) {
    const left = parseGroups(halves[0]);
    const right = parseGroups(halves[1]);
    if (!left || !right) return null;
    const missing = 8 - left.length - right.length;
    if (missing < 1) return null;
    groups = [...left, ...new Array<number>(missing).fill(0), ...right];
  } else {
    const all = parseGroups(ip);
    if (!all || all.length !== 8) return null;
    groups = all;
  }

  let bits = 0n;
  for (const group of groups) bits = (bits << 16n) | BigInt(group);
  return bits;
}

interface ParsedIp {
  version: 4 | 6;
  value: number | bigint;
}

function parseIp(ip: string): ParsedIp | null {
  if (ip.includes(":")) {
    const value = parseIpv6(ip);
    return value === null ? null : { version: 6, value };
  }
  const value = ipv4ToInt(ip);
  return value === null ? null : { version: 4, value };
}

const CF_IPV4_NETWORKS = CF_IPV4_CIDRS.map(([network, prefix]) => {
  const value = ipv4ToInt(network) ?? 0;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return { network: (value & mask) >>> 0, mask };
});

const CF_IPV6_NETWORKS = CF_IPV6_CIDRS.map(([network, prefix]) => {
  const value = parseIpv6(network) ?? 0n;
  const shift = BigInt(128 - prefix);
  const mask = prefix === 0 ? 0n : ((1n << BigInt(prefix)) - 1n) << shift;
  return { network: value & mask, mask };
});

export function isCloudflareIp(ip: string): boolean {
  const parsed = parseIp(ip);
  if (!parsed) return false;
  if (parsed.version === 4) {
    const value = parsed.value as number;
    return CF_IPV4_NETWORKS.some(({ network, mask }) => (value & mask) >>> 0 === network);
  }
  const value = parsed.value as bigint;
  return CF_IPV6_NETWORKS.some(({ network, mask }) => (value & mask) === network);
}

/** Returns true for loopback and RFC1918/private IPs — not useful as a client IP. */
export function isPrivateIp(ip: string): boolean {
  const parsed = parseIp(ip);
  if (!parsed) return false;
  if (parsed.version === 4) {
    const value = parsed.value as number;
    const inRange = (network: string, prefix: number): boolean => {
      const base = ipv4ToInt(network) ?? 0;
      const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
      return (value & mask) >>> 0 === (base & mask) >>> 0;
    };
    return (
      inRange("127.0.0.0", 8) ||
      inRange("10.0.0.0", 8) ||
      inRange("172.16.0.0", 12) ||
      inRange("192.168.0.0", 16)
    );
  }
  // Only the loopback address is filtered for IPv6.
  return parsed.value === 1n;
}

export function isUntrustedIp(ip: string): boolean {
  return ip === "" || isCloudflareIp(ip) || isPrivateIp(ip);
}

export interface IpInfo {
  ip: string;
  user_agent: string;
  accept_language: string;
  accept: string;
  country: string;
  city: string;
  region: string;
  timezone: string;
  colo: string;
  headers: Array<[string, string]>;
}

function firstNonEmpty(...values: Array<string | null>): string {
  for (const value of values) {
    if (value) return value;
  }
  return "";
}

function decodeSafe(value: string): string {
  if (!value) return value;
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

export function extractClientIp(get: (name: string) => string): string {
  const firstTrusted = (value: string): string =>
    value
      .split(",")
      .map((part) => part.trim())
      .find((ip) => !isUntrustedIp(ip)) ?? "";

  const cf = get("cf-connecting-ip");
  if (!isUntrustedIp(cf)) return cf.trim();

  // Vercel-native and not overwritten by an upstream proxy.
  const vercelForwarded = get("x-vercel-forwarded-for");
  if (vercelForwarded) {
    const found = firstTrusted(vercelForwarded);
    if (found) return found;
  }

  const real = get("x-real-ip");
  if (!isUntrustedIp(real)) return real.trim();

  const forwarded = get("x-forwarded-for");
  if (forwarded) {
    const found = firstTrusted(forwarded);
    if (found) return found;
  }

  return "";
}

export function buildIpInfo(headers: Headers): IpInfo {
  const get = (name: string): string => headers.get(name) ?? "";

  const ip = extractClientIp(get).trim() || "unknown";

  const cfRay = get("cf-ray");
  const cfColo = cfRay.includes("-") ? cfRay.slice(cfRay.lastIndexOf("-") + 1) : "";
  // Vercel: x-vercel-id looks like "hnd1::abc123"
  const vercelColo = get("x-vercel-id").split("::")[0];

  return {
    ip,
    user_agent: get("user-agent"),
    accept_language: get("accept-language"),
    accept: get("accept"),
    country: firstNonEmpty(get("cf-ipcountry"), get("x-vercel-ip-country")),
    city: decodeSafe(firstNonEmpty(get("cf-ipcity"), get("x-vercel-ip-city"))),
    region: firstNonEmpty(get("cf-region"), get("x-vercel-ip-country-region")),
    timezone: firstNonEmpty(get("cf-timezone"), get("x-vercel-ip-timezone")),
    colo: firstNonEmpty(cfColo, vercelColo),
    headers: [...headers.entries()],
  };
}

export function toPlainText(info: IpInfo): string {
  let out = "";
  out += `IP:              ${info.ip}\n`;
  if (info.country) out += `Country:         ${info.country}\n`;
  if (info.city) out += `City:            ${info.city}\n`;
  if (info.region) out += `Region:          ${info.region}\n`;
  if (info.timezone) out += `Timezone:        ${info.timezone}\n`;
  if (info.colo) out += `Colo:            ${info.colo}\n`;
  out += `User-Agent:      ${info.user_agent}\n`;
  if (info.accept_language) out += `Accept-Language: ${info.accept_language}\n`;
  return out;
}

export function htmlEscape(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** Best-effort detection of the hosting platform from edge-injected headers. */
export function detectPlatform(headers: Headers): string {
  if (headers.has("cf-ray") || headers.has("cf-connecting-ip")) {
    return "Cloudflare Workers";
  }
  if (headers.has("x-vercel-id") || headers.has("x-vercel-ip-country")) {
    return "Vercel Serverless";
  }
  return "Cloudflare Workers";
}

export function toHtml(info: IpInfo, host: string, platform = "Cloudflare Workers"): string {
  let headerRows = "";
  for (const [k, v] of info.headers) {
    headerRows += `<tr><td>${htmlEscape(k)}</td><td>${htmlEscape(v)}</td></tr>`;
  }

  let geoSection = "";
  const geoFields: Array<[string, string]> = [
    ["Country", info.country],
    ["City", info.city],
    ["Region", info.region],
    ["Timezone", info.timezone],
    ["Colo", info.colo],
  ];
  for (const [label, value] of geoFields) {
    if (value) {
      geoSection += `<tr><td>${label}</td><td>${htmlEscape(value)}</td></tr>`;
    }
  }

  const geoCard = geoSection
    ? `<div class="card"><div class="card-title">Geo</div><table>${geoSection}</table></div>`
    : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IP Info</title>
<style>
  :root { --bg: #0a0a0a; --card: #141414; --border: #2a2a2a; --text: #e0e0e0; --dim: #888; --accent: #6cf; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace; background: var(--bg); color: var(--text); min-height: 100vh; display: flex; justify-content: center; padding: 2rem 1rem; }
  .container { max-width: 720px; width: 100%; }
  h1 { font-size: 1.1rem; color: var(--accent); margin-bottom: 1.5rem; font-weight: 500; }
  .ip-display { font-size: 2.5rem; font-weight: 700; color: #fff; margin-bottom: 2rem; letter-spacing: -0.02em; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1.5rem; overflow: hidden; }
  .card-title { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--dim); padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); }
  table { width: 100%; border-collapse: collapse; }
  td { padding: 0.5rem 1rem; font-size: 0.85rem; }
  tr:not(:last-child) td { border-bottom: 1px solid var(--border); }
  td:first-child { color: var(--dim); width: 35%; white-space: nowrap; }
  td:last-child { word-break: break-all; }
  .footer { text-align: center; color: var(--dim); font-size: 0.7rem; margin-top: 2rem; }
  .footer a { color: var(--accent); text-decoration: none; }
</style>
</head>
<body>
<div class="container">
  <h1>$ curl ${htmlEscape(host)}</h1>
  <div class="ip-display">${htmlEscape(info.ip)}</div>

  <div class="card">
    <div class="card-title">Client</div>
    <table>
      <tr><td>User-Agent</td><td>${htmlEscape(info.user_agent)}</td></tr>
      <tr><td>Accept-Language</td><td>${htmlEscape(info.accept_language)}</td></tr>
    </table>
  </div>

  ${geoCard}

  <div class="card">
    <div class="card-title">All Headers</div>
    <table>${headerRows}</table>
  </div>

  <div class="footer">
    <a href="https://github.com/johnwmail/ipinfo">ipinfo ${VERSION}</a></br>
    Powered by TypeScript on ${htmlEscape(platform)}
  </div>
</div>
</body>
</html>`;
}

export function isBrowser(accept: string): boolean {
  return accept.includes("text/html");
}

function textResponse(body: string): Response {
  return new Response(body, {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

/**
 * Platform-agnostic request handler. Both the Cloudflare Worker and the Vercel
 * functions delegate to this, passing the logical route path explicitly.
 */
export function handleRequest(request: Request, path: string): Response {
  const info = buildIpInfo(request.headers);
  const host = request.headers.get("host") ?? "";

  let response: Response;
  if (path === "/json") {
    response = new Response(JSON.stringify(info, null, 2), {
      status: 200,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "access-control-allow-origin": "*",
      },
    });
  } else if (path === "/ip") {
    response = textResponse(`${info.ip}\n`);
  } else if (path === "/text") {
    response = textResponse(toPlainText(info));
  } else if (isBrowser(info.accept)) {
    response = new Response(toHtml(info, host, detectPlatform(request.headers)), {
      status: 200,
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  } else {
    // curl / wget / CLI — just the IP
    response = textResponse(`${info.ip}\n`);
  }

  response.headers.set("cache-control", "no-store, no-cache, must-revalidate");
  return response;
}
