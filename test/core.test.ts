import { describe, expect, it } from "vitest";
import {
  buildIpInfo,
  detectPlatform,
  extractClientIp,
  handleRequest,
  htmlEscape,
  isBrowser,
  isCloudflareIp,
  isPrivateIp,
  isUntrustedIp,
  toHtml,
  toPlainText,
  type IpInfo,
} from "../src/core.js";

// --- isCloudflareIp ---

describe("isCloudflareIp", () => {
  it.each(["173.245.48.1", "104.16.0.1", "162.158.0.1", "172.64.0.1", "131.0.72.1"])(
    "matches IPv4 range %s",
    (ip) => {
      expect(isCloudflareIp(ip)).toBe(true);
    },
  );

  it.each(["2400:cb00::1", "2606:4700::1"])("matches IPv6 range %s", (ip) => {
    expect(isCloudflareIp(ip)).toBe(true);
  });

  it.each(["8.8.8.8", "203.0.113.50", "2001:db8::1", "not-an-ip", ""])(
    "rejects %s",
    (ip) => {
      expect(isCloudflareIp(ip)).toBe(false);
    },
  );
});

// --- isPrivateIp ---

describe("isPrivateIp", () => {
  it.each(["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "::1"])(
    "detects private %s",
    (ip) => {
      expect(isPrivateIp(ip)).toBe(true);
    },
  );

  it("treats public IPs as public", () => {
    expect(isPrivateIp("8.8.8.8")).toBe(false);
  });

  it("does not treat Cloudflare IPs as private", () => {
    expect(isPrivateIp("104.16.0.1")).toBe(false);
  });
});

// --- isUntrustedIp ---

describe("isUntrustedIp", () => {
  it("rejects empty, private and Cloudflare IPs", () => {
    expect(isUntrustedIp("")).toBe(true);
    expect(isUntrustedIp("127.0.0.1")).toBe(true);
    expect(isUntrustedIp("104.16.0.1")).toBe(true);
  });

  it("accepts a public IP", () => {
    expect(isUntrustedIp("203.0.113.50")).toBe(false);
  });
});

// --- extractClientIp ---

describe("extractClientIp", () => {
  it("prefers cf-connecting-ip when public", () => {
    const get = (name: string) => (name === "cf-connecting-ip" ? "198.51.100.7" : "");
    expect(extractClientIp(get)).toBe("198.51.100.7");
  });

  it("uses x-vercel-forwarded-for before x-forwarded-for", () => {
    const headers: Record<string, string> = {
      "x-vercel-forwarded-for": "198.51.100.8",
      "x-forwarded-for": "203.0.113.99",
    };
    expect(extractClientIp((name) => headers[name] ?? "")).toBe("198.51.100.8");
  });

  it("skips untrusted hops in x-vercel-forwarded-for", () => {
    const headers: Record<string, string> = {
      "x-vercel-forwarded-for": "104.16.0.1, 127.0.0.1, 198.51.100.9",
    };
    expect(extractClientIp((name) => headers[name] ?? "")).toBe("198.51.100.9");
  });

  it("falls back to x-forwarded-for, skipping untrusted hops", () => {
    const headers: Record<string, string> = {
      "x-forwarded-for": "104.16.0.1, 127.0.0.1, 198.51.100.9",
    };
    expect(extractClientIp((name) => headers[name] ?? "")).toBe("198.51.100.9");
  });

  it("returns empty when nothing trusted is present", () => {
    expect(extractClientIp(() => "")).toBe("");
  });
});

// --- htmlEscape ---

describe("htmlEscape", () => {
  it("escapes special characters", () => {
    expect(htmlEscape("a&b")).toBe("a&amp;b");
    expect(htmlEscape("<script>")).toBe("&lt;script&gt;");
    expect(htmlEscape('say "hi"')).toBe("say &quot;hi&quot;");
    expect(htmlEscape("hello world")).toBe("hello world");
  });
});

// --- isBrowser ---

describe("isBrowser", () => {
  it("detects HTML Accept headers", () => {
    expect(isBrowser("text/html,application/xhtml+xml,application/xml;q=0.9")).toBe(true);
  });

  it("treats curl/json/empty as non-browser", () => {
    expect(isBrowser("*/*")).toBe(false);
    expect(isBrowser("application/json")).toBe(false);
    expect(isBrowser("")).toBe(false);
  });
});

// --- detectPlatform ---

describe("detectPlatform", () => {
  it("detects Cloudflare from cf headers", () => {
    expect(detectPlatform(new Headers({ "cf-ray": "abc-SJC" }))).toBe("Cloudflare Workers");
    expect(detectPlatform(new Headers({ "cf-connecting-ip": "1.2.3.4" }))).toBe(
      "Cloudflare Workers",
    );
  });

  it("detects Vercel from x-vercel headers", () => {
    expect(detectPlatform(new Headers({ "x-vercel-id": "hnd1::abc" }))).toBe("Vercel Serverless");
    expect(detectPlatform(new Headers({ "x-vercel-ip-country": "HK" }))).toBe("Vercel Serverless");
  });

  it("falls back to Cloudflare Workers", () => {
    expect(detectPlatform(new Headers())).toBe("Cloudflare Workers");
  });
});

// --- output formatting ---

function makeInfo(ip: string, country: string, city: string): IpInfo {
  return {
    ip,
    user_agent: "curl/8.0",
    accept_language: "en-US",
    accept: "*/*",
    country,
    city,
    region: "",
    timezone: "",
    colo: "SJC",
    headers: [["user-agent", "curl/8.0"]],
  };
}

describe("toPlainText", () => {
  it("includes populated fields", () => {
    const text = toPlainText(makeInfo("1.2.3.4", "US", "San Jose"));
    expect(text).toContain("1.2.3.4");
    expect(text).toContain("US");
    expect(text).toContain("San Jose");
    expect(text).toContain("curl/8.0");
  });

  it("omits empty fields", () => {
    const text = toPlainText(makeInfo("1.2.3.4", "", ""));
    expect(text).not.toContain("Country");
    expect(text).not.toContain("City");
  });
});

describe("toHtml", () => {
  it("renders the dashboard", () => {
    const html = toHtml(makeInfo("1.2.3.4", "US", ""), "ip.example.com");
    expect(html).toContain("1.2.3.4");
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("US");
    expect(html).toContain("ip.example.com");
  });

  it("escapes XSS in user agent", () => {
    const info = makeInfo("1.2.3.4", "", "");
    info.user_agent = "<script>alert(1)</script>";
    const html = toHtml(info, "ip.example.com");
    expect(html).not.toContain("<script>alert");
    expect(html).toContain("&lt;script&gt;");
  });

  it("shows geo card when colo is present", () => {
    const html = toHtml(makeInfo("1.2.3.4", "", ""), "ip.example.com");
    expect(html).toContain("SJC");
  });
});

// --- buildIpInfo ---

describe("buildIpInfo", () => {
  it("reads Cloudflare and Vercel geo headers", () => {
    const headers = new Headers({
      "cf-connecting-ip": "198.51.100.4",
      "cf-ipcountry": "US",
      "cf-ray": "abc123-SJC",
    });
    const info = buildIpInfo(headers);
    expect(info.ip).toBe("198.51.100.4");
    expect(info.country).toBe("US");
    expect(info.colo).toBe("SJC");
  });

  it("falls back to Vercel headers", () => {
    const headers = new Headers({
      "x-forwarded-for": "198.51.100.5",
      "x-vercel-ip-country": "HK",
      "x-vercel-ip-city": "Hong%20Kong",
      "x-vercel-id": "hnd1::abc123",
    });
    const info = buildIpInfo(headers);
    expect(info.ip).toBe("198.51.100.5");
    expect(info.country).toBe("HK");
    expect(info.city).toBe("Hong Kong");
    expect(info.colo).toBe("hnd1");
  });
});

// --- handleRequest routing ---

function request(path: string, headers: Record<string, string>): Request {
  return new Request(`https://ip.example.com${path}`, { headers });
}

describe("handleRequest", () => {
  it("returns JSON on /json", async () => {
    const res = handleRequest(
      request("/json", { "cf-connecting-ip": "198.51.100.4" }),
      "/json",
    );
    expect(res.headers.get("content-type")).toContain("application/json");
    const body = await res.json();
    expect(body.ip).toBe("198.51.100.4");
  });

  it("returns just the IP on /ip", async () => {
    const res = handleRequest(
      request("/ip", { "cf-connecting-ip": "198.51.100.4" }),
      "/ip",
    );
    expect(await res.text()).toBe("198.51.100.4\n");
  });

  it("returns plain text on /text", async () => {
    const res = handleRequest(
      request("/text", { "cf-connecting-ip": "198.51.100.4" }),
      "/text",
    );
    expect(await res.text()).toContain("IP:              198.51.100.4");
  });

  it("returns just the IP to curl on /", async () => {
    const res = handleRequest(
      request("/", { "cf-connecting-ip": "198.51.100.4", accept: "*/*" }),
      "/",
    );
    expect(res.headers.get("content-type")).toContain("text/plain");
    expect(await res.text()).toBe("198.51.100.4\n");
  });

  it("returns HTML to browsers on /", async () => {
    const res = handleRequest(
      request("/", { "cf-connecting-ip": "198.51.100.4", accept: "text/html" }),
      "/",
    );
    expect(res.headers.get("content-type")).toContain("text/html");
    expect(await res.text()).toContain("<!DOCTYPE html>");
  });

  it("shows the detected platform in the footer", async () => {
    const cfRes = handleRequest(
      request("/", { "cf-ray": "abc-SJC", accept: "text/html" }),
      "/",
    );
    expect(await cfRes.text()).toContain("Powered by TypeScript on Cloudflare Workers");

    const vercelRes = handleRequest(
      request("/", { "x-vercel-id": "hnd1::abc", accept: "text/html" }),
      "/",
    );
    expect(await vercelRes.text()).toContain("Powered by TypeScript on Vercel Serverless");
  });

  it("sets no-store cache headers", () => {
    const res = handleRequest(request("/ip", {}), "/ip");
    expect(res.headers.get("cache-control")).toContain("no-store");
  });
});
