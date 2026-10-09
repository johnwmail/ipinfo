import { describe, expect, it } from "vitest";
import cloudflare from "../src/cloudflare.js";
import apiRoot from "../api/root.js";
import apiIp from "../api/ip.js";
import apiText from "../api/text.js";
import apiJson from "../api/json.js";

const headers = { "cf-connecting-ip": "198.51.100.4" };

function req(path: string, extra: Record<string, string> = {}): Request {
  return new Request(`https://ip.example.com${path}`, {
    headers: { ...headers, ...extra },
  });
}

describe("Cloudflare entry", () => {
  it("routes by URL path", async () => {
    const res = cloudflare.fetch(req("/ip"));
    expect(await res.text()).toBe("198.51.100.4\n");
  });
});

describe("Vercel entries", () => {
  it("root delegates to /", async () => {
    const res = apiRoot.fetch(req("/", { accept: "*/*" }));
    expect(await res.text()).toBe("198.51.100.4\n");
  });

  it("ip delegates to /ip", async () => {
    const res = apiIp.fetch(req("/ip"));
    expect(await res.text()).toBe("198.51.100.4\n");
  });

  it("text delegates to /text", async () => {
    const res = apiText.fetch(req("/text"));
    expect(await res.text()).toContain("IP:              198.51.100.4");
  });

  it("json delegates to /json", async () => {
    const res = apiJson.fetch(req("/json"));
    expect((await res.json()).ip).toBe("198.51.100.4");
  });
});
