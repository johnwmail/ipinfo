use std::net::IpAddr;
use serde::Serialize;
use worker::*;

const VERSION: &str = match option_env!("IPINFO_VERSION") {
    Some(v) => v,
    None => "dev",
};

// Cloudflare published IP ranges: https://www.cloudflare.com/ips/
const CF_IPV4_CIDRS: &[(u32, u8)] = &[
    // 173.245.48.0/20
    (0xADF53000, 20),
    // 103.21.244.0/22
    (0x6715F400, 22),
    // 103.22.200.0/22
    (0x6716C800, 22),
    // 103.31.4.0/22
    (0x671F0400, 22),
    // 141.101.64.0/18
    (0x8D654000, 18),
    // 108.162.192.0/18
    (0x6CA2C000, 18),
    // 190.93.240.0/20
    (0xBE5DF000, 20),
    // 188.114.96.0/20
    (0xBC726000, 20),
    // 197.234.240.0/22
    (0xC5EAF000, 22),
    // 198.41.128.0/17
    (0xC6298000, 17),
    // 162.158.0.0/15
    (0xA29E0000, 15),
    // 104.16.0.0/13
    (0x68100000, 13),
    // 104.24.0.0/14
    (0x68180000, 14),
    // 172.64.0.0/13
    (0xAC400000, 13),
    // 131.0.72.0/22
    (0x83004800, 22),
];

const CF_IPV6_CIDRS: &[(u128, u8)] = &[
    // 2400:cb00::/32
    (0x2400_cb00_0000_0000_0000_0000_0000_0000, 32),
    // 2606:4700::/32
    (0x2606_4700_0000_0000_0000_0000_0000_0000, 32),
    // 2803:f800::/32
    (0x2803_f800_0000_0000_0000_0000_0000_0000, 32),
    // 2405:b500::/32
    (0x2405_b500_0000_0000_0000_0000_0000_0000, 32),
    // 2405:8100::/32
    (0x2405_8100_0000_0000_0000_0000_0000_0000, 32),
    // 2a06:98c0::/29
    (0x2a06_98c0_0000_0000_0000_0000_0000_0000, 29),
    // 2c0f:f248::/32
    (0x2c0f_f248_0000_0000_0000_0000_0000_0000, 32),
];

fn is_cloudflare_ip(ip_str: &str) -> bool {
    let Ok(addr) = ip_str.parse::<IpAddr>() else {
        return false;
    };
    match addr {
        IpAddr::V4(v4) => {
            let ip = u32::from(v4);
            CF_IPV4_CIDRS.iter().any(|&(network, prefix_len)| {
                let mask = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
                (ip & mask) == (network & mask)
            })
        }
        IpAddr::V6(v6) => {
            let ip = u128::from(v6);
            CF_IPV6_CIDRS.iter().any(|&(network, prefix_len)| {
                let mask = if prefix_len == 0 { 0 } else { !0u128 << (128 - prefix_len) };
                (ip & mask) == (network & mask)
            })
        }
    }
}

/// Returns true for loopback and RFC1918/private IPs — not useful as a client IP.
fn is_private_ip(ip_str: &str) -> bool {
    let Ok(addr) = ip_str.parse::<IpAddr>() else {
        return false;
    };
    match addr {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

fn is_untrusted_ip(ip_str: &str) -> bool {
    ip_str.is_empty() || is_cloudflare_ip(ip_str) || is_private_ip(ip_str)
}

#[derive(Serialize)]
struct IpInfo {
    ip: String,
    user_agent: String,
    accept_language: String,
    accept: String,
    country: String,
    city: String,
    region: String,
    timezone: String,
    colo: String,
    headers: Vec<(String, String)>,
}

impl IpInfo {
    fn from_request(_req: &Request, headers: &Headers) -> Self {
        let get = |name: &str| -> String {
            headers.get(name).ok().flatten().unwrap_or_default()
        };

        // Collect all headers
        let all_headers: Vec<(String, String)> = headers
            .entries()
            .collect();

        // Extract real client IP, skipping CF proxy and private/loopback IPs
        let ip = {
            let cf = get("cf-connecting-ip");
            if !is_untrusted_ip(&cf) {
                cf
            } else {
                let real = get("x-real-ip");
                if !is_untrusted_ip(&real) {
                    real
                } else {
                    let fwd = get("x-forwarded-for");
                    if !fwd.is_empty() {
                        // Walk the chain, pick the first non-CF, non-private IP
                        fwd.split(',')
                            .map(|s| s.trim())
                            .find(|ip| !is_untrusted_ip(ip))
                            .unwrap_or_default()
                            .to_string()
                    } else {
                        String::new()
                    }
                }
            }
        }
        .trim().to_string();
        let ip = if ip.is_empty() { "unknown".to_string() } else { ip };

        IpInfo {
            ip,
            user_agent: get("user-agent"),
            accept_language: get("accept-language"),
            accept: get("accept"),
            country: get("cf-ipcountry"),
            city: get("cf-ipcity"),
            region: get("cf-region"),
            timezone: get("cf-timezone"),
            colo: get("cf-ray").split('-').next_back().unwrap_or_default().to_string(),
            headers: all_headers,
        }
    }

    fn to_plain_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("IP:              {}\n", self.ip));
        if !self.country.is_empty() {
            out.push_str(&format!("Country:         {}\n", self.country));
        }
        if !self.city.is_empty() {
            out.push_str(&format!("City:            {}\n", self.city));
        }
        if !self.region.is_empty() {
            out.push_str(&format!("Region:          {}\n", self.region));
        }
        if !self.timezone.is_empty() {
            out.push_str(&format!("Timezone:        {}\n", self.timezone));
        }
        if !self.colo.is_empty() {
            out.push_str(&format!("Colo:            {}\n", self.colo));
        }
        out.push_str(&format!("User-Agent:      {}\n", self.user_agent));
        if !self.accept_language.is_empty() {
            out.push_str(&format!("Accept-Language: {}\n", self.accept_language));
        }
        out
    }

    fn to_html(&self) -> String {
        let mut header_rows = String::new();
        for (k, v) in &self.headers {
            header_rows.push_str(&format!(
                "<tr><td>{}</td><td>{}</td></tr>",
                html_escape(k),
                html_escape(v)
            ));
        }

        let mut geo_section = String::new();
        let geo_fields = [
            ("Country", &self.country),
            ("City", &self.city),
            ("Region", &self.region),
            ("Timezone", &self.timezone),
            ("Colo", &self.colo),
        ];
        for (label, val) in &geo_fields {
            if !val.is_empty() {
                geo_section.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td></tr>",
                    label,
                    html_escape(val)
                ));
            }
        }

        format!(
            r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IP Info</title>
<style>
  :root {{ --bg: #0a0a0a; --card: #141414; --border: #2a2a2a; --text: #e0e0e0; --dim: #888; --accent: #6cf; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace; background: var(--bg); color: var(--text); min-height: 100vh; display: flex; justify-content: center; padding: 2rem 1rem; }}
  .container {{ max-width: 720px; width: 100%; }}
  h1 {{ font-size: 1.1rem; color: var(--accent); margin-bottom: 1.5rem; font-weight: 500; }}
  .ip-display {{ font-size: 2.5rem; font-weight: 700; color: #fff; margin-bottom: 2rem; letter-spacing: -0.02em; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1.5rem; overflow: hidden; }}
  .card-title {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--dim); padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); }}
  table {{ width: 100%; border-collapse: collapse; }}
  td {{ padding: 0.5rem 1rem; font-size: 0.85rem; }}
  tr:not(:last-child) td {{ border-bottom: 1px solid var(--border); }}
  td:first-child {{ color: var(--dim); width: 35%; white-space: nowrap; }}
  td:last-child {{ word-break: break-all; }}
  .footer {{ text-align: center; color: var(--dim); font-size: 0.7rem; margin-top: 2rem; }}
  .footer a {{ color: var(--accent); text-decoration: none; }}
</style>
</head>
<body>
<div class="container">
  <h1>$ curl ip.YOUR_DOMAIN</h1>
  <div class="ip-display">{ip}</div>

  <div class="card">
    <div class="card-title">Client</div>
    <table>
      <tr><td>User-Agent</td><td>{ua}</td></tr>
      <tr><td>Accept-Language</td><td>{lang}</td></tr>
    </table>
  </div>

  {geo_card}

  <div class="card">
    <div class="card-title">All Headers</div>
    <table>{header_rows}</table>
  </div>

  <div class="footer">
    <a href="https://github.com/johnwmail/ipinfo">ipinfo v{version}</a></br>
    Powered by Rust + Wasm on Cloudflare Workers
  </div>
</div>
</body>
</html>"##,
            ip = html_escape(&self.ip),
            ua = html_escape(&self.user_agent),
            lang = html_escape(&self.accept_language),
            geo_card = if geo_section.is_empty() {
                String::new()
            } else {
                format!(
                    "<div class=\"card\"><div class=\"card-title\">Geo</div><table>{}</table></div>",
                    geo_section
                )
            },
            header_rows = header_rows,
            version = VERSION,
        )
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn is_browser(accept: &str) -> bool {
    accept.contains("text/html")
}

#[event(fetch)]
async fn fetch(req: Request, _env: Env, _ctx: Context) -> Result<Response> {
    let headers = req.headers();
    let info = IpInfo::from_request(&req, headers);

    // Route: /json — always return JSON
    let path = req.path();
    if path == "/json" {
        let json = serde_json::to_string_pretty(&info).unwrap_or_default();
        let mut resp = Response::ok(json)?;
        resp.headers_mut().set("Content-Type", "application/json; charset=utf-8")?;
        resp.headers_mut().set("Access-Control-Allow-Origin", "*")?;
        return Ok(resp);
    }

    // Route: /ip — always return plain IP
    if path == "/ip" {
        let mut resp = Response::ok(format!("{}\n", info.ip))?;
        resp.headers_mut().set("Content-Type", "text/plain; charset=utf-8")?;
        return Ok(resp);
    }

    // Route: / — content negotiation
    if is_browser(&info.accept) {
        let mut resp = Response::ok(info.to_html())?;
        resp.headers_mut().set("Content-Type", "text/html; charset=utf-8")?;
        Ok(resp)
    } else {
        // curl / wget / CLI
        let mut resp = Response::ok(info.to_plain_text())?;
        resp.headers_mut().set("Content-Type", "text/plain; charset=utf-8")?;
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- is_cloudflare_ip ---

    #[test]
    fn cf_ip_173_245_48_1() {
        assert!(is_cloudflare_ip("173.245.48.1"));
    }

    #[test]
    fn cf_ip_104_16_0_1() {
        assert!(is_cloudflare_ip("104.16.0.1"));
    }

    #[test]
    fn cf_ip_162_158_0_1() {
        assert!(is_cloudflare_ip("162.158.0.1"));
    }

    #[test]
    fn cf_ip_172_64_0_1() {
        assert!(is_cloudflare_ip("172.64.0.1"));
    }

    #[test]
    fn cf_ip_131_0_72_1() {
        assert!(is_cloudflare_ip("131.0.72.1"));
    }

    #[test]
    fn cf_ipv6_2400_cb00() {
        assert!(is_cloudflare_ip("2400:cb00::1"));
    }

    #[test]
    fn cf_ipv6_2606_4700() {
        assert!(is_cloudflare_ip("2606:4700::1"));
    }

    #[test]
    fn not_cf_ip_8_8_8_8() {
        assert!(!is_cloudflare_ip("8.8.8.8"));
    }

    #[test]
    fn not_cf_ip_203_0_113_50() {
        assert!(!is_cloudflare_ip("203.0.113.50"));
    }

    #[test]
    fn not_cf_ipv6_2001_db8() {
        assert!(!is_cloudflare_ip("2001:db8::1"));
    }

    #[test]
    fn cf_ip_invalid_string() {
        assert!(!is_cloudflare_ip("not-an-ip"));
    }

    #[test]
    fn cf_ip_empty() {
        assert!(!is_cloudflare_ip(""));
    }

    // --- is_private_ip ---

    #[test]
    fn private_loopback() {
        assert!(is_private_ip("127.0.0.1"));
    }

    #[test]
    fn private_10_x() {
        assert!(is_private_ip("10.0.0.1"));
    }

    #[test]
    fn private_172_16_x() {
        assert!(is_private_ip("172.16.0.1"));
    }

    #[test]
    fn private_192_168_x() {
        assert!(is_private_ip("192.168.1.1"));
    }

    #[test]
    fn private_ipv6_loopback() {
        assert!(is_private_ip("::1"));
    }

    #[test]
    fn not_private_public_ip() {
        assert!(!is_private_ip("8.8.8.8"));
    }

    #[test]
    fn not_private_cf_ip() {
        // CF IPs are not private, they're filtered separately
        assert!(!is_private_ip("104.16.0.1"));
    }

    // --- is_untrusted_ip ---

    #[test]
    fn untrusted_empty() {
        assert!(is_untrusted_ip(""));
    }

    #[test]
    fn untrusted_private() {
        assert!(is_untrusted_ip("127.0.0.1"));
    }

    #[test]
    fn untrusted_cf() {
        assert!(is_untrusted_ip("104.16.0.1"));
    }

    #[test]
    fn trusted_public() {
        assert!(!is_untrusted_ip("203.0.113.50"));
    }

    // --- html_escape ---

    #[test]
    fn escape_ampersand() {
        assert_eq!(html_escape("a&b"), "a&amp;b");
    }

    #[test]
    fn escape_angle_brackets() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
    }

    #[test]
    fn escape_quotes() {
        assert_eq!(html_escape(r#"say "hi""#), "say &quot;hi&quot;");
    }

    #[test]
    fn escape_clean_string() {
        assert_eq!(html_escape("hello world"), "hello world");
    }

    // --- is_browser ---

    #[test]
    fn browser_accept_html() {
        assert!(is_browser("text/html,application/xhtml+xml,application/xml;q=0.9"));
    }

    #[test]
    fn not_browser_curl() {
        assert!(!is_browser("*/*"));
    }

    #[test]
    fn not_browser_json() {
        assert!(!is_browser("application/json"));
    }

    #[test]
    fn not_browser_empty() {
        assert!(!is_browser(""));
    }

    // --- IpInfo output ---

    fn make_info(ip: &str, country: &str, city: &str) -> IpInfo {
        IpInfo {
            ip: ip.to_string(),
            user_agent: "curl/8.0".to_string(),
            accept_language: "en-US".to_string(),
            accept: "*/*".to_string(),
            country: country.to_string(),
            city: city.to_string(),
            region: String::new(),
            timezone: String::new(),
            colo: "SJC".to_string(),
            headers: vec![
                ("user-agent".to_string(), "curl/8.0".to_string()),
            ],
        }
    }

    #[test]
    fn plain_text_has_ip() {
        let info = make_info("1.2.3.4", "US", "San Jose");
        let text = info.to_plain_text();
        assert!(text.contains("1.2.3.4"));
        assert!(text.contains("US"));
        assert!(text.contains("San Jose"));
        assert!(text.contains("curl/8.0"));
    }

    #[test]
    fn plain_text_omits_empty_fields() {
        let info = make_info("1.2.3.4", "", "");
        let text = info.to_plain_text();
        assert!(!text.contains("Country"));
        assert!(!text.contains("City"));
    }

    #[test]
    fn html_has_ip() {
        let info = make_info("1.2.3.4", "US", "");
        let html = info.to_html();
        assert!(html.contains("1.2.3.4"));
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("US"));
    }

    #[test]
    fn html_escapes_xss() {
        let mut info = make_info("1.2.3.4", "", "");
        info.user_agent = "<script>alert(1)</script>".to_string();
        let html = info.to_html();
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn html_no_geo_card_when_empty() {
        let info = make_info("1.2.3.4", "", "");
        // colo is set, so geo card should still appear
        let html = info.to_html();
        assert!(html.contains("SJC"));
    }
}
