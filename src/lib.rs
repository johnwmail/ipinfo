use serde::Serialize;
use serde_json;
use worker::*;

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
            .map(|(k, v)| (k, v))
            .collect();

        // CF headers for geo info
        let ip = {
            let cf = get("cf-connecting-ip");
            if !cf.is_empty() {
                cf
            } else {
                let real = get("x-real-ip");
                if !real.is_empty() {
                    real
                } else {
                    let fwd = get("x-forwarded-for");
                    if !fwd.is_empty() {
                        fwd.split(',').next().unwrap_or_default().trim().to_string()
                    } else {
                        "unknown".to_string()
                    }
                }
            }
        };

        IpInfo {
            ip,
            user_agent: get("user-agent"),
            accept_language: get("accept-language"),
            accept: get("accept"),
            country: get("cf-ipcountry"),
            city: get("cf-ipcity"),
            region: get("cf-region"),
            timezone: get("cf-timezone"),
            colo: get("cf-ray").split('-').last().unwrap_or_default().to_string(),
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

  <div class="footer">Powered by Rust + Wasm on Cloudflare Workers</div>
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
    let info = IpInfo::from_request(&req, &headers);

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
