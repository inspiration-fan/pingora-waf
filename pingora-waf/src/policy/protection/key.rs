use crate::waf::context::WafContext;

use super::cookie::get_cookie_value;
use super::matcher::HeaderView;

pub fn build_key(parts: &[String], wctx: &WafContext, headers: &dyn HeaderView) -> String {
    let mut out = String::new();
    let cookie_header = headers.get("cookie");

    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            out.push('|');
        }
        out.push_str(p);
        out.push('=');
        out.push_str(&part_value(p, wctx, headers, cookie_header));
    }
    out
}

fn part_value(part: &str, wctx: &WafContext, headers: &dyn HeaderView, cookie_header: Option<&str>) -> String {
    match part {
        "client_ip" => wctx.client_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "0.0.0.0".to_string()),
        "host" => wctx.host.clone().unwrap_or_default(),
        "path" => wctx.path.clone(),
        "method" => wctx.method.clone(),
        "user_agent" => wctx.user_agent.clone().unwrap_or_default(),

        _ => {
            if let Some(name) = part.strip_prefix("header:") {
                return headers.get(name).unwrap_or("").to_string();
            }
            if let Some(name) = part.strip_prefix("cookie:") {
                if let Some(ch) = cookie_header {
                    return get_cookie_value(ch, name).unwrap_or("").to_string();
                }
                return String::new();
            }
            String::new()
        }
    }
}
