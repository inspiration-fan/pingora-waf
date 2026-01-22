use crate::waf::normalizer::Normalizer;

#[derive(Debug, Clone)]
pub struct WafContext {
    pub method: String,
    pub path: String,
    pub client_ip: Option<std::net::IpAddr>,
    pub host: Option<String>,
    pub user_agent: Option<String>,

}

impl WafContext {
    pub async fn from_session(session: &mut pingora_proxy::Session) -> pingora::Result<Self> {
        let (method, path, host, user_agent) = {
            let req: &pingora::http::RequestHeader = session.req_header();

            let raw_path = req.uri.path().to_string();
            let path = Normalizer::normalize_path(&raw_path);

            // Host fix (HTTP/2 uses :authority). Pingora may expose it as "authority".
            let host = extract_host(req);
            let user_agent = req.headers.get("user-agent").and_then(|v| v.to_str().ok()).map(|s| s.to_string());

            (req.method.to_string(), path, host, user_agent)
        };

        let client_ip = session
            .client_addr()
            .and_then(|a| a.to_string().parse::<std::net::SocketAddr>().ok())
            .map(|sa| sa.ip());

        Ok(Self {
            method,
            path,
            client_ip,
            host,
            user_agent,
        })
    }
}

fn extract_host(req: &pingora::http::RequestHeader) -> Option<String> {
    // 1) "host" header (HTTP/1.1)
    let mut host = req
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // 2) "authority" header (HTTP/2 :authority)
    if host.is_none() {
        host = req
            .headers
            .get("authority")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
    }

    // 3) URI authority
    if host.is_none() {
        host = req.uri.authority().map(|a| a.as_str().to_string());
    }

    host.map(|h| normalize_host(&h))
}

fn normalize_host(host: &str) -> String {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    // Strip port if present.
    if h.starts_with('[') {
        // IPv6 literal, keep as-is (may include port)
        return h;
    }
    if let Some(i) = h.rfind(':') {
        let (left, right) = h.split_at(i);
        if right.len() > 1 && right[1..].chars().all(|c| c.is_ascii_digit()) {
            return left.to_string();
        }
    }
    h
}
