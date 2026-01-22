use crate::obs::{AccessLog, ObsSink, SecurityEvent};
use crate::server::block_page::BlockPage;
use crate::upstream::{manager::UpstreamManager, router::UpstreamRouter};
use crate::waf::context::WafContext;
use crate::waf::decision::Decision;
use crate::waf::engine::WafEngine;
use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora_proxy::{ProxyHttp, Session};
use crate::policy::enforcer::PolicyEnforcer;
use crate::policy::manager::PolicyManager;
use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicU64, Ordering};

static REQ_COUNTER: Lazy<AtomicU64> = Lazy::new(|| AtomicU64::new(1));

fn gen_request_id() -> String {
    // Low-overhead request id: timestamp(ms) + monotonic counter.
    let n = REQ_COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts = Utc::now().timestamp_millis();
    format!("req-{}-{:x}", ts, n)
}

#[derive(Clone)]
pub struct WafProxy {
    pub engine: WafEngine,
    pub upstream_mgr: UpstreamManager,
    block_page: BlockPage,
    pub policy_mgr: PolicyManager,
    pub enforcer: PolicyEnforcer,
    pub obs: ObsSink,
}

impl WafProxy {
    pub fn new(engine: WafEngine, upstream_mgr: UpstreamManager, policy_mgr: PolicyManager, obs: ObsSink) -> Self {
        let block_page = BlockPage::load_from_assets().unwrap();
        let enforcer = PolicyEnforcer::new(policy_mgr.clone(), engine.clone());

        Self { engine, upstream_mgr, block_page, policy_mgr, enforcer, obs }
    }
}

#[derive(Default)]
pub struct ProxyCtx {
    pub ctx: Option<WafContext>,

    pub request_id: Option<String>,
    pub edge_key: Option<String>,
    pub upstream: Option<String>,
    pub policy_id: Option<String>,
    pub action: Option<String>,
    pub decision_status: Option<u16>,

    // request body scan
    pub req_tail: Vec<u8>,
    pub req_body_rules: Vec<usize>,

    // response body scan
    pub resp_tail: Vec<u8>,
    pub resp_body_rules: Vec<usize>,

    pub blocked: bool,

    pub start: Option<std::time::Instant>,
    pub host: Option<String>,
}

impl WafProxy {
    async fn write_block_html(&self, session: &mut Session, status: u16, rule_id: &str, reason: &str, request_id: &str) -> pingora::Result<()> {
        let html = self
            .block_page
            .render_403(status, "Forbidden", rule_id, reason, request_id);
        let body = Bytes::from(html);
        let len = body.len().to_string();

        let mut resp = ResponseHeader::build(status, None)?;
        resp.insert_header("content-type", "text/html; charset=utf-8")?;
        resp.insert_header("content-length", len.as_str())?;
        resp.insert_header("cache-control", "no-store")?;
        resp.insert_header("x-request-id", request_id)?;

        session.write_response_header(Box::new(resp), false).await?;
        session.write_response_body(Some(body), true).await?;
        Ok(())
    }

    async fn write_block_text(session: &mut Session, status: u16, msg: &str, request_id: &str) -> pingora::Result<()> {
        let body = Bytes::from(msg.to_string());
        let len = body.len().to_string();

        let mut resp = ResponseHeader::build(status, None)?;
        resp.insert_header("content-type", "text/plain; charset=utf-8")?;
        resp.insert_header("content-length", len.as_str())?;
        resp.insert_header("cache-control", "no-store")?;
        resp.insert_header("x-request-id", request_id)?;

        session.write_response_header(Box::new(resp), false).await?;
        session.write_response_body(Some(body), true).await?;
        Ok(())
    }

    fn log_event(&self, ctx: &ProxyCtx, wctx: &WafContext, action: &str, rule_id: &str, reason: &str, phase: &str, status: u16) {
        let request_id = ctx.request_id.clone().unwrap_or_else(|| "".to_string());
        let edge_key = ctx.edge_key.clone().unwrap_or_else(|| "default".to_string());
        let policy_id = ctx.policy_id.clone().unwrap_or_else(|| "unknown".to_string());
        self.obs.write_event(&SecurityEvent {
            ts: Utc::now(),
            request_id,
            edge_key,
            policy_id,
            action: action.to_string(),
            rule_id: rule_id.to_string(),
            reason: reason.to_string(),
            phase: phase.to_string(),
            status,
            host: wctx.host.clone().unwrap_or_else(|| "unknown".to_string()),
            path: wctx.path.clone(),
            method: wctx.method.clone(),
            client_ip: wctx.client_ip.map(|ip| ip.to_string()),
        });
    }
}

#[async_trait]
impl ProxyHttp for WafProxy {
    type CTX = ProxyCtx;

    fn new_ctx(&self) -> Self::CTX {
        ProxyCtx::default()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> pingora::Result<bool> {
        ctx.start = Some(std::time::Instant::now());

        let request_id = gen_request_id();
        ctx.request_id = Some(request_id.clone());

        let wctx = WafContext::from_session(session).await?;
        let host = wctx.host.clone().unwrap_or_else(|| "unknown".to_string());
        ctx.host = Some(host.clone());
        crate::metrics::counters::on_req_start(&host);

        // Resolve edge_key + upstream early so blocked requests still have edge_key.
        let router = self.upstream_mgr.get();
        let (edge_key, upstream) = router.pick_endpoint_and_edge_key(Some(&host)).await;
        ctx.edge_key = Some(edge_key);
        ctx.upstream = Some(upstream);

        let req = session.req_header();
        let r = self.enforcer.enforce_request_headers(&wctx, req);

        ctx.ctx = Some(wctx.clone());
        ctx.policy_id = Some(r.policy_id.clone());
        ctx.req_body_rules = r.req_body_rules;
        ctx.resp_body_rules = r.resp_body_rules;
        ctx.action = Some(r.decision.kind_str().to_string());

        match r.decision {
            Decision::Allow => Ok(false),
            Decision::Log { reason, rule_id } => {
                self.log_event(ctx, &wctx, "log", &rule_id, &reason, "request_headers", 0);
                tracing::info!(%rule_id, %reason, "policy log");
                Ok(false)
            }
            Decision::Block { status, reason, rule_id } => {
                ctx.blocked = true;
                ctx.decision_status = Some(status);
                self.log_event(ctx, &wctx, "block", &rule_id, &reason, "request_headers", status);
                self.write_block_html(session, status, &rule_id, &reason, &request_id).await?;
                Ok(true)
            }
            Decision::Challenge { status, reason, rule_id } => {
                ctx.blocked = true;
                ctx.decision_status = Some(status);
                self.log_event(ctx, &wctx, "challenge", &rule_id, &reason, "request_headers", status);
                Self::write_block_text(session, status, &format!("challenge: {reason}"), &request_id).await?;
                Ok(true)
            }
        }
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        _end: bool,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        if ctx.blocked || ctx.req_body_rules.is_empty() {
            return Ok(());
        }
        let Some(chunk) = body.as_ref() else {
            return Ok(());
        };

        let ruleset = self.engine.rules_snapshot();
        let mut keep = 0usize;
        for &idx in &ctx.req_body_rules {
            if let Some(r) = ruleset.rules.get(idx) {
                keep = keep.max(r.body_keep_len());
            }
        }

        let mut window = Vec::with_capacity(ctx.req_tail.len() + chunk.len());
        window.extend_from_slice(&ctx.req_tail);
        window.extend_from_slice(chunk);

        for &idx in &ctx.req_body_rules {
            if let Some(rule) = ruleset.rules.get(idx) {
                if rule.body_match(&window) {
                    ctx.blocked = true;
                    ctx.action = Some("block".to_string());
                    ctx.decision_status = Some(403);
                    *body = None;

                    let wctx = ctx.ctx.clone().unwrap_or_else(|| WafContext {
                        method: "UNKNOWN".to_string(),
                        path: "".to_string(),
                        client_ip: None,
                        host: ctx.host.clone(),
                        user_agent: None,
                    });

                    self.log_event(ctx, &wctx, "block", &rule.id, "request body match", "request_body", 403);

                    let rid = ctx.request_id.clone().unwrap_or_else(|| gen_request_id());
                    Self::write_block_text(session, 403, "blocked by WAF (request body)", &rid).await?;
                    return Ok(());
                }
            }
        }

        if keep > 0 {
            if window.len() > keep {
                ctx.req_tail = window[window.len() - keep..].to_vec();
            } else {
                ctx.req_tail = window;
            }
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end: bool,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Option<std::time::Duration>> {
        if ctx.blocked || ctx.resp_body_rules.is_empty() {
            return Ok(None);
        }
        let Some(chunk) = body.as_ref() else {
            return Ok(None);
        };

        let ruleset = self.engine.rules_snapshot();

        let mut keep = 0usize;
        for &idx in &ctx.resp_body_rules {
            if let Some(r) = ruleset.rules.get(idx) {
                keep = keep.max(r.body_keep_len());
            }
        }

        let mut window = Vec::with_capacity(ctx.resp_tail.len() + chunk.len());
        window.extend_from_slice(&ctx.resp_tail);
        window.extend_from_slice(chunk);

        for &idx in &ctx.resp_body_rules {
            if let Some(rule) = ruleset.rules.get(idx) {
                if rule.body_match(&window) {
                    ctx.blocked = true;
                    ctx.action = Some("block".to_string());
                    *body = None;

                    let wctx = ctx.ctx.clone().unwrap_or_else(|| WafContext {
                        method: "UNKNOWN".to_string(),
                        path: "".to_string(),
                        client_ip: None,
                        host: ctx.host.clone(),
                        user_agent: None,
                    });

                    self.log_event(ctx, &wctx, "block", &rule.id, "response body match", "response_body", 0);
                    return Ok(None);
                }
            }
        }

        if keep > 0 {
            if window.len() > keep {
                ctx.resp_tail = window[window.len() - keep..].to_vec();
            } else {
                ctx.resp_tail = window;
            }
        }

        Ok(None)
    }

    async fn logging(
        &self,
        session: &mut Session,
        err: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        let host = ctx.host.as_deref().unwrap_or("unknown");
        let elapsed = ctx
            .start
            .map(|s| s.elapsed().as_secs_f64())
            .unwrap_or(0.0);

        crate::metrics::counters::on_req_end(host, elapsed);
        let status = ctx.decision_status.unwrap_or(200);

        let wctx = ctx.ctx.clone().unwrap_or_else(|| WafContext {
            method: session.req_header().method.to_string(),
            path: session.req_header().uri.path().to_string(),
            client_ip: session
                .client_addr()
                .and_then(|a| a.to_string().parse::<std::net::SocketAddr>().ok())
                .map(|sa| sa.ip()),
            host: ctx.host.clone(),
            user_agent: None,
        });

        let access = AccessLog {
            ts: Utc::now(),
            request_id: ctx.request_id.clone().unwrap_or_else(|| "".to_string()),
            edge_key: ctx.edge_key.clone().unwrap_or_else(|| "default".to_string()),
            policy_id: ctx.policy_id.clone().unwrap_or_else(|| "unknown".to_string()),
            action: ctx.action.clone().unwrap_or_else(|| "allow".to_string()),
            method: wctx.method.clone(),
            host: wctx.host.clone().unwrap_or_else(|| host.to_string()),
            path: wctx.path.clone(),
            status,
            latency_ms: (elapsed * 1000.0) as u64,
            upstream: ctx.upstream.clone(),
            client_ip: wctx.client_ip.map(|ip| ip.to_string()),
            user_agent: wctx.user_agent.clone(),
            error: err.map(|e| e.to_string()),
        };

        self.obs.write_access(&access);
    }

    async fn upstream_peer(&self, session: &mut Session, ctx: &mut Self::CTX) -> pingora::Result<Box<HttpPeer>> {
        let host = ctx
            .ctx
            .as_ref()
            .and_then(|w| w.host.as_deref())
            .or_else(|| session.req_header().headers.get("host").and_then(|v| v.to_str().ok()));

        if ctx.upstream.is_none() {
            let router = self.upstream_mgr.get();
            let (edge_key, upstream) = router.pick_endpoint_and_edge_key(host).await;
            ctx.edge_key = Some(edge_key);
            ctx.upstream = Some(upstream);
        }

        let selected = ctx.upstream.clone().unwrap_or_else(|| "".to_string());
        let peer = UpstreamRouter::build_peer(&selected)
            .map_err(|_e| pingora::Error::new(pingora::ErrorType::InternalError))?;

        Ok(Box::new(peer))
    }
}
