use pingora::http::RequestHeader;

use crate::waf::context::WafContext;
use crate::waf::decision::Decision;
use crate::waf::engine::WafEngine;

use super::manager::PolicyManager;
use super::protection::engine::ProtectionEngine;
use super::protection::matcher::HeaderView;

struct ReqHeaderView<'a> {
    req: &'a RequestHeader,
}

impl<'a> HeaderView for ReqHeaderView<'a> {
    fn get(&self, name: &str) -> Option<&str> {
        self.req.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

pub struct EnforceResult {
    pub decision: Decision,
    pub policy_id: String,
    pub req_body_rules: Vec<usize>,
    pub resp_body_rules: Vec<usize>,
}

#[derive(Clone)]
pub struct PolicyEnforcer {
    mgr: PolicyManager,
    engine: WafEngine,
}

impl PolicyEnforcer {
    pub fn new(mgr: PolicyManager, engine: WafEngine) -> Self {
        Self { mgr, engine }
    }

    pub fn enforce_request_headers(&self, wctx: &WafContext, req: &RequestHeader) -> EnforceResult {
        let host = wctx.host.as_deref().unwrap_or("");
        let policy = self.mgr.get_policy_for_host(host);
        let policy_id = policy.id.clone();

        let hv = ReqHeaderView { req };

        let st = self.mgr.load();
        let limiter = st.cc.as_ref();

        // 1) precise
        let d1 = ProtectionEngine::eval_rules(&policy.precise, wctx, &hv, limiter);
        if d1.is_terminal() {
            return EnforceResult { decision: d1, policy_id, req_body_rules: vec![], resp_body_rules: vec![] };
        }

        // 2) base
        let d2 = ProtectionEngine::eval_rules(&policy.base, wctx, &hv, limiter);
        if d2.is_terminal() {
            return EnforceResult { decision: d2, policy_id, req_body_rules: vec![], resp_body_rules: vec![] };
        }

        // 3) WAF switch
        if !policy.waf.enabled {
            return EnforceResult { decision: Decision::Allow, policy_id, req_body_rules: vec![], resp_body_rules: vec![] };
        }

        let (decision, req_body_rules, resp_body_rules) = self.engine.eval_request_headers(wctx);
        EnforceResult { decision, policy_id, req_body_rules, resp_body_rules }
    }
}
