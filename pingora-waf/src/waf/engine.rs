use std::sync::Arc;

use arc_swap::ArcSwap;

use super::context::WafContext;
use super::decision::Decision;
use super::rules::compiler::{CompiledRule, CompiledRuleset};
use crate::metrics;

#[derive(Clone)]
pub struct WafEngine {
    rules: Arc<ArcSwap<CompiledRuleset>>,
}

impl WafEngine {
    pub fn new(initial: CompiledRuleset) -> Self {
        Self {
            rules: Arc::new(ArcSwap::from_pointee(initial)),
        }
    }

    pub fn swap_rules(&self, new_rules: CompiledRuleset) {
        self.rules.store(Arc::new(new_rules));
    }

    pub fn rules_snapshot(&self) -> Arc<CompiledRuleset> {
        self.rules.load_full()
    }

    /// Evaluate request HEADERS only. Returns:
    /// (decision, request_body_rule_indexes, response_body_rule_indexes)
    ///
    /// For now:
    /// - uri_ac and path/method rules can decide immediately
    /// - body_ac rules are deferred to request_body_filter
    /// - (optional) response_body rules reuse the same body_ac set (can be split in DSL later)
    pub fn eval_request_headers(&self, ctx: &WafContext) -> (Decision, Vec<usize>, Vec<usize>) {
        let rs = self.rules_snapshot();
        let method = ctx.method.as_str();
        let path = ctx.path.as_str();
        let uri_bytes = path.as_bytes();

        let mut req_body_rules = Vec::new();
        let mut resp_body_rules = Vec::new();

        for (idx, rule) in rs.rules.iter().enumerate() {
            if let Some(ms) = &rule.methods {
                if !ms.iter().any(|m| m == method) {
                    continue;
                }
            }
            if let Some(pfxs) = &rule.path_prefix {
                if !pfxs.iter().any(|p| path.starts_with(p)) {
                    continue;
                }
            }
            if let Some(ac) = &rule.uri_ac {
                if !ac.is_match(uri_bytes) {
                    continue;
                }
            }

            // defer body scan
            if rule.body_ac.is_some() {
                req_body_rules.push(idx);
                // simple default: also scan response body for the same patterns
                resp_body_rules.push(idx);
                continue;
            }

            // matched w/o body => decide now
            let d = rule.action_to_decision();
            return (d, req_body_rules, resp_body_rules);
        }

        (Decision::Allow, req_body_rules, resp_body_rules)
    }
}

/// Helpers used by proxy streaming filters
impl CompiledRule {
    pub fn body_match(&self, window: &[u8]) -> bool {
        self.body_ac.as_ref().map(|ac| ac.is_match(window)).unwrap_or(false)
    }
    pub fn body_keep_len(&self) -> usize {
        self.body_ac
            .as_ref()
            .map(|ac| ac.max_pat_len().saturating_sub(1))
            .unwrap_or(0)
    }
}

impl CompiledRule {
    pub fn action_to_decision(&self) -> Decision {
        match self.action {
            super::rules::rule::Action::Allow => Decision::Allow,
            super::rules::rule::Action::Block => Decision::Block {
                status: 403,
                reason: "matched".into(),
                rule_id: self.id.clone(),
            },
            super::rules::rule::Action::Challenge => Decision::Challenge {
                status: 403,
                reason: "challenge".into(),
                rule_id: self.id.clone(),
            },
        }
    }
}



