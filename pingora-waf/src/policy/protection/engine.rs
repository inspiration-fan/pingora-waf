use crate::policy::cc::{CcLimiter, CcParams};
use crate::waf::context::WafContext;
use crate::waf::decision::Decision;
use crate::metrics;

use super::compiled::{CompiledAction, CompiledRule};
use super::key::build_key;
use super::matcher::{self, HeaderView};

pub struct ProtectionEngine;

impl ProtectionEngine {
    pub fn eval_rules(
        rules: &[CompiledRule],
        wctx: &WafContext,
        headers: &dyn HeaderView,
        limiter: &CcLimiter,
    ) -> Decision {
        for r in rules {
            if !matcher::eval(&r.matcher, wctx, headers) {
                continue;
            }
            let d = Self::exec_action(&r.id, &r.action, wctx, headers, limiter);

            // Log 不终止，并且我们把 log 当作 side-effect，因此这里直接继续
            if d.is_terminal() {
                return d;
            } else {
                // allow/log 都算一次命中，可选
                // metrics::inc(d.kind_str(), &r.id);
            }
        }
        Decision::Allow
    }

    fn exec_action(
        rule_id: &str,
        action: &CompiledAction,
        wctx: &WafContext,
        headers: &dyn HeaderView,
        limiter: &CcLimiter,
    ) -> Decision {
        match action {
            CompiledAction::Allow { .. } => Decision::Allow,

            // ✅ 这里把 Log 当 side-effect：记录后返回 Allow
            CompiledAction::Log { reason } => {
                tracing::info!(rule_id=%rule_id, reason=%reason, host=?wctx.host, path=%wctx.path, "protection log");
                Decision::Allow
            }

            CompiledAction::Block { status, reason } => Decision::Block {
                status: *status,
                rule_id: rule_id.to_string(),
                reason: reason.clone(),
            },

            CompiledAction::Challenge { status, reason } => Decision::Challenge {
                status: *status,
                rule_id: rule_id.to_string(),
                reason: reason.clone(),
            },

            CompiledAction::Cc { key_parts, window_secs, max_requests, block_secs, on_limit } => {
                let key_body = build_key(key_parts, wctx, headers);

                let params = CcParams {
                    window_secs: *window_secs,
                    max_requests: *max_requests,
                    block_secs: *block_secs,
                };

                if let Some(hit) = limiter.check(rule_id, &key_body, params) {
                    // 超限后执行 on_limit（只允许 log/block/challenge；log 也不终止）
                    crate::metrics::counters::inc_cc_hit(rule_id);
                    return match &**on_limit {
                        CompiledAction::Log { reason } => {
                            tracing::warn!(
                                rule_id=%rule_id,
                                hit_reason=%hit.reason,
                                on_limit_reason=%reason,
                                host=?wctx.host,
                                path=%wctx.path,
                                "cc on_limit log"
                            );
                            Decision::Allow
                        }

                        CompiledAction::Challenge { status, reason } => Decision::Challenge {
                            status: *status,
                            rule_id: rule_id.to_string(),
                            reason: format!("{}; {}", hit.reason, reason),
                        },

                        CompiledAction::Block { status, reason } => Decision::Block {
                            status: *status,
                            rule_id: rule_id.to_string(),
                            reason: format!("{}; {}", hit.reason, reason),
                        },

                        // 理论上不会发生（编译阶段已限制），这里兜底
                        _ => Decision::Block {
                            status: 429,
                            rule_id: rule_id.to_string(),
                            reason: hit.reason,
                        },
                    };
                }

                Decision::Allow
            }
        }
    }
}
