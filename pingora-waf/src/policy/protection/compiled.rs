use regex::Regex;

use super::types::*;

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub id: String,
    pub matcher: CompiledMatchExpr,
    pub action: CompiledAction,
}

#[derive(Debug, Clone)]
pub enum CompiledMatchExpr {
    Any,

    PathPrefix(String),
    MethodIn(Vec<String>),
    HostIn(Vec<String>),

    HeaderExists(String),
    HeaderEquals { name: String, value: String },
    HeaderRegex { name: String, re: Regex },

    And(Vec<CompiledMatchExpr>),
    Or(Vec<CompiledMatchExpr>),
    Not(Box<CompiledMatchExpr>),
}

#[derive(Debug, Clone)]
pub enum CompiledAction {
    Allow { reason: Option<String> },
    Log { reason: String },

    Block { status: u16, reason: String },
    Challenge { status: u16, reason: String },

    /// ✅ CC 动作（保留 cc 关键字来源）
    Cc {
        key_parts: Vec<String>,
        window_secs: u64,
        max_requests: u64,
        block_secs: u64,
        on_limit: Box<CompiledAction>, // 只会是 log/block/challenge
    },
}

pub fn compile_rules(rs: &[RuleSpec]) -> anyhow::Result<Vec<CompiledRule>> {
    let mut out = Vec::with_capacity(rs.len());
    for r in rs {
        out.push(CompiledRule {
            id: r.id.clone(),
            matcher: compile_match(&r.match_expr)?,
            action: compile_action(&r.action)?,
        });
    }
    Ok(out)
}

fn compile_match(m: &MatchExpr) -> anyhow::Result<CompiledMatchExpr> {
    Ok(match m {
        MatchExpr::Any => CompiledMatchExpr::Any,

        MatchExpr::PathPrefix { path_prefix } => CompiledMatchExpr::PathPrefix(path_prefix.clone()),
        MatchExpr::MethodIn { method_in } => CompiledMatchExpr::MethodIn(method_in.clone()),
        MatchExpr::HostIn { host_in } => CompiledMatchExpr::HostIn(host_in.clone()),

        MatchExpr::HeaderExists { header_exists } => CompiledMatchExpr::HeaderExists(header_exists.clone()),

        MatchExpr::HeaderEquals { header_equals } => CompiledMatchExpr::HeaderEquals {
            name: header_equals.name.to_ascii_lowercase(),
            value: header_equals.value.clone(),
        },

        MatchExpr::HeaderRegex { header_regex } => {
            let re = Regex::new(&header_regex.pattern)
                .map_err(|e| anyhow::anyhow!("bad header_regex pattern for {}: {}", header_regex.name, e))?;
            CompiledMatchExpr::HeaderRegex {
                name: header_regex.name.to_ascii_lowercase(),
                re,
            }
        }

        MatchExpr::And { and } => {
            let mut xs = Vec::with_capacity(and.len());
            for x in and {
                xs.push(compile_match(x)?);
            }
            CompiledMatchExpr::And(xs)
        }

        MatchExpr::Or { or } => {
            let mut xs = Vec::with_capacity(or.len());
            for x in or {
                xs.push(compile_match(x)?);
            }
            CompiledMatchExpr::Or(xs)
        }

        MatchExpr::Not { not } => CompiledMatchExpr::Not(Box::new(compile_match(not)?)),
    })
}

fn compile_action(a: &ActionSpec) -> anyhow::Result<CompiledAction> {
    Ok(match a {
        ActionSpec::Allow { allow } => CompiledAction::Allow { reason: allow.reason.clone() },

        ActionSpec::Log { log } => CompiledAction::Log { reason: log.reason.clone() },

        ActionSpec::Block { block } => CompiledAction::Block { status: block.status, reason: block.reason.clone() },

        ActionSpec::Challenge { challenge } => CompiledAction::Challenge {
            status: challenge.status,
            reason: challenge.reason.clone(),
        },

        ActionSpec::Cc { cc } => {
            let on = match &cc.on_limit {
                OnLimitActionSpec::Log { log } => CompiledAction::Log { reason: log.reason.clone() },
                OnLimitActionSpec::Block { block } => CompiledAction::Block { status: block.status, reason: block.reason.clone() },
                OnLimitActionSpec::Challenge { challenge } => CompiledAction::Challenge { status: challenge.status, reason: challenge.reason.clone() },
            };
            CompiledAction::Cc {
                key_parts: cc.key_parts.clone(),
                window_secs: cc.window_secs,
                max_requests: cc.max_requests,
                block_secs: cc.block_secs,
                on_limit: Box::new(on),
            }
        }
    })
}
