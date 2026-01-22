use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ProtectionsSpec {
    #[serde(default)]
    pub precise: Vec<RuleSpec>,
    #[serde(default)]
    pub base: Vec<RuleSpec>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleSpec {
    pub id: String,

    #[serde(rename = "match", default)]
    pub match_expr: MatchExpr,

    pub action: ActionSpec,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(untagged)] // 支持自然 YAML map，不需要 !Tag
pub enum MatchExpr {
    #[default]
    Any,

    PathPrefix { path_prefix: String },
    MethodIn { method_in: Vec<String> },
    HostIn { host_in: Vec<String> },

    HeaderExists { header_exists: String },
    HeaderEquals { header_equals: HeaderEq },
    HeaderRegex { header_regex: HeaderRegex },

    And { and: Vec<MatchExpr> },
    Or { or: Vec<MatchExpr> },
    Not { not: Box<MatchExpr> },
}

#[derive(Debug, Clone, Deserialize)]
pub struct HeaderEq {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HeaderRegex {
    pub name: String,
    pub pattern: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)] // ✅ 自然 YAML：action: { block: {...} } / { cc: {...} }
pub enum ActionSpec {
    Allow { allow: AllowSpec },
    Log { log: LogSpec },
    Block { block: BlockSpec },
    Challenge { challenge: BlockSpec },

    // ✅ 保留 cc 关键字
    Cc { cc: CcSpec },
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AllowSpec {
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LogSpec {
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockSpec {
    pub status: u16,
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CcSpec {
    pub key_parts: Vec<String>,
    pub window_secs: u64,
    pub max_requests: u64,
    pub block_secs: u64,

    /// 超限后执行的动作（仍然是统一 Action，只不过限制在 allow/log/block/challenge）
    pub on_limit: OnLimitActionSpec,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum OnLimitActionSpec {
    Log { log: LogSpec },
    Block { block: BlockSpec },
    Challenge { challenge: BlockSpec },
}
