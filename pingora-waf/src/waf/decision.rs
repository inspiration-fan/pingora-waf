

#[derive(Debug, Clone)]
pub enum Decision {
    Allow,

    Log {
        reason: String,
        rule_id: String,
    },

    Block {
        status: u16,
        reason: String,
        rule_id: String,
    },

    Challenge {
        status: u16,
        reason: String,
        rule_id: String,
    },
}

impl Decision {
    pub fn block(rule_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Block {
            status: 403,
            reason: reason.into(),
            rule_id: rule_id.into(),
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Decision::Block { .. } | Decision::Challenge { .. })
    }

    pub fn kind_str(&self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Log { .. } => "log",
            Decision::Block { .. } => "block",
            Decision::Challenge { .. } => "challenge",
        }
    }
}

impl Decision {
    pub fn allow() -> Self {
        Self::Allow
    }

    pub fn log(rule_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Log {
            reason: reason.into(),
            rule_id: rule_id.into(),
        }
    }



    pub fn block_with_status(status: u16, rule_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Block {
            status,
            reason: reason.into(),
            rule_id: rule_id.into(),
        }
    }

    pub fn challenge(rule_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Challenge {
            status: 403,
            reason: reason.into(),
            rule_id: rule_id.into(),
        }
    }


}
