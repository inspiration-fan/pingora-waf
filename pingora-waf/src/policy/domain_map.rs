use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
pub struct DomainMapFile {
    pub version: u32,
    pub domains: HashMap<String, DomainTarget>,
    pub default_policy: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DomainTarget {
    pub policy: String,
}

/// 运行时匹配器：支持
/// - 精确域名：www.a.com
/// - 通配符：*.img.a.com（只支持前缀 "*." 这一种）
#[derive(Debug, Clone)]
pub struct DomainMatcher {
    exact: HashMap<String, String>,
    wildcard_suffix: Vec<(String, String)>, // (suffix_without_star, policy_id)
    default_policy: String,
}

impl DomainMatcher {
    pub fn from_file(f: DomainMapFile) -> Self {
        let mut exact = HashMap::new();
        let mut wildcard_suffix = Vec::new();

        for (k, v) in f.domains {
            let key = k.to_ascii_lowercase();
            if let Some(suf) = key.strip_prefix("*.") {
                wildcard_suffix.push((suf.to_string(), v.policy));
            } else {
                exact.insert(key, v.policy);
            }
        }

        // 通配符 suffix 越长优先级越高（更具体）
        wildcard_suffix.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        Self {
            exact,
            wildcard_suffix,
            default_policy: f.default_policy,
        }
    }

    pub fn match_policy_id(&self, host: &str) -> String {
        let h = host.to_ascii_lowercase();

        if let Some(p) = self.exact.get(&h) {
            return p.clone();
        }

        for (suf, p) in &self.wildcard_suffix {
            if h == *suf || h.ends_with(&format!(".{}", suf)) {
                return p.clone();
            }
        }

        self.default_policy.clone()
    }

    pub fn default_policy(&self) -> &str {
        &self.default_policy
    }
}
