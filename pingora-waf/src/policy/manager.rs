use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Context;
use arc_swap::ArcSwap;
use crate::policy::cc::CcLimiter;
use super::{
    compiled::{compile_policy, CompiledPolicy},
    domain_map::{DomainMapFile, DomainMatcher},
    types::PolicyFile,
};

#[derive(Clone)]
pub struct PolicyManager {
    state: Arc<ArcSwap<PolicyState>>,
}

#[derive(Debug)]
pub struct PolicyState {
    pub matcher: DomainMatcher,
    pub policies: HashMap<String, Arc<CompiledPolicy>>,
    pub cc: Arc<CcLimiter>, // 仍保留：action.cc 用它做状态
}

impl PolicyManager {
    pub fn new(initial: PolicyState) -> Self {
        Self {
            state: Arc::new(ArcSwap::from(Arc::new(initial))),
        }
    }

    pub fn load(&self) -> Arc<PolicyState> {
        self.state.load_full()
    }

    pub fn swap(&self, new_state: PolicyState) {
        self.state.store(Arc::new(new_state));
    }

    pub fn get_policy_for_host(&self, host: &str) -> Arc<CompiledPolicy> {
        let st = self.load();
        let pid = st.matcher.match_policy_id(host);

        st.policies
            .get(&pid)
            .cloned()
            .or_else(|| st.policies.get(st.matcher.default_policy()).cloned())
            .unwrap_or_else(|| {
                Arc::new(CompiledPolicy {
                    version: 1,
                    id: "policy-fallback".to_string(),
                    waf: Default::default(),
                    precise: vec![],
                    base: vec![],
                })
            })
    }

    pub fn load_from_files(domain_map_path: &Path, policies_dir: &Path) -> anyhow::Result<PolicyState> {
        let dm_bytes = std::fs::read(domain_map_path)
            .with_context(|| format!("read domain_map failed: {}", domain_map_path.display()))?;
        let dm: DomainMapFile = serde_yaml::from_slice(&dm_bytes)
            .with_context(|| "parse domain_map yaml failed")?;
        let matcher = DomainMatcher::from_file(dm);

        let policies = load_and_compile_policies_dir(policies_dir)?;

        let default_id = matcher.default_policy().to_string();
        if !policies.contains_key(&default_id) {
            anyhow::bail!(
                "default policy '{}' not found in {}",
                default_id,
                policies_dir.display()
            );
        }

        Ok(PolicyState {
            matcher,
            policies,
            cc: Arc::new(CcLimiter::new()),
        })
    }
}

fn load_and_compile_policies_dir(
    policies_dir: &Path,
) -> anyhow::Result<HashMap<String, Arc<CompiledPolicy>>> {
    let mut map = HashMap::new();

    let rd = std::fs::read_dir(policies_dir)
        .with_context(|| format!("read policies dir failed: {}", policies_dir.display()))?;

    for ent in rd {
        let ent = ent?;
        let path = ent.path();

        if !is_yaml(&path) {
            continue;
        }

        let bytes = std::fs::read(&path)?;
        let p: PolicyFile = serde_yaml::from_slice(&bytes)
            .with_context(|| format!("parse policy failed: {}", path.display()))?;

        let compiled = compile_policy(&p)
            .with_context(|| format!("compile policy failed: {}", path.display()))?;

        map.insert(compiled.id.clone(), compiled);
    }

    Ok(map)
}

fn is_yaml(p: &PathBuf) -> bool {
    matches!(p.extension().and_then(|s| s.to_str()), Some("yaml" | "yml"))
}
