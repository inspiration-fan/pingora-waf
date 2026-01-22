use std::sync::Arc;

use crate::policy::protection::compiled::{compile_rules, CompiledRule};
use crate::policy::types::{PolicyFile, WafConfig};

#[derive(Debug)]
pub struct CompiledPolicy {
    pub version: u32,
    pub id: String,

    pub waf: WafConfig,

    pub precise: Vec<CompiledRule>,
    pub base: Vec<CompiledRule>,
}

pub fn compile_policy(p: &PolicyFile) -> anyhow::Result<Arc<CompiledPolicy>> {
    let precise = compile_rules(&p.protections.precise)?;
    let base = compile_rules(&p.protections.base)?;

    Ok(Arc::new(CompiledPolicy {
        version: p.version,
        id: p.id.clone(),
        waf: p.waf.clone(),
        precise,
        base,
    }))
}
