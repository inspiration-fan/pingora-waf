use serde::Deserialize;

use super::protection::types::ProtectionsSpec;

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyFile {
    pub version: u32,
    pub id: String,

    #[serde(default)]
    pub protections: ProtectionsSpec,

    #[serde(default)]
    pub waf: WafConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct WafConfig {
    pub enabled: bool,
    pub ruleset: Option<String>,
}
