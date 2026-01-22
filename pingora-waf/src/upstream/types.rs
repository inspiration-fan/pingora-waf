use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfigFile {
    pub version: u32,

    pub resolver: ResolverConfig,

    pub cname_routing: CnameRouting,

    pub tenants: HashMap<String, TenantUpstreams>,
    pub default: TenantUpstreams,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum ResolverConfig {
    /// 本地测试：直接用映射表模拟 CNAME
    Static { host_to_cname: HashMap<String, String> },

    /// 线上：真实 DNS 查询
    Dns {
        timeout_ms: Option<u64>,
        cache_ttl_secs: Option<u64>,
        cname_chain_limit: Option<usize>,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct CnameRouting {
    pub tenant_from_cname_regex: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TenantUpstreams {
    pub upstreams: Vec<String>,
}
