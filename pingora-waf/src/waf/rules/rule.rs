use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Ruleset {
    pub version: Option<String>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: String,
    pub _description: Option<String>,
    pub when: When,
    pub action: Action,
}

#[derive(Debug, Clone, Deserialize)]
pub struct When {
    pub methods: Option<Vec<String>>,
    pub path_prefix: Option<Vec<String>>,
    pub uri_ac: Option<Vec<String>>,
    pub body_ac: Option<Vec<String>>,
    pub header_regex: Option<Vec<HeaderRegex>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HeaderRegex {
    pub name: String,
    pub pattern: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Block,
    Challenge,
}
