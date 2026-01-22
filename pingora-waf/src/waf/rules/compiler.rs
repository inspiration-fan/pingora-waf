use anyhow::{Context, Result};
use regex::Regex;
use std::path::Path;

use super::matcher::{AcMatcher, HeaderRegexMatcher};
use super::rule::{Action, Rule, Ruleset};

#[derive(Debug)]
pub struct CompiledRule {
    pub id: String,
    pub action: Action,
    pub methods: Option<Vec<String>>,
    pub path_prefix: Option<Vec<String>>,
    pub uri_ac: Option<AcMatcher>,
    pub body_ac: Option<AcMatcher>,
    pub _header_regex: Vec<HeaderRegexMatcher>,
}

#[derive(Debug)]
pub struct CompiledRuleset {
    pub version: Option<String>,
    pub rules: Vec<CompiledRule>,
}

impl CompiledRuleset {
    pub fn compile(yaml: &str) -> Result<Self> {
        let rs: Ruleset = serde_yaml::from_str(yaml).context("parse rules yaml")?;
        let mut rules = Vec::with_capacity(rs.rules.len());
        for r in rs.rules {
            rules.push(compile_rule(&r)?);
        }
        Ok(Self {
            version: rs.version,
            rules,
        })
    }
}

pub fn compile_from_file(path: &Path) -> Result<CompiledRuleset> {
    let yaml = std::fs::read_to_string(path).with_context(|| format!("read rules file: {}", path.display()))?;
    CompiledRuleset::compile(&yaml)
}

fn compile_rule(r: &Rule) -> Result<CompiledRule> {
    let uri_ac = r.when.uri_ac.as_ref().map(|p| AcMatcher::new(p));
    let body_ac = r.when.body_ac.as_ref().map(|p| AcMatcher::new(p));

    let mut header_regex = Vec::new();
    if let Some(v) = &r.when.header_regex {
        for hr in v {
            let re = Regex::new(&hr.pattern)
                .with_context(|| format!("invalid regex for header {} in rule {}", hr.name, r.id))?;
            header_regex.push(HeaderRegexMatcher {
                _name: hr.name.to_ascii_lowercase(),
                re,
            });
        }
    }

    Ok(CompiledRule {
        id: r.id.clone(),
        action: r.action.clone(),
        methods: r
            .when
            .methods
            .clone()
            .map(|ms| ms.into_iter().map(|m| m.to_ascii_uppercase()).collect()),
        path_prefix: r.when.path_prefix.clone(),
        uri_ac,
        body_ac,
        _header_regex:header_regex,
    })
}
