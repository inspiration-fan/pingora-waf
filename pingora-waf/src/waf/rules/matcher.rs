use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use regex::Regex;

#[derive(Debug)]
pub struct AcMatcher {
    ac: AhoCorasick,
    max_pat_len: usize,
}

impl AcMatcher {
    pub fn new(patterns: &[String]) -> Self {
        let max_pat_len = patterns.iter().map(|s| s.len()).max().unwrap_or(0);
        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(patterns)
            .expect("build aho-corasick");
        Self { ac, max_pat_len }
    }

    #[inline]
    pub fn is_match(&self, hay: &[u8]) -> bool {
        self.ac.is_match(hay)
    }

    #[inline]
    pub fn max_pat_len(&self) -> usize {
        self.max_pat_len
    }
}

#[derive(Debug)]
pub struct HeaderRegexMatcher {
    pub _name: String,
    pub re: Regex,
}
