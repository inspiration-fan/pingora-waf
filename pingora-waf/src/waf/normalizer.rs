pub struct Normalizer;

impl Normalizer {
    pub fn normalize_path(raw: &str) -> String {
        let mut out = String::with_capacity(raw.len());
        let mut prev_slash = false;
        for ch in raw.chars() {
            if ch == '/' {
                if !prev_slash {
                    out.push(ch);
                }
                prev_slash = true;
            } else {
                prev_slash = false;
                out.push(ch);
            }
        }
        if out.is_empty() {
            "/".to_string()
        } else {
            out
        }
    }
}
