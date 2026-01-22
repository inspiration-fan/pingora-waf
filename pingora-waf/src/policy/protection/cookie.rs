pub fn get_cookie_value<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    let mut s = cookie_header;

    loop {
        s = s.trim_start_matches(|c: char| c == ' ' || c == ';');
        if s.is_empty() {
            return None;
        }

        let end = s.find(';').unwrap_or(s.len());
        let pair = &s[..end];
        s = if end < s.len() { &s[end + 1..] } else { "" };

        let Some(eq) = pair.find('=') else { continue; };
        let k = pair[..eq].trim();
        if !k.eq_ignore_ascii_case(name) {
            continue;
        }
        return Some(pair[eq + 1..].trim());
    }
}
