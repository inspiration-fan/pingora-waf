use prometheus::{Encoder, TextEncoder};

pub fn gather_as_text() -> String {
    let mf = prometheus::gather();
    let encoder = TextEncoder::new();
    let mut buf = Vec::new();
    let _ = encoder.encode(&mf, &mut buf);
    String::from_utf8_lossy(&buf).to_string()
}
