use std::sync::Arc;

#[derive(Clone)]
pub struct BlockPage {
    tpl_403: Arc<String>,
}

impl BlockPage {
    pub fn load_from_assets() -> anyhow::Result<Self> {
        // Built-in template. This avoids runtime fs path issues (industrial-grade behavior).
        let tpl_403 = include_str!("../../assets/block/403.html").to_string();
        Ok(Self {
            tpl_403: Arc::new(tpl_403),
        })
    }

    pub fn render_403(&self, status: u16, title: &str, rule_id: &str, reason: &str, request_id: &str) -> String {
        // 极简占位符替换（够用、无依赖）。如果你想更强可换 handlebars/tera。
        let now = chrono::Utc::now().to_rfc3339();
        self.tpl_403
            .replace("{{status}}", &status.to_string())
            .replace("{{title}}", title)
            .replace("{{rule_id}}", &html_escape(rule_id))
            .replace("{{reason}}", &html_escape(reason))
            .replace("{{request_id}}", request_id)
            .replace("{{time}}", &now)
            .replace("{{brand}}", "Aegis")
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
