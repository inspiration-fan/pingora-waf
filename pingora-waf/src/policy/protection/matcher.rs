use crate::waf::context::WafContext;

use super::compiled::CompiledMatchExpr;

pub trait HeaderView {
    fn get(&self, name: &str) -> Option<&str>;
}

pub fn eval(m: &CompiledMatchExpr, wctx: &WafContext, headers: &dyn HeaderView) -> bool {
    match m {
        CompiledMatchExpr::Any => true,

        CompiledMatchExpr::PathPrefix(p) => wctx.path.starts_with(p),

        CompiledMatchExpr::MethodIn(ms) => ms.iter().any(|m| m.eq_ignore_ascii_case(&wctx.method)),

        CompiledMatchExpr::HostIn(hs) => {
            let Some(h) = wctx.host.as_deref() else { return false; };
            hs.iter().any(|x| x.eq_ignore_ascii_case(h))
        }

        CompiledMatchExpr::HeaderExists(name) => headers.get(name).is_some(),

        CompiledMatchExpr::HeaderEquals { name, value } => headers.get(name).is_some_and(|v| v == value),

        CompiledMatchExpr::HeaderRegex { name, re } => headers.get(name).is_some_and(|v| re.is_match(v)),

        CompiledMatchExpr::And(xs) => xs.iter().all(|x| eval(x, wctx, headers)),
        CompiledMatchExpr::Or(xs) => xs.iter().any(|x| eval(x, wctx, headers)),
        CompiledMatchExpr::Not(x) => !eval(x, wctx, headers),
    }
}
