use dashmap::DashMap;
use std::time::{Duration, Instant};

/// CC 限速参数（从 action.cc 编译/组装得到）
#[derive(Debug, Clone, Copy)]
pub struct CcParams {
    pub window_secs: u64,
    pub max_requests: u64,
    pub block_secs: u64,
}

/// 命中（处于封禁或刚刚触发封禁）
#[derive(Debug, Clone)]
pub struct CcHit {
    pub reason: String,
}

/// 单个 key 的状态
#[derive(Debug, Clone)]
struct Entry {
    window_start: Instant,
    count: u64,
    blocked_until: Option<Instant>,
    last_seen: Instant,
}

/// 只做状态机 + 计数
/// key 建议外部带 rule_id：
///   key = format!("rule={rule_id}|{key_body}")
#[derive(Debug)]
pub struct CcLimiter {
    table: DashMap<String, Entry>,
}

impl CcLimiter {
    pub fn new() -> Self {
        Self {
            table: DashMap::new(),
        }
    }

    /// 返回 Some 表示“应当认为触发 CC”（调用方再决定 block/challenge/log）
    pub fn check(&self, rule_id: &str, key_body: &str, p: CcParams) -> Option<CcHit> {
        let now = Instant::now();

        let window = Duration::from_secs(p.window_secs.max(1));
        let block_for = Duration::from_secs(p.block_secs.max(1));
        let max_req = p.max_requests.max(1);

        let k = format!("rule={}|{}", rule_id, key_body);

        // 读出或初始化
        let mut e = self.table.get(&k).map(|v| v.clone()).unwrap_or(Entry {
            window_start: now,
            count: 0,
            blocked_until: None,
            last_seen: now,
        });

        e.last_seen = now;

        // 如果处于封禁期
        if let Some(until) = e.blocked_until {
            if now < until {
                self.table.insert(k, e);
                return Some(CcHit {
                    reason: format!("cc blocked: {}", rule_id),
                });
            } else {
                // 封禁过期，重置窗口
                e.blocked_until = None;
                e.window_start = now;
                e.count = 0;
            }
        }

        // 窗口滚动
        if now.duration_since(e.window_start) >= window {
            e.window_start = now;
            e.count = 0;
        }

        // 计数 + 判断
        e.count += 1;

        if e.count > max_req {
            e.blocked_until = Some(now + block_for);
            self.table.insert(k, e);
            return Some(CcHit {
                reason: format!(
                    "cc exceeded {} req/{}s on {}",
                    max_req, p.window_secs, rule_id
                ),
            });
        }

        self.table.insert(k, e);
        None
    }

    /// 可选：定期清理陈旧 key，避免 table 无限增长
    /// 你可以在后台任务里每隔 N 秒调用一次
    pub fn prune_older_than(&self, older_than: Duration) {
        let now = Instant::now();
        let mut remove_keys = Vec::new();

        for it in self.table.iter() {
            if now.duration_since(it.last_seen) > older_than {
                remove_keys.push(it.key().clone());
            }
        }

        for k in remove_keys {
            self.table.remove(&k);
        }
    }
}
