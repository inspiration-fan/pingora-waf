use std::time::Instant;

#[derive(Debug)]
pub struct TokenBucket {
    cap: u64,
    tokens: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(cap: u64, refill_per_sec: f64) -> Self {
        Self {
            cap,
            tokens: cap as f64,
            refill_per_sec,
            last: Instant::now(),
        }
    }

    pub fn allow(&mut self, cost: u64) -> bool {
        self.refill();
        if self.tokens >= cost as f64 {
            self.tokens -= cost as f64;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let dt = now.duration_since(self.last);
        self.last = now;
        let add = dt.as_secs_f64() * self.refill_per_sec;
        self.tokens = (self.tokens + add).min(self.cap as f64);
    }
}
