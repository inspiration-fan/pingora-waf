use once_cell::sync::Lazy;
use prometheus::{
    register_histogram_vec, register_int_counter_vec, register_int_gauge_vec,
    HistogramVec, IntCounterVec, IntGaugeVec,
};

pub static REQ_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aegis_http_requests_total",
        "Total HTTP requests seen by Aegis",
        &["host"]
    )
        .expect("register aegis_http_requests_total")
});

pub static INFLIGHT: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!(
        "aegis_http_inflight",
        "In-flight HTTP requests",
        &["host"]
    )
        .expect("register aegis_http_inflight")
});

pub static REQ_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    let buckets = vec![0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0];
    register_histogram_vec!(
        "aegis_http_request_duration_seconds",
        "End-to-end request duration in seconds",
        &["host"],
        buckets
    )
        .expect("register aegis_http_request_duration_seconds")
});

pub static RESP_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aegis_http_responses_total",
        "Total HTTP responses returned by Aegis",
        &["host", "code"]
    )
        .expect("register aegis_http_responses_total")
});

pub static DECISIONS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aegis_decisions_total",
        "Decisions made by protection/waf engine",
        &["source", "kind", "rule_id"]
    )
        .expect("register aegis_decisions_total")
});

pub static CC_HITS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aegis_cc_hits_total",
        "CC limiter hits",
        &["rule_id"]
    )
        .expect("register aegis_cc_hits_total")
});

#[inline]
pub fn on_req_start(host: &str) {
    REQ_TOTAL.with_label_values(&[host]).inc();
    INFLIGHT.with_label_values(&[host]).inc();
}

#[inline]
pub fn on_req_end(host: &str, secs: f64) {
    INFLIGHT.with_label_values(&[host]).dec();
    REQ_DURATION.with_label_values(&[host]).observe(secs);
}

#[inline]
pub fn inc_decision(source: &str, kind: &str, rule_id: &str) {
    DECISIONS_TOTAL
        .with_label_values(&[source, kind, rule_id])
        .inc();
}

#[inline]
pub fn inc_cc_hit(rule_id: &str) {
    CC_HITS_TOTAL.with_label_values(&[rule_id]).inc();
}
