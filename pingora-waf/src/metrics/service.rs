use std::convert::Infallible;

use async_trait::async_trait;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use pingora::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use tokio::net::TcpListener;

#[derive(Clone)]
pub struct MetricsSvc {
    listen: String,
}

impl MetricsSvc {
    pub fn new(listen: impl Into<String>) -> Self {
        Self { listen: listen.into() }
    }
}

#[async_trait]
impl BackgroundService for MetricsSvc {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let listener = match TcpListener::bind(&self.listen).await {
            Ok(l) => {
                tracing::info!("metrics listening on {}", self.listen);
                l
            }
            Err(e) => {
                tracing::error!("metrics bind {} failed: {}", self.listen, e);
                return;
            }
        };

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    tracing::info!("metrics service shutdown");
                    return;
                }
                res = listener.accept() => {
                    let (stream, _peer) = match res {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!("metrics accept error: {}", e);
                            continue;
                        }
                    };

                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let svc = service_fn(handle);

                        // 仅 http1（与你 hyper features 对齐）
                        let builder = hyper::server::conn::http1::Builder::new();

                        if let Err(e) = builder.serve_connection(io, svc).await {
                            tracing::warn!("metrics conn error: {}", e);
                        }
                    });
                }
            }
        }
    }
}

async fn handle(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.uri().path() != "/metrics" {
        return Ok(Response::builder()
            .status(404)
            .header("content-type", "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from_static(b"not found")))
            .unwrap());
    }

    let body = crate::metrics::registry::gather_as_text();

    Ok(Response::builder()
        .status(200)
        .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}
