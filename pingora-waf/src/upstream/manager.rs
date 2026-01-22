use arc_swap::ArcSwap;
use std::sync::Arc;

use super::router::UpstreamRouter;

#[derive(Clone)]
pub struct UpstreamManager {
    router: Arc<ArcSwap<UpstreamRouter>>,
}

impl UpstreamManager {
    pub fn new(router: UpstreamRouter) -> Self {
        Self {
            router: Arc::new(ArcSwap::from_pointee(router)),
        }
    }

    pub fn get(&self) -> Arc<UpstreamRouter> {
        self.router.load_full()
    }

    pub fn swap(&self, new_router: UpstreamRouter) {
        self.router.store(Arc::new(new_router));
    }
}
