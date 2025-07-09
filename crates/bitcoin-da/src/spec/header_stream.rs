//! A stream of Bitcoin block headers.
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::{FutureExt, Stream};
use pin_project::pin_project;
use sov_rollup_interface::da::DaSpec;
use sov_rollup_interface::services::da::DaService;

use crate::service::BitcoinService;

/// A stream that emits the latest Bitcoin block headers
/// while checking for new headers at a periodic interval.
/// This struct implements the `Stream` trait, which is required
/// for the DaService implementation.
#[pin_project]
pub struct BitcoinHeaderStream {
    #[pin]
    service: Arc<BitcoinService>,
    interval: Duration,
    timer: tokio::time::Interval,
}

impl BitcoinHeaderStream {
    /// Creates a new `BitcoinHeaderStream`.
    pub fn new(service: Arc<BitcoinService>, interval: Duration) -> Self {
        Self {
            service,
            interval,
            timer: tokio::time::interval(interval),
        }
    }
}

impl Stream for BitcoinHeaderStream {
    type Item = Result<
        <<BitcoinService as DaService>::Spec as DaSpec>::BlockHeader,
        <BitcoinService as DaService>::Error,
    >;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        if this.timer.poll_tick(cx).is_ready() {
            let header = futures::ready!(this
                .service
                .get_last_finalized_block_header()
                .boxed()
                .poll_unpin(cx));
            return Poll::Ready(Some(header));
        }
        Poll::Pending
    }
}
