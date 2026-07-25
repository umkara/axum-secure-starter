//! Connection-level admission control.
//!
//! The middleware stack bounds *requests*, which is a different thing from
//! bounding *connections*. A slowloris client opens sockets and dribbles header
//! bytes: no request ever reaches the router, so the concurrency limit and the
//! request timeout never see it, while the file descriptors accumulate. This
//! acceptor caps how many connections may exist at once and closes anything
//! beyond that immediately, before a byte is read.
//!
//! Rejecting rather than queueing is deliberate. Making excess connections wait
//! would keep exactly the sockets we are trying to shed, and turn descriptor
//! exhaustion into unbounded task growth instead.

use std::{
    future::{Ready, ready},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use axum_server::accept::Accept;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{OwnedSemaphorePermit, Semaphore},
};

/// Admits at most `limit` concurrent connections.
#[derive(Clone, Debug)]
pub struct ConnectionLimitAcceptor {
    permits: Arc<Semaphore>,
}

impl ConnectionLimitAcceptor {
    pub fn new(limit: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(limit)),
        }
    }

    /// Slots still available. Useful for a metric or a readiness signal.
    pub fn available(&self) -> usize {
        self.permits.available_permits()
    }
}

impl<I, S> Accept<I, S> for ConnectionLimitAcceptor {
    type Stream = GuardedStream<I>;
    type Service = S;
    type Future = Ready<io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        match Arc::clone(&self.permits).try_acquire_owned() {
            Ok(permit) => ready(Ok((
                GuardedStream {
                    inner: stream,
                    _permit: permit,
                },
                service,
            ))),
            Err(_) => {
                tracing::debug!("connection refused: the connection limit is saturated");
                ready(Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "connection limit reached",
                )))
            }
        }
    }
}

/// A stream that holds its slot until the connection is dropped.
pub struct GuardedStream<I> {
    inner: I,
    _permit: OwnedSemaphorePermit,
}

impl<I: AsyncRead + Unpin> AsyncRead for GuardedStream<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for GuardedStream<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}
