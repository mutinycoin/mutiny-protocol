//! Counts encrypted transport bytes, not key material; a peer cannot stream without a bound.
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
pub struct BoundedIo<T> {
    inner: T,
    read: usize,
    written: usize,
}
const LIMIT: usize = 65_536;
impl<T> BoundedIo<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            read: 0,
            written: 0,
        }
    }
}
fn exhausted() -> io::Error {
    io::Error::other("NTS transport byte budget exhausted")
}
impl<T: AsyncRead + Unpin> AsyncRead for BoundedIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.read == LIMIT {
            return Poll::Ready(Err(exhausted()));
        }
        let mut bytes = [0u8; 8192];
        let count = out.remaining().min(bytes.len()).min(LIMIT - this.read);
        let mut buf = ReadBuf::new(&mut bytes[..count]);
        match Pin::new(&mut this.inner).poll_read(cx, &mut buf) {
            Poll::Ready(Ok(())) => {
                this.read += buf.filled().len();
                out.put_slice(buf.filled());
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for BoundedIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.written == LIMIT {
            return Poll::Ready(Err(exhausted()));
        }
        let count = bytes.len().min(LIMIT - this.written);
        match Pin::new(&mut this.inner).poll_write(cx, &bytes[..count]) {
            Poll::Ready(Ok(n)) => {
                this.written += n;
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
