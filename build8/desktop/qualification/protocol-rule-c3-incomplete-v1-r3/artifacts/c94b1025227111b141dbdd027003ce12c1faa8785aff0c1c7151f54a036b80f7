//! Cancellable owned Linux pipe reads for the host-local TPM channel.
//! The outer request has its own deadline; cancellation bounds reader shutdown
//! even when another process retains a copy of the pipe's write descriptor.
use std::{
    io::{self, Read},
    os::fd::AsRawFd,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
pub(super) struct CancellableReader<R> {
    input: R,
    cancelled: Arc<AtomicBool>,
}
impl<R: Read + AsRawFd> CancellableReader<R> {
    pub(super) fn new(input: R, cancelled: Arc<AtomicBool>) -> io::Result<Self> {
        let fd = input.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { input, cancelled })
    }
}
impl<R: Read + AsRawFd> Read for CancellableReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.cancelled.load(Ordering::Acquire) {
                // Interrupted would be retried by BufRead::read_until.
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "TPM reader cancelled",
                ));
            }
            let mut fd = libc::pollfd {
                fd: self.input.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut fd, 1, 100) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if ready == 0 {
                continue;
            }
            if fd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "TPM reader pipe failure",
                ));
            }
            // HUP can accompany final buffered bytes. A nonblocking read drains
            // them and then returns EOF; no descriptor can trap this thread.
            match self.input.read(out) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                result => return result,
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Write},
        os::unix::net::UnixStream,
        thread,
        time::{Duration, Instant},
    };
    #[test]
    fn retained_writer_cannot_trap_cancelled_reader() {
        for partial in [false, true] {
            let (read, mut write) = UnixStream::pair().unwrap();
            let cancel = Arc::new(AtomicBool::new(false));
            let reader = CancellableReader::new(read, cancel.clone()).unwrap();
            if partial {
                write.write_all(b"{\"unfinished\":").unwrap();
            }
            let worker = thread::spawn(move || {
                let mut line = Vec::new();
                BufReader::new(reader).read_until(b'\n', &mut line)
            });
            thread::sleep(Duration::from_millis(20));
            let started = Instant::now();
            cancel.store(true, Ordering::Release);
            assert_eq!(
                worker.join().unwrap().unwrap_err().kind(),
                io::ErrorKind::ConnectionAborted
            );
            assert!(started.elapsed() < Duration::from_secs(2));
            drop(write); // It remained open throughout cancellation and join.
        }
    }
    #[test]
    fn final_buffered_bytes_and_eof_are_preserved() {
        let (read, mut write) = UnixStream::pair().unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut reader = CancellableReader::new(read, cancel).unwrap();
        write.write_all(b"public reply\n").unwrap();
        drop(write);
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"public reply\n");
    }
}
