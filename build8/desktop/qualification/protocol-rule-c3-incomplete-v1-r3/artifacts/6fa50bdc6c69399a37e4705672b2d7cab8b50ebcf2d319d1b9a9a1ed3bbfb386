//! One total socket-I/O deadline across fragmented reads and writes.
use std::{
    io::{self, Read, Write},
    net::TcpStream,
    time::{Duration, Instant},
};
pub struct DeadlineIo<'a> {
    stream: &'a mut TcpStream,
    deadline: Instant,
}
impl<'a> DeadlineIo<'a> {
    pub fn new(stream: &'a mut TcpStream, duration: Duration) -> io::Result<Self> {
        if duration.is_zero() || duration > Duration::from_secs(30) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "I/O deadline bound",
            ));
        }
        Ok(Self {
            stream,
            deadline: Instant::now() + duration,
        })
    }
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "total I/O deadline"))
    }
}
impl Read for DeadlineIo<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(out)
    }
}
impl Write for DeadlineIo<'_> {
    fn write(&mut self, raw: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(raw)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.remaining()?;
        self.stream.flush()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::TcpListener, thread};
    #[test]
    fn fragmented_input_cannot_extend_total_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            for _ in 0..8 {
                if s.write_all(&[7]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(30));
            }
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        let mut io = DeadlineIo::new(&mut stream, Duration::from_millis(80)).unwrap();
        let mut raw = [0; 8];
        let started = Instant::now();
        assert!(io.read_exact(&mut raw).is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(stream);
        server.join().unwrap();
    }
    #[test]
    fn ordinary_request_and_response_share_one_bound() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut b = [0; 4];
            s.read_exact(&mut b).unwrap();
            s.write_all(&b).unwrap();
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        let mut io = DeadlineIo::new(&mut stream, Duration::from_secs(1)).unwrap();
        io.write_all(b"test").unwrap();
        let mut b = [0; 4];
        io.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"test");
        server.join().unwrap();
        assert!(DeadlineIo::new(&mut stream, Duration::ZERO).is_err());
    }
}
