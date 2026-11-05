//! Bounded local console input. No file/stdin fallback or password output.
use std::io::{self, Write};
use zeroize::{Zeroize, Zeroizing};
const MAX_BYTES: usize = 4096;
const MAX_EVENTS: usize = 16384;
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "Invalid or excessive private input",
    )
}
struct Buffer {
    bytes: Zeroizing<[u8; MAX_BYTES]>,
    len: usize,
}
impl Buffer {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new([0; MAX_BYTES]),
            len: 0,
        }
    }
    fn pop(&mut self) {
        if self.len == 0 {
            return;
        }
        let end = self.len;
        self.len -= 1;
        while self.len > 0 && self.bytes[self.len] & 0xc0 == 0x80 {
            self.len -= 1;
        }
        self.bytes[self.len..end].zeroize();
    }
    fn push(&mut self, c: char) -> io::Result<()> {
        let n = c.len_utf8();
        if self.len + n > MAX_BYTES {
            return Err(invalid());
        }
        c.encode_utf8(&mut self.bytes[self.len..self.len + n]);
        self.len += n;
        Ok(())
    }
    fn finish(&self) -> io::Result<Zeroizing<String>> {
        Ok(Zeroizing::new(
            std::str::from_utf8(&self.bytes[..self.len])
                .map_err(|_| invalid())?
                .to_owned(),
        ))
    }
}
fn collect(mut next: impl FnMut() -> io::Result<char>) -> io::Result<Zeroizing<String>> {
    let mut b = Buffer::new();
    for _ in 0..MAX_EVENTS {
        let mut c = next()?;
        match c {
            '\r' | '\n' => {
                c.zeroize();
                return b.finish();
            }
            '\x08' | '\x7f' => b.pop(),
            '\x15' => {
                b.bytes.zeroize();
                b.len = 0;
            }
            '\x17' => {
                while b.len > 0 && b.bytes[b.len - 1] == b' ' {
                    b.pop();
                }
                while b.len > 0 && b.bytes[b.len - 1] != b' ' {
                    b.pop();
                }
            }
            c if c.is_control() => return Err(invalid()),
            _ => {
                let result = b.push(c);
                c.zeroize();
                result?;
                continue;
            }
        }
        c.zeroize();
    }
    Err(invalid())
}
pub fn prompt(message: &str) -> Result<Zeroizing<String>, &'static str> {
    let mut console = platform::Console::open().map_err(|_| "Private console unavailable")?;
    console
        .prompt(message)
        .map_err(|_| "Private console prompt failed")?;
    let result = collect(|| console.next());
    console
        .restore()
        .map_err(|_| "Private console restoration failed")?;
    result.map_err(|_| "Password input cancelled, incomplete or exceeds bound")
}
#[cfg(windows)]
mod platform {
    use super::*;
    use std::{
        fs::{File, OpenOptions},
        os::windows::io::AsRawHandle,
    };
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
        ENABLE_VIRTUAL_TERMINAL_INPUT, FlushConsoleInputBuffer, GetConsoleMode, ReadConsoleW,
        SetConsoleMode,
    };
    pub struct Console {
        input: File,
        output: File,
        mode: u32,
        changed: bool,
    }
    impl Console {
        pub fn open() -> io::Result<Self> {
            let input = OpenOptions::new().read(true).write(true).open("CONIN$")?;
            let output = OpenOptions::new().write(true).open("CONOUT$")?;
            let mut mode = 0;
            if unsafe { GetConsoleMode(input.as_raw_handle(), &mut mode) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut out = Self {
                input,
                output,
                mode,
                changed: false,
            };
            let hidden = mode
                & !(ENABLE_ECHO_INPUT
                    | ENABLE_LINE_INPUT
                    | ENABLE_PROCESSED_INPUT
                    | ENABLE_VIRTUAL_TERMINAL_INPUT);
            if unsafe { SetConsoleMode(out.input.as_raw_handle(), hidden) } == 0 {
                return Err(io::Error::last_os_error());
            }
            out.changed = true;
            if unsafe { FlushConsoleInputBuffer(out.input.as_raw_handle()) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(out)
        }
        pub fn prompt(&mut self, s: &str) -> io::Result<()> {
            self.output.write_all(s.as_bytes())?;
            self.output.flush()
        }
        fn unit(&mut self) -> io::Result<u16> {
            let mut unit = Zeroizing::new([0u16; 1]);
            let mut count = 0;
            if unsafe {
                ReadConsoleW(
                    self.input.as_raw_handle(),
                    unit.as_mut_ptr().cast(),
                    1,
                    &mut count,
                    std::ptr::null(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            if count != 1 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            Ok(unit[0])
        }
        pub fn next(&mut self) -> io::Result<char> {
            let mut units = Zeroizing::new([0u16; 2]);
            units[0] = self.unit()?;
            if (0xd800..=0xdbff).contains(&units[0]) {
                units[1] = self.unit()?;
                char::decode_utf16(*units)
                    .next()
                    .and_then(Result::ok)
                    .ok_or_else(invalid)
            } else {
                char::from_u32(units[0] as u32).ok_or_else(invalid)
            }
        }
        pub fn restore(&mut self) -> io::Result<()> {
            if self.changed {
                let flushed = unsafe { FlushConsoleInputBuffer(self.input.as_raw_handle()) } != 0;
                let restored =
                    unsafe { SetConsoleMode(self.input.as_raw_handle(), self.mode) } != 0;
                if restored {
                    self.changed = false;
                }
                if !flushed || !restored {
                    return Err(io::Error::last_os_error());
                }
                self.output.write_all(b"\r\n")?;
                self.output.flush()?;
            }
            Ok(())
        }
    }
    impl Drop for Console {
        fn drop(&mut self) {
            let _ = self.restore();
        }
    }
}
#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::{
        fs::{File, OpenOptions},
        io::Read,
        os::fd::AsRawFd,
    };
    pub struct Console {
        tty: File,
        mode: libc::termios,
        changed: bool,
    }
    impl Console {
        pub fn open() -> io::Result<Self> {
            let tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
            let mut mode: libc::termios = unsafe { std::mem::zeroed() };
            if unsafe { libc::isatty(tty.as_raw_fd()) } != 1
                || unsafe { libc::tcgetattr(tty.as_raw_fd(), &mut mode) } != 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut hidden = mode;
            hidden.c_lflag &=
                !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN);
            hidden.c_iflag &= !(libc::ISTRIP
                | libc::INLCR
                | libc::IGNCR
                | libc::ICRNL
                | libc::IXON
                | libc::IXOFF);
            hidden.c_cc[libc::VMIN] = 1;
            hidden.c_cc[libc::VTIME] = 0;
            if unsafe { libc::tcsetattr(tty.as_raw_fd(), libc::TCSAFLUSH, &hidden) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                tty,
                mode,
                changed: true,
            })
        }
        pub fn prompt(&mut self, s: &str) -> io::Result<()> {
            self.tty.write_all(s.as_bytes())?;
            self.tty.flush()
        }
        pub fn next(&mut self) -> io::Result<char> {
            let mut bytes = Zeroizing::new([0u8; 4]);
            self.tty.read_exact(&mut bytes[..1])?;
            let n = match bytes[0] {
                0..=0x7f => 1,
                0xc2..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf4 => 4,
                _ => return Err(invalid()),
            };
            self.tty.read_exact(&mut bytes[1..n])?;
            std::str::from_utf8(&bytes[..n])
                .ok()
                .and_then(|s| s.chars().next())
                .ok_or_else(invalid)
        }
        pub fn restore(&mut self) -> io::Result<()> {
            if self.changed {
                if unsafe { libc::tcsetattr(self.tty.as_raw_fd(), libc::TCSAFLUSH, &self.mode) }
                    != 0
                {
                    return Err(io::Error::last_os_error());
                }
                self.changed = false;
                self.tty.write_all(b"\n")?;
                self.tty.flush()?;
            }
            Ok(())
        }
    }
    impl Drop for Console {
        fn drop(&mut self) {
            let _ = self.restore();
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn read(s: &str) -> io::Result<Zeroizing<String>> {
        let mut chars = s.chars();
        collect(|| {
            chars
                .next()
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        })
    }
    #[test]
    fn bounded_unicode_input_and_edits_wipe_removed_bytes() {
        assert_eq!(&*read("PUBLIC\n").unwrap(), "PUBLIC");
        assert_eq!(&*read("a\u{1f980}\u{e9}\x08\x7fb\r").unwrap(), "ab");
        assert_eq!(&*read("PUBLIC OLD\x17NEW\n").unwrap(), "PUBLIC NEW");
        assert_eq!(&*read("PUBLIC\x15NEW\n").unwrap(), "NEW");
        assert_eq!(
            read(&format!("{}\n", "x".repeat(MAX_BYTES))).unwrap().len(),
            MAX_BYTES
        );
        assert!(read(&format!("{}\n", "x".repeat(MAX_BYTES + 1))).is_err());
        assert!(read(&format!("{}\u{e9}\n", "x".repeat(MAX_BYTES - 1))).is_err());
        let mut b = Buffer::new();
        b.push('a').unwrap();
        b.push('\u{1f980}').unwrap();
        b.pop();
        assert_eq!(b.len, 1);
        assert!(b.bytes[1..].iter().all(|x| *x == 0));
    }
    #[test]
    fn incomplete_cancelled_control_and_unbounded_editing_fail_closed() {
        for s in [
            "PUBLIC",
            "PUBLIC\x03",
            "PUBLIC\x04",
            "PUBLIC\x1b",
            "PUBLIC\t",
        ] {
            assert!(read(s).is_err());
        }
        let mut calls = 0;
        assert!(
            collect(|| {
                calls += 1;
                Ok('\x08')
            })
            .is_err()
        );
        assert_eq!(calls, MAX_EVENTS);
        assert!(collect(|| Err(io::Error::from(io::ErrorKind::Other))).is_err());
    }
}

#[cfg(all(test, windows))]
#[test]
fn isolated_windows_console_child() {
    if std::env::var("BUILD8_PUBLIC_CONSOLE_TEST").as_deref() != Ok("ISOLATED_HIDDEN_CONSOLE") {
        return;
    }
    use std::{fs::OpenOptions, os::windows::io::AsRawHandle};
    use windows_sys::Win32::System::Console::*;
    let input = OpenOptions::new()
        .read(true)
        .write(true)
        .open("CONIN$")
        .unwrap();
    let handle = input.as_raw_handle();
    let mut original = 0;
    assert_ne!(unsafe { GetConsoleMode(handle, &mut original) }, 0);
    let cases = [
        (
            "PUBLIC\u{1f980}\u{e9}\x08\rTRAIL".to_string(),
            Some("PUBLIC\u{1f980}"),
        ),
        ("PUBLIC\x03TRAIL".into(), None),
        (format!("{}\rTRAIL", "x".repeat(MAX_BYTES + 1)), None),
    ];
    for (text, expected) in cases {
        let mut console = platform::Console::open().unwrap();
        let mut current = 0;
        assert_ne!(unsafe { GetConsoleMode(handle, &mut current) }, 0);
        assert_eq!(
            current & (ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT),
            0
        );
        let events: Vec<_> = text
            .encode_utf16()
            .map(|u| INPUT_RECORD {
                EventType: KEY_EVENT as u16,
                Event: INPUT_RECORD_0 {
                    KeyEvent: KEY_EVENT_RECORD {
                        bKeyDown: 1,
                        wRepeatCount: 1,
                        wVirtualKeyCode: if u == 13 { 13 } else { 0 },
                        wVirtualScanCode: 0,
                        uChar: KEY_EVENT_RECORD_0 { UnicodeChar: u },
                        dwControlKeyState: 0,
                    },
                },
            })
            .collect();
        let mut count = 0;
        assert_ne!(
            unsafe { WriteConsoleInputW(handle, events.as_ptr(), events.len() as u32, &mut count) },
            0
        );
        assert_eq!(count as usize, events.len());
        let result = collect(|| console.next());
        match expected {
            Some(s) => assert_eq!(&*result.unwrap(), s),
            None => assert!(result.is_err()),
        };
        console.restore().unwrap();
        assert_ne!(unsafe { GetConsoleMode(handle, &mut current) }, 0);
        assert_eq!(current, original);
        assert_ne!(
            unsafe { GetNumberOfConsoleInputEvents(handle, &mut count) },
            0
        );
        assert_eq!(count, 0);
    }
    println!(
        "SYNTHETIC_WINDOWS_CONSOLE_PASS cases=3 hidden_input=true restored=true pending_input_flushed=true production=false"
    );
}
