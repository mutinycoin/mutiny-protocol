//! Process termination is independent of stdin for a service-managed daemon.
#[cfg(unix)]
mod unix {
    use std::sync::atomic::{AtomicBool, Ordering};
    static STOP: AtomicBool = AtomicBool::new(false);
    extern "C" fn terminate(_: libc::c_int) {
        STOP.store(true, Ordering::Release);
    }
    pub struct Shutdown {
        previous: Vec<(libc::c_int, libc::sigaction)>,
    }
    impl Shutdown {
        pub fn install() -> Result<Self, String> {
            STOP.store(false, Ordering::Release);
            let mut guard = Self { previous: vec![] };
            for signal in [libc::SIGTERM, libc::SIGINT] {
                // sigaction is initialized fully; the handler only stores a
                // lock-free atomic flag. All cleanup happens in the main loop.
                let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
                let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
                action.sa_sigaction = terminate as *const () as usize;
                unsafe {
                    libc::sigemptyset(&mut action.sa_mask);
                }
                if unsafe { libc::sigaction(signal, &action, &mut old) } != 0 {
                    return Err(std::io::Error::last_os_error().to_string());
                }
                guard.previous.push((signal, old));
            }
            Ok(guard)
        }
        pub fn requested(&self) -> bool {
            STOP.load(Ordering::Acquire)
        }
    }
    impl Drop for Shutdown {
        fn drop(&mut self) {
            for (signal, action) in &self.previous {
                unsafe {
                    libc::sigaction(*signal, action, std::ptr::null_mut());
                }
            }
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn service_stop_is_signal_driven() {
            let guard = Shutdown::install().unwrap();
            assert!(!guard.requested());
            assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
            assert!(guard.requested());
            drop(guard);
        }
    }
}
#[cfg(unix)]
pub use unix::Shutdown;
#[cfg(not(unix))]
pub struct Shutdown;
#[cfg(not(unix))]
impl Shutdown {
    pub fn install() -> Result<Self, String> {
        Err("Production daemon requires Linux".into())
    }
    pub fn requested(&self) -> bool {
        false
    }
}
