//! Bounded, non-blocking execution of `chronyc` (Order of 4 Oct 2026, decision C3).
//!
//! Every `chronyc` call of a poll is a child process with:
//! * no shell: the program path and each argument are passed as they are (`std::process::Command`
//!   performs no word splitting, globbing or substitution);
//! * an EMPTY inherited environment, stdin closed, stderr discarded, stdout captured;
//! * a hard deadline (`CHRONYC_DEADLINE`): the calling thread only ever polls `try_wait` in short
//!   steps, so it never waits on the child without a bound; past the deadline the child is killed
//!   and reaped;
//! * a bounded stdout (`CHRONYC_MAX_STDOUT`): a reader thread takes at most that many bytes plus
//!   one and then stops reading, so a flooding child is refused and killed, never buffered;
//! * a bounded reap: a killed child is collected within `REAP_GRACE`; one that cannot be (a process
//!   stuck in the kernel) is handed to a detached reaper thread;
//! * bounded threads: the stdout reader thread of every run is counted from its start until it
//!   ends, in the same budget as the uncollected children. A reader can outlive its run when
//!   something else still holds the pipe (a grandchild that inherited stdout: then the run fails
//!   after `REAP_GRACE` and the reader stays blocked until that process exits). While
//!   `MAX_UNREAPED` children and readers together are outstanding no new child is started (the
//!   poll fails closed instead of piling up processes or threads; independent review, MINOR-3).
//!
//! These values are LOCAL IMPLEMENTATION SETTINGS, not protocol or profile parameters (the profile
//! identity does not cover them) and not measured bounds: a spawn that takes more than a few
//! hundred milliseconds already makes the sample unusable, because the measured window `W` is part
//! of the sample uncertainty (`U = ceil(E) + W + 1`, capped by the profile).
use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Hard deadline of one `chronyc` call (local implementation setting).
pub const CHRONYC_DEADLINE: Duration = Duration::from_secs(1);
/// Largest accepted stdout of one `chronyc` call, in bytes (local implementation setting).
pub const CHRONYC_MAX_STDOUT: usize = 64 * 1024;
/// How long a killed child may take to be collected before a detached reaper takes it over.
pub const REAP_GRACE: Duration = Duration::from_millis(500);
/// Outstanding children killed but not yet collected, plus stdout reader threads still running,
/// beyond which no new child is started.
pub const MAX_UNREAPED: usize = 4;
/// Step of the polling waits (the calling thread never blocks longer than this at a time).
const POLL_STEP: Duration = Duration::from_millis(2);

static UNREAPED: AtomicUsize = AtomicUsize::new(0);

/// Why a bounded child run failed. Every case leaves the poll without a reading.
#[derive(Debug, PartialEq, Eq)]
pub enum ExecError {
    /// The program could not be started.
    Spawn(String),
    /// Too many earlier children are still not collected: nothing was started.
    Unreaped,
    /// The child did not finish before the deadline; it was killed. `reaped`: it was collected
    /// within the grace (otherwise a detached reaper collects it).
    Deadline { reaped: bool },
    /// The child wrote more than the stdout bound; it was killed (if it was still running).
    Oversized { reaped: bool },
    /// The child exited unsuccessfully (exit code, if any).
    Failed(Option<i32>),
    /// Pipe or wait failure.
    Io(String),
}
impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecError::Spawn(e) => write!(f, "could not start: {e}"),
            ExecError::Unreaped => write!(f, "earlier calls are still not collected; nothing started"),
            ExecError::Deadline { reaped } => write!(f, "deadline exceeded, killed (reaped: {reaped})"),
            ExecError::Oversized { reaped } => write!(f, "output over the bound, killed (reaped: {reaped})"),
            ExecError::Failed(code) => write!(f, "failed (exit {code:?})"),
            ExecError::Io(e) => write!(f, "{e}"),
        }
    }
}

/// The `chronyc` command line: explicit arguments, no shell, nothing inherited from the node's own
/// process environment, stdin closed, stderr discarded.
pub fn chronyc_command(program: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    command
}

/// Run `command` with a hard `deadline`, keeping at most `max_stdout` bytes of its stdout.
pub fn run_bounded(command: Command, deadline: Duration, max_stdout: usize) -> Result<Vec<u8>, ExecError> {
    run_counted(command, deadline, max_stdout, &UNREAPED)
}

fn run_counted(
    mut command: Command,
    deadline: Duration,
    max_stdout: usize,
    unreaped: &'static AtomicUsize,
) -> Result<Vec<u8>, ExecError> {
    if unreaped.load(Ordering::SeqCst) >= MAX_UNREAPED {
        return Err(ExecError::Unreaped);
    }
    let started = Instant::now();
    command.stdout(Stdio::piped());
    let mut child = command.spawn().map_err(|e| ExecError::Spawn(e.to_string()))?;
    let Some(stdout) = child.stdout.take() else {
        kill_and_reap(child, unreaped);
        return Err(ExecError::Io("no stdout pipe".into()));
    };
    let (tx, rx) = mpsc::channel();
    // The reader is counted until it ends (MINOR-3): a reader blocked by a pipe that a grandchild
    // still holds keeps its place in the budget.
    unreaped.fetch_add(1, Ordering::SeqCst);
    let reader = std::thread::Builder::new()
        .name("chronyc-stdout".into())
        .spawn(move || {
            // At most max + 1 bytes, then the pipe is dropped: an oversized output is recognised
            // and a flooding child is blocked or broken, never buffered without a bound.
            let mut buf = Vec::new();
            let read = stdout
                .take(max_stdout as u64 + 1)
                .read_to_end(&mut buf)
                .map(|_| buf)
                .map_err(|e| e.to_string());
            let _ = tx.send(read);
            unreaped.fetch_sub(1, Ordering::SeqCst);
        });
    if let Err(e) = reader {
        unreaped.fetch_sub(1, Ordering::SeqCst);
        kill_and_reap(child, unreaped);
        return Err(ExecError::Io(e.to_string()));
    }
    let mut output: Option<Result<Vec<u8>, String>> = None;
    let status = loop {
        if output.is_none() {
            output = rx.try_recv().ok();
        }
        if let Some(Ok(buf)) = &output
            && buf.len() > max_stdout
        {
            let reaped = kill_and_reap(child, unreaped);
            return Err(ExecError::Oversized { reaped });
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(e) => {
                kill_and_reap(child, unreaped);
                return Err(ExecError::Io(e.to_string()));
            }
        }
        if started.elapsed() >= deadline {
            let reaped = kill_and_reap(child, unreaped);
            return Err(ExecError::Deadline { reaped });
        }
        std::thread::sleep(POLL_STEP);
    };
    // The child is gone; its stdout reaches end of file at once unless something else still holds
    // the pipe: bounded by the grace either way.
    let output = match output {
        Some(read) => read,
        None => rx
            .recv_timeout(REAP_GRACE)
            .map_err(|_| ExecError::Io("stdout still open after the child exited".into()))?,
    };
    let buf = output.map_err(ExecError::Io)?;
    if buf.len() > max_stdout {
        return Err(ExecError::Oversized { reaped: true });
    }
    if !status.success() {
        return Err(ExecError::Failed(status.code()));
    }
    Ok(buf)
}

/// Kill the child and collect it within `REAP_GRACE`; otherwise hand it to a detached reaper
/// (counted in `unreaped` until it is collected). Returns whether it was collected here.
fn kill_and_reap(mut child: Child, unreaped: &'static AtomicUsize) -> bool {
    let _ = child.kill();
    let since = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if since.elapsed() < REAP_GRACE => std::thread::sleep(POLL_STEP),
            _ => break,
        }
    }
    unreaped.fetch_add(1, Ordering::SeqCst);
    let spawned = std::thread::Builder::new()
        .name("chronyc-reaper".into())
        .spawn(move || {
            let _ = child.wait();
            unreaped.fetch_sub(1, Ordering::SeqCst);
        });
    // Without a reaper thread the count stays raised: no further child is started.
    let _ = spawned;
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The marker that turns a run of this test binary into a CHILD with a role (an argument, since
    /// the child's environment is empty). In an ordinary test run the role test returns at once.
    const MARKER: &str = "BUILD8-EXEC-CHILD=";

    #[test]
    fn exec_child_role() {
        // The CHILD side of the tests below: this test binary, started with the marker.
        let Some(role) = std::env::args().find_map(|a| a.strip_prefix(MARKER).map(str::to_string)) else {
            return; // an ordinary run: nothing to do
        };
        use std::io::Write;
        let mut out = std::io::stdout();
        match role.as_str() {
            "ok" => {
                writeln!(out, "BUILD8-EXEC-OUT=162.159.200.1,NTS").unwrap();
            }
            "env" => {
                writeln!(out, "BUILD8-EXEC-ENV-COUNT={}", std::env::vars_os().count()).unwrap();
            }
            "args" => {
                for a in std::env::args().skip_while(|a| !a.starts_with(MARKER)).skip(1) {
                    writeln!(out, "BUILD8-EXEC-ARG={a}").unwrap();
                }
            }
            "sleep" => std::thread::sleep(Duration::from_secs(60)),
            "hold" => std::thread::sleep(Duration::from_secs(10)),
            "grandchild" => {
                // Start a grandchild that INHERITS this child's stdout (the parent's pipe) and
                // keeps it open for 10 s, then exit at once.
                let marker = format!("{MARKER}hold");
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", &test_name(), "--nocapture", "--test-threads=1", &marker])
                    .stdin(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
            }
            "flood" => loop {
                if out.write_all(&[b'x'; 65_536]).is_err() {
                    std::process::exit(0);
                }
            },
            "fail" => std::process::exit(3),
            other => panic!("unknown role {other}"),
        }
        out.flush().unwrap();
    }
    /// The libtest name of `exec_child_role`.
    fn test_name() -> String {
        format!(
            "{}::exec_child_role",
            module_path!().split_once("::").map_or(module_path!(), |(_, rest)| rest)
        )
    }
    /// A command that runs this test binary as a child with `role` (no shell, as in production).
    fn child(role: &str, extra: &[&str]) -> Command {
        let name = test_name();
        let marker = format!("{MARKER}{role}");
        let mut args = vec!["--exact", name.as_str(), "--nocapture", "--test-threads=1", marker.as_str()];
        args.extend_from_slice(extra);
        chronyc_command(&std::env::current_exe().unwrap(), &args)
    }
    /// The values the child printed after `key` (libtest may print its own text before them on the
    /// same line).
    fn lines(out: &[u8], key: &str) -> Vec<String> {
        String::from_utf8_lossy(out)
            .lines()
            .filter_map(|l| l.split_once(key).map(|(_, value)| value.to_string()))
            .collect()
    }
    /// Generous: a test binary starts slowly on a loaded host. The deadline tests use short ones.
    const SLOW: Duration = Duration::from_secs(60);

    #[test]
    fn c3_a_normal_child_is_read_completely() {
        let out = run_bounded(child("ok", &[]), SLOW, CHRONYC_MAX_STDOUT).unwrap();
        assert_eq!(lines(&out, "BUILD8-EXEC-OUT="), ["162.159.200.1,NTS"]);
    }

    #[test]
    fn c3_the_child_gets_an_empty_environment_and_its_arguments_without_a_shell() {
        let out = run_bounded(child("env", &[]), SLOW, CHRONYC_MAX_STDOUT).unwrap();
        assert_eq!(lines(&out, "BUILD8-EXEC-ENV-COUNT="), ["0"], "nothing inherited");
        // Shell syntax arrives as literal arguments: there is no shell to interpret it.
        let tricky = ["; echo injected", "$(id)", "a b", "`x`", "|", "*"];
        let out = run_bounded(child("args", &tricky), SLOW, CHRONYC_MAX_STDOUT).unwrap();
        assert_eq!(lines(&out, "BUILD8-EXEC-ARG="), tricky);
    }

    #[test]
    fn c3_a_child_that_outlives_the_deadline_is_killed_and_reaped_within_a_bound() {
        let started = Instant::now();
        let r = run_bounded(child("sleep", &[]), Duration::from_millis(1_500), CHRONYC_MAX_STDOUT);
        let took = started.elapsed();
        assert_eq!(r, Err(ExecError::Deadline { reaped: true }));
        // Deadline plus the reap grace plus scheduling slack: never the child's 60 s.
        assert!(took < Duration::from_millis(1_500) + REAP_GRACE + Duration::from_secs(5), "{took:?}");
    }

    #[test]
    fn c3_stdout_beyond_the_bound_is_refused_and_the_child_killed() {
        let started = Instant::now();
        let r = run_bounded(child("flood", &[]), SLOW, 4_096);
        assert!(matches!(r, Err(ExecError::Oversized { .. })), "{r:?}");
        assert!(started.elapsed() < Duration::from_secs(30), "{:?}", started.elapsed());
    }

    #[test]
    fn c3_a_grandchild_holding_stdout_keeps_its_reader_counted_and_bounds_the_threads() {
        // Independent review, MINOR-3: a grandchild that inherited stdout keeps the pipe open after
        // the child exited, so the reader thread cannot finish. The run fails after the grace, the
        // blocked reader stays counted, and once MAX_UNREAPED readers are outstanding nothing new
        // is started. When the grandchildren exit the readers end and the budget is free again.
        // (A private counter, so the other tests are unaffected.)
        static READERS: AtomicUsize = AtomicUsize::new(0);
        for i in 0..MAX_UNREAPED {
            let r = run_counted(child("grandchild", &[]), SLOW, CHRONYC_MAX_STDOUT, &READERS);
            assert_eq!(r, Err(ExecError::Io("stdout still open after the child exited".into())), "run {i}");
            assert_eq!(READERS.load(Ordering::SeqCst), i + 1, "the blocked reader stays counted");
        }
        let started = Instant::now();
        assert_eq!(
            run_counted(child("ok", &[]), SLOW, CHRONYC_MAX_STDOUT, &READERS),
            Err(ExecError::Unreaped)
        );
        assert!(started.elapsed() < Duration::from_secs(1), "nothing was started or waited for");
        let since = Instant::now();
        while READERS.load(Ordering::SeqCst) > 0 {
            assert!(since.elapsed() < Duration::from_secs(60), "readers never ended");
            std::thread::sleep(Duration::from_millis(50));
        }
        let out = run_counted(child("ok", &[]), SLOW, CHRONYC_MAX_STDOUT, &READERS).unwrap();
        assert_eq!(lines(&out, "BUILD8-EXEC-OUT="), ["162.159.200.1,NTS"]);
    }

    #[test]
    fn c3_failures_are_reported_and_spawning_stops_while_children_are_unreaped() {
        assert_eq!(run_bounded(child("fail", &[]), SLOW, CHRONYC_MAX_STDOUT), Err(ExecError::Failed(Some(3))));
        let missing = std::env::temp_dir().join("build8-no-such-chronyc-binary");
        assert!(matches!(
            run_bounded(chronyc_command(&missing, &["tracking"]), SLOW, CHRONYC_MAX_STDOUT),
            Err(ExecError::Spawn(_))
        ));
        // With MAX_UNREAPED children outstanding nothing is started (a private counter, so the
        // other tests are unaffected).
        static FULL: AtomicUsize = AtomicUsize::new(MAX_UNREAPED);
        let started = Instant::now();
        assert_eq!(
            run_counted(child("sleep", &[]), SLOW, CHRONYC_MAX_STDOUT, &FULL),
            Err(ExecError::Unreaped)
        );
        assert!(started.elapsed() < Duration::from_secs(1), "nothing was started or waited for");
    }
}
