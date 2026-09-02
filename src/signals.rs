//! Signal helpers: mapping validated signal names to libc numbers and
//! delivering signals to the game server child process.

use std::io;

/// A signal that may be used as the graceful stop action.
///
/// `KILL` and `STOP` are deliberately not representable here: they cannot be
/// caught by the target process, so they do not belong in the graceful slot.
/// Escalation to `SIGKILL` goes through [`tokio::process::Child::start_kill`]
/// instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GracefulSignal {
    /// `SIGTERM`, the default.
    Term,
    /// `SIGINT`.
    Int,
    /// `SIGHUP`.
    Hup,
    /// `SIGQUIT`.
    Quit,
}

impl GracefulSignal {
    /// Parse a signal name, case-insensitively, with an optional `SIG` prefix,
    /// and validate it against the graceful whitelist.
    ///
    /// # Errors
    /// Returns a descriptive error for `KILL`/`STOP` (which cannot be caught)
    /// and for any name outside `TERM`, `INT`, `HUP`, `QUIT`.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let upper = raw.to_ascii_uppercase();
        let name = upper.strip_prefix("SIG").unwrap_or(upper.as_str());
        match name {
            "TERM" => Ok(Self::Term),
            "INT" => Ok(Self::Int),
            "HUP" => Ok(Self::Hup),
            "QUIT" => Ok(Self::Quit),
            "KILL" | "STOP" => Err(format!(
                "stop signal {raw:?} cannot be caught and does not belong in the \
                 graceful stop slot; allowed signals: TERM, INT, HUP, QUIT"
            )),
            _ => Err(format!(
                "unknown stop signal {raw:?}; allowed signals: TERM, INT, HUP, QUIT"
            )),
        }
    }

    /// The libc signal number for this signal.
    #[must_use]
    pub const fn libc_number(self) -> i32 {
        match self {
            Self::Term => libc::SIGTERM,
            Self::Int => libc::SIGINT,
            Self::Hup => libc::SIGHUP,
            Self::Quit => libc::SIGQUIT,
        }
    }
}

/// Send a signal to a child process.
///
/// # Errors
/// Returns the OS error if the signal could not be delivered, for example
/// because the process already exited.
#[expect(
    unsafe_code,
    reason = "libc::kill is an unsafe FFI call; the pid always comes from \
              Child::id() of a process this program spawned itself, so no \
              arbitrary process is targeted"
)]
pub fn send(pid: i32, signal: GracefulSignal) -> io::Result<()> {
    // SAFETY: `kill` only delivers a signal to the process with the given pid,
    // which is always our own spawned child. It touches no memory.
    let rc = unsafe { libc::kill(pid, signal.libc_number()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::GracefulSignal;

    #[test]
    fn parses_names_with_and_without_prefix() {
        let cases = [
            ("TERM", GracefulSignal::Term),
            ("term", GracefulSignal::Term),
            ("SIGTERM", GracefulSignal::Term),
            ("SigTerm", GracefulSignal::Term),
            ("INT", GracefulSignal::Int),
            ("sigint", GracefulSignal::Int),
            ("HUP", GracefulSignal::Hup),
            ("sighup", GracefulSignal::Hup),
            ("QUIT", GracefulSignal::Quit),
            ("SIGQUIT", GracefulSignal::Quit),
        ];
        for (name, expected) in cases {
            assert_eq!(
                GracefulSignal::parse(name),
                Ok(expected),
                "parsing signal name {name:?}"
            );
        }
    }

    #[test]
    fn rejects_uncatchable_signals() {
        for name in ["KILL", "kill", "SIGKILL", "STOP", "stop", "SIGSTOP"] {
            let err = GracefulSignal::parse(name)
                .err()
                .unwrap_or_else(|| panic!("{name} should have been rejected"));
            assert!(
                err.contains("cannot be caught"),
                "error for {name} should mention that it cannot be caught: {err}"
            );
        }
    }

    #[test]
    fn rejects_unknown_signals() {
        for name in ["USR1", "SIGUSR2", "", "SIG", "PWR"] {
            let err = GracefulSignal::parse(name)
                .err()
                .unwrap_or_else(|| panic!("{name:?} should have been rejected"));
            assert!(
                err.contains("TERM, INT, HUP, QUIT"),
                "error for {name:?} should list the allowed signals: {err}"
            );
        }
    }

    #[test]
    fn maps_to_libc_numbers() {
        assert_eq!(GracefulSignal::Term.libc_number(), libc::SIGTERM);
        assert_eq!(GracefulSignal::Int.libc_number(), libc::SIGINT);
        assert_eq!(GracefulSignal::Hup.libc_number(), libc::SIGHUP);
        assert_eq!(GracefulSignal::Quit.libc_number(), libc::SIGQUIT);
    }
}
