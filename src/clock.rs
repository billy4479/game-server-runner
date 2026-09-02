//! Unix time helper, shared by sessions, tokens and the auto-stop scheduler.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current Unix time in whole seconds; `0` if the clock is before the epoch.
#[must_use]
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |delta| {
            i64::try_from(delta.as_secs()).unwrap_or(i64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_now_is_plausible() {
        let now = unix_now();
        // Any wall clock after 2020-01-01 and before year 2100.
        assert!(now > 1_577_836_800, "now {now} should be after 2020");
        assert!(now < 4_102_444_800, "now {now} should be before 2100");
    }
}
