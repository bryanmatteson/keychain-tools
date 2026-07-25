//! Timestamped stderr logging for the long-running service.
//!
//! The service is meant to run under launchd, where stderr lands in a log file
//! with no timestamps of its own, so each line stamps itself. Deliberately not a
//! logging framework: one level, one destination, no configuration.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

/// Log a line to stderr with a UTC timestamp.
#[macro_export]
macro_rules! log_line {
    ($($arg:tt)*) => {
        $crate::logging::emit(&format!($($arg)*))
    };
}

pub fn emit(message: &str) {
    let stamp = timestamp(SystemTime::now());
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "{stamp} {message}");
}

/// Format a time as `YYYY-MM-DDTHH:MM:SSZ`.
fn timestamp(now: SystemTime) -> String {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (days, seconds_of_day) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (
        seconds_of_day / 3600,
        (seconds_of_day % 3600) / 60,
        seconds_of_day % 60,
    );
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Days since 1970-01-01 to a civil date (Howard Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(epoch_secs: u64) -> String {
        timestamp(UNIX_EPOCH + Duration::from_secs(epoch_secs))
    }

    #[test]
    fn formats_known_instants() {
        assert_eq!(at(0), "1970-01-01T00:00:00Z");
        assert_eq!(at(1), "1970-01-01T00:00:01Z");
        assert_eq!(at(86_399), "1970-01-01T23:59:59Z");
        assert_eq!(at(86_400), "1970-01-02T00:00:00Z");
        assert_eq!(at(1_784_982_896), "2026-07-25T12:34:56Z");
        // Leap day, and the day after.
        assert_eq!(at(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(at(1_709_251_200), "2024-03-01T00:00:00Z");
        // Century non-leap year boundary.
        assert_eq!(at(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn stamps_are_fixed_width_and_sort_chronologically() {
        let early = at(1_000_000_000);
        let late = at(2_000_000_000);
        assert_eq!(early.len(), 20);
        assert_eq!(late.len(), 20);
        assert!(early < late);
    }
}
