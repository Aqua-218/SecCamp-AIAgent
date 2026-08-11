//! Session-local monotonic time windows used by capability authorities.

use std::{error::Error, fmt};

/// A timestamp measured by the session host's monotonic clock.
///
/// Values are only comparable when they use the same session-local clock
/// origin and tick unit. Authority core deliberately does not interpret ticks
/// as wall-clock time or carry them across VM sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonotonicTime(u64);

impl MonotonicTime {
    /// Creates a timestamp from host-assigned monotonic clock ticks.
    #[must_use]
    pub const fn from_ticks(ticks: u64) -> Self {
        Self(ticks)
    }

    /// Returns the host-assigned monotonic clock ticks.
    #[must_use]
    pub const fn ticks(self) -> u64 {
        self.0
    }
}

/// A non-empty half-open validity interval `[not_before, expires_at)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimeWindow {
    not_before: MonotonicTime,
    expires_at: MonotonicTime,
}

impl TimeWindow {
    /// Creates a non-empty capability validity window.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTimeWindow`] unless `not_before < expires_at`.
    pub const fn new(
        not_before: MonotonicTime,
        expires_at: MonotonicTime,
    ) -> Result<Self, InvalidTimeWindow> {
        if not_before.0 < expires_at.0 {
            Ok(Self {
                not_before,
                expires_at,
            })
        } else {
            Err(InvalidTimeWindow {
                not_before,
                expires_at,
            })
        }
    }

    /// Returns the inclusive lower bound.
    #[must_use]
    pub const fn not_before(self) -> MonotonicTime {
        self.not_before
    }

    /// Returns the exclusive upper bound.
    #[must_use]
    pub const fn expires_at(self) -> MonotonicTime {
        self.expires_at
    }

    /// Returns whether `time` belongs to this half-open interval.
    #[must_use]
    pub const fn contains(self, time: MonotonicTime) -> bool {
        self.not_before.0 <= time.0 && time.0 < self.expires_at.0
    }

    /// Returns whether every time in this window also belongs to `parent`.
    #[must_use]
    pub const fn is_subset_of(self, parent: Self) -> bool {
        parent.not_before.0 <= self.not_before.0 && self.expires_at.0 <= parent.expires_at.0
    }
}

/// Reports bounds that do not form a non-empty half-open time window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidTimeWindow {
    not_before: MonotonicTime,
    expires_at: MonotonicTime,
}

impl InvalidTimeWindow {
    /// Returns the rejected inclusive lower bound.
    #[must_use]
    pub const fn not_before(self) -> MonotonicTime {
        self.not_before
    }

    /// Returns the rejected exclusive upper bound.
    #[must_use]
    pub const fn expires_at(self) -> MonotonicTime {
        self.expires_at
    }
}

impl fmt::Display for InvalidTimeWindow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid time window: not_before ({}) must be less than expires_at ({})",
            self.not_before.ticks(),
            self.expires_at.ticks()
        )
    }
}

impl Error for InvalidTimeWindow {}

#[cfg(test)]
mod tests {
    use super::{InvalidTimeWindow, MonotonicTime, TimeWindow};

    const fn time(ticks: u64) -> MonotonicTime {
        MonotonicTime::from_ticks(ticks)
    }

    fn window(not_before: u64, expires_at: u64) -> TimeWindow {
        TimeWindow::new(time(not_before), time(expires_at))
            .expect("test bounds must form a non-empty time window")
    }

    #[test]
    fn time_window_requires_strictly_ordered_bounds() {
        let valid = window(10, 20);
        let empty = TimeWindow::new(time(10), time(10))
            .expect_err("equal bounds must not form a time window");
        let reversed = TimeWindow::new(time(20), time(10))
            .expect_err("reversed bounds must not form a time window");

        assert_eq!(valid.not_before(), time(10));
        assert_eq!(valid.expires_at(), time(20));
        assert_eq!(
            empty,
            InvalidTimeWindow {
                not_before: time(10),
                expires_at: time(10),
            }
        );
        assert_eq!(reversed.not_before(), time(20));
        assert_eq!(reversed.expires_at(), time(10));
        assert_eq!(
            reversed.to_string(),
            "invalid time window: not_before (20) must be less than expires_at (10)"
        );
    }

    #[test]
    fn time_window_contains_its_lower_but_not_upper_bound() {
        let validity = window(10, 20);

        assert!(!validity.contains(time(9)));
        assert!(validity.contains(time(10)));
        assert!(validity.contains(time(19)));
        assert!(!validity.contains(time(20)));
    }

    #[test]
    fn time_window_subset_requires_both_bounds_inside_parent() {
        let parent = window(10, 30);

        assert!(parent.is_subset_of(parent));
        assert!(window(10, 20).is_subset_of(parent));
        assert!(window(20, 30).is_subset_of(parent));
        assert!(!window(9, 20).is_subset_of(parent));
        assert!(!window(20, 31).is_subset_of(parent));
    }

    #[test]
    fn time_window_subset_is_transitive() {
        let leaf = window(30, 40);
        let child = window(20, 50);
        let root = window(10, 60);

        assert!(leaf.is_subset_of(child));
        assert!(child.is_subset_of(root));
        assert!(leaf.is_subset_of(root));
    }
}
