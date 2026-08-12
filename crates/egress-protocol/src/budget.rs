//! Session-wide resource budgets for broker-dispatched requests.
//!
//! Capability delegation narrows authority sets, but a caller could otherwise
//! mint many valid children and multiply request count or response-byte usage.
//! This state machine owns those session-wide consumable limits separately.

use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    num::{NonZeroU64, NonZeroUsize},
};

use crate::session::BrokerRequestId;

/// Fixed resource ceilings for one Broker session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionBudgetLimits {
    requests: NonZeroU64,
    response_bytes: u64,
    concurrent: NonZeroUsize,
}

impl SessionBudgetLimits {
    /// Creates a session budget with non-zero request and concurrency ceilings.
    #[must_use]
    pub const fn new(
        max_requests: NonZeroU64,
        max_response_bytes: u64,
        max_concurrent_requests: NonZeroUsize,
    ) -> Self {
        Self {
            requests: max_requests,
            response_bytes: max_response_bytes,
            concurrent: max_concurrent_requests,
        }
    }

    /// Returns the maximum number of requests that may start in this session.
    #[must_use]
    pub const fn max_requests(self) -> NonZeroU64 {
        self.requests
    }

    /// Returns the total number of response bytes this session may consume.
    #[must_use]
    pub const fn max_response_bytes(self) -> u64 {
        self.response_bytes
    }

    /// Returns the maximum number of requests that may be active at once.
    #[must_use]
    pub const fn max_concurrent_requests(self) -> NonZeroUsize {
        self.concurrent
    }
}

/// A snapshot of budget use that does not expose mutable reservations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionBudgetUsage {
    started_requests: u64,
    committed_response_bytes: u64,
    reserved_response_bytes: u64,
    active_requests: usize,
}

impl SessionBudgetUsage {
    /// Returns how many requests have consumed a request-count token.
    #[must_use]
    pub const fn started_requests(self) -> u64 {
        self.started_requests
    }

    /// Returns response bytes actually completed by broker requests.
    #[must_use]
    pub const fn committed_response_bytes(self) -> u64 {
        self.committed_response_bytes
    }

    /// Returns response-byte capacity provisionally held by active requests.
    #[must_use]
    pub const fn reserved_response_bytes(self) -> u64 {
        self.reserved_response_bytes
    }

    /// Returns the number of currently active broker requests.
    #[must_use]
    pub const fn active_requests(self) -> usize {
        self.active_requests
    }
}

/// The bytes reserved for one active request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseReservation {
    request: BrokerRequestId,
    max_response_bytes: u64,
}

impl ResponseReservation {
    /// Returns the request identity that owns this reservation.
    #[must_use]
    pub const fn request(self) -> BrokerRequestId {
        self.request
    }

    /// Returns the hard byte ceiling reserved for this active request.
    #[must_use]
    pub const fn max_response_bytes(self) -> u64 {
        self.max_response_bytes
    }
}

/// Why a session resource budget cannot perform a requested transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionBudgetError {
    /// Starting another request would exceed the session's total request count.
    RequestCountExhausted,
    /// Starting another request would exceed the simultaneous request limit.
    ConcurrentRequestLimitReached,
    /// The requested byte reservation would exceed the remaining session budget.
    ResponseBytesExhausted {
        /// Bytes requested for the new response.
        requested: u64,
        /// Bytes uncommitted and unreserved at the failed transition.
        remaining: u64,
    },
    /// The caller tried to start the same request identity while it is active.
    ReservationAlreadyActive {
        /// Request identity with an existing active reservation.
        request: BrokerRequestId,
    },
    /// The caller tried to complete or abort a request that is not active.
    UnknownReservation {
        /// Request identity without an active reservation.
        request: BrokerRequestId,
    },
    /// A completion claims more bytes than the active reservation allowed.
    ResponseExceedsReservation {
        /// Request identity whose response exceeded its reservation.
        request: BrokerRequestId,
        /// Bytes reported by the transport.
        received: u64,
        /// Maximum bytes reserved for this request.
        reserved: u64,
    },
    /// Internal accounting stopped satisfying its checked arithmetic invariant.
    ///
    /// Callers must fail the session closed rather than attempting recovery.
    AccountingInvariantBroken,
}

impl fmt::Display for SessionBudgetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestCountExhausted => {
                formatter.write_str("broker session request budget is exhausted")
            }
            Self::ConcurrentRequestLimitReached => {
                formatter.write_str("broker session concurrent request limit is reached")
            }
            Self::ResponseBytesExhausted {
                requested,
                remaining,
            } => write!(
                formatter,
                "broker session cannot reserve {requested} response bytes; {remaining} remain"
            ),
            Self::ReservationAlreadyActive { .. } => {
                formatter.write_str("broker request already has an active response reservation")
            }
            Self::UnknownReservation { .. } => {
                formatter.write_str("broker request has no active response reservation")
            }
            Self::ResponseExceedsReservation {
                received, reserved, ..
            } => write!(
                formatter,
                "broker response reported {received} bytes but reserved at most {reserved}"
            ),
            Self::AccountingInvariantBroken => {
                formatter.write_str("broker session budget accounting invariant is broken")
            }
        }
    }
}

impl Error for SessionBudgetError {}

/// Stateful accounting for one broker session's consumable limits.
///
/// A successful [`Self::start`] consumes a request-count token permanently and
/// reserves the request's maximum response bytes. [`Self::complete`] converts
/// received bytes into committed usage and releases unused reservation bytes.
/// [`Self::abort`] releases all bytes but deliberately does not return the
/// request-count token: an attempted external request remains an attempt.
#[derive(Debug)]
pub struct SessionBudget {
    limits: SessionBudgetLimits,
    started_requests: u64,
    committed_response_bytes: u64,
    reserved_response_bytes: u64,
    active: BTreeMap<BrokerRequestId, ResponseReservation>,
}

impl SessionBudget {
    /// Creates an unused session budget with the supplied immutable ceilings.
    #[must_use]
    pub const fn new(limits: SessionBudgetLimits) -> Self {
        Self {
            limits,
            started_requests: 0,
            committed_response_bytes: 0,
            reserved_response_bytes: 0,
            active: BTreeMap::new(),
        }
    }

    /// Returns the immutable limits that govern this session.
    #[must_use]
    pub const fn limits(&self) -> SessionBudgetLimits {
        self.limits
    }

    /// Returns a read-only snapshot of current consumption and reservations.
    #[must_use]
    pub fn usage(&self) -> SessionBudgetUsage {
        SessionBudgetUsage {
            started_requests: self.started_requests,
            committed_response_bytes: self.committed_response_bytes,
            reserved_response_bytes: self.reserved_response_bytes,
            active_requests: self.active.len(),
        }
    }

    /// Starts a request after authority and replay checks have accepted it.
    ///
    /// # Errors
    ///
    /// Returns an error without changing any accounting when the request ID is
    /// active already, or any count / concurrency / response-byte ceiling
    /// would be exceeded.
    pub fn start(
        &mut self,
        request: BrokerRequestId,
        max_response_bytes: u64,
    ) -> Result<ResponseReservation, SessionBudgetError> {
        if self.active.contains_key(&request) {
            return Err(SessionBudgetError::ReservationAlreadyActive { request });
        }
        if self.started_requests >= self.limits.requests.get() {
            return Err(SessionBudgetError::RequestCountExhausted);
        }
        if self.active.len() >= self.limits.concurrent.get() {
            return Err(SessionBudgetError::ConcurrentRequestLimitReached);
        }

        let used_or_reserved = self
            .committed_response_bytes
            .checked_add(self.reserved_response_bytes)
            .ok_or(SessionBudgetError::AccountingInvariantBroken)?;
        let remaining = self
            .limits
            .response_bytes
            .checked_sub(used_or_reserved)
            .ok_or(SessionBudgetError::AccountingInvariantBroken)?;
        if max_response_bytes > remaining {
            return Err(SessionBudgetError::ResponseBytesExhausted {
                requested: max_response_bytes,
                remaining,
            });
        }

        let next_started_requests = self
            .started_requests
            .checked_add(1)
            .ok_or(SessionBudgetError::AccountingInvariantBroken)?;
        let next_reserved_response_bytes = self
            .reserved_response_bytes
            .checked_add(max_response_bytes)
            .ok_or(SessionBudgetError::AccountingInvariantBroken)?;
        let reservation = ResponseReservation {
            request,
            max_response_bytes,
        };
        self.started_requests = next_started_requests;
        self.reserved_response_bytes = next_reserved_response_bytes;
        self.active.insert(request, reservation);
        Ok(reservation)
    }

    /// Completes one active request and records the actual received bytes.
    ///
    /// # Errors
    ///
    /// Returns an error without removing the reservation when the request is
    /// unknown, reports too many bytes, or accounting is inconsistent.
    pub fn complete(
        &mut self,
        request: BrokerRequestId,
        received_response_bytes: u64,
    ) -> Result<(), SessionBudgetError> {
        let reservation = self
            .active
            .get(&request)
            .copied()
            .ok_or(SessionBudgetError::UnknownReservation { request })?;
        if received_response_bytes > reservation.max_response_bytes {
            return Err(SessionBudgetError::ResponseExceedsReservation {
                request,
                received: received_response_bytes,
                reserved: reservation.max_response_bytes,
            });
        }
        let next_committed_response_bytes = self
            .committed_response_bytes
            .checked_add(received_response_bytes)
            .ok_or(SessionBudgetError::AccountingInvariantBroken)?;
        let next_reserved_response_bytes = self
            .reserved_response_bytes
            .checked_sub(reservation.max_response_bytes)
            .ok_or(SessionBudgetError::AccountingInvariantBroken)?;

        self.active.remove(&request);
        self.committed_response_bytes = next_committed_response_bytes;
        self.reserved_response_bytes = next_reserved_response_bytes;
        Ok(())
    }

    /// Aborts one active request and releases its reserved response bytes.
    ///
    /// The request count remains consumed because the broker already began an
    /// external request attempt.
    ///
    /// # Errors
    ///
    /// Returns an error without changing state when the request is unknown or
    /// the accounting invariant has already been violated.
    pub fn abort(&mut self, request: BrokerRequestId) -> Result<(), SessionBudgetError> {
        let reservation = self
            .active
            .get(&request)
            .copied()
            .ok_or(SessionBudgetError::UnknownReservation { request })?;
        let next_reserved_response_bytes = self
            .reserved_response_bytes
            .checked_sub(reservation.max_response_bytes)
            .ok_or(SessionBudgetError::AccountingInvariantBroken)?;

        self.active.remove(&request);
        self.reserved_response_bytes = next_reserved_response_bytes;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::num::{NonZeroU64, NonZeroUsize};

    use super::{SessionBudget, SessionBudgetError, SessionBudgetLimits, SessionBudgetUsage};
    use crate::session::BrokerRequestId;

    fn request(value: u8) -> BrokerRequestId {
        BrokerRequestId::new([value; 16])
    }

    fn limits() -> SessionBudgetLimits {
        SessionBudgetLimits::new(
            NonZeroU64::new(3).expect("test request limit must be non-zero"),
            100,
            NonZeroUsize::new(2).expect("test concurrency limit must be non-zero"),
        )
    }

    #[test]
    fn complete_commits_actual_bytes_and_releases_unused_reservation() {
        let mut budget = SessionBudget::new(limits());
        let first = request(1);

        assert_eq!(
            budget
                .start(first, 80)
                .map(super::ResponseReservation::request),
            Ok(first)
        );
        assert_eq!(
            budget.usage(),
            SessionBudgetUsage {
                started_requests: 1,
                committed_response_bytes: 0,
                reserved_response_bytes: 80,
                active_requests: 1,
            }
        );
        assert_eq!(budget.complete(first, 25), Ok(()));
        assert_eq!(
            budget.usage(),
            SessionBudgetUsage {
                started_requests: 1,
                committed_response_bytes: 25,
                reserved_response_bytes: 0,
                active_requests: 0,
            }
        );
        assert!(budget.start(request(2), 75).is_ok());
    }

    #[test]
    fn start_rejects_duplicate_active_requests_and_every_budget_exhaustion() {
        let mut budget = SessionBudget::new(limits());
        assert_eq!(budget.start(request(1), 60).map(|_| ()), Ok(()));
        assert_eq!(
            budget.start(request(1), 1),
            Err(SessionBudgetError::ReservationAlreadyActive {
                request: request(1),
            })
        );
        assert_eq!(
            budget.start(request(2), 41),
            Err(SessionBudgetError::ResponseBytesExhausted {
                requested: 41,
                remaining: 40,
            })
        );
        assert_eq!(budget.start(request(2), 40).map(|_| ()), Ok(()));
        assert_eq!(
            budget.start(request(3), 0),
            Err(SessionBudgetError::ConcurrentRequestLimitReached)
        );

        assert_eq!(budget.abort(request(1)), Ok(()));
        assert_eq!(budget.abort(request(2)), Ok(()));
        assert_eq!(budget.start(request(3), 0).map(|_| ()), Ok(()));
        assert_eq!(
            budget.start(request(4), 0),
            Err(SessionBudgetError::RequestCountExhausted)
        );
    }

    #[test]
    fn complete_rejects_an_oversized_or_unknown_response_without_releasing_it() {
        let mut budget = SessionBudget::new(limits());
        assert_eq!(budget.start(request(1), 10).map(|_| ()), Ok(()));

        assert_eq!(
            budget.complete(request(1), 11),
            Err(SessionBudgetError::ResponseExceedsReservation {
                request: request(1),
                received: 11,
                reserved: 10,
            })
        );
        assert_eq!(budget.usage().active_requests(), 1);
        assert_eq!(
            budget.complete(request(2), 0),
            Err(SessionBudgetError::UnknownReservation {
                request: request(2),
            })
        );
        assert_eq!(budget.complete(request(1), 10), Ok(()));
    }

    #[test]
    fn abort_releases_bytes_but_never_refunds_the_request_count() {
        let limits = SessionBudgetLimits::new(
            NonZeroU64::new(1).expect("test request limit must be non-zero"),
            10,
            NonZeroUsize::new(1).expect("test concurrency limit must be non-zero"),
        );
        let mut budget = SessionBudget::new(limits);
        assert_eq!(budget.start(request(1), 10).map(|_| ()), Ok(()));
        assert_eq!(budget.abort(request(1)), Ok(()));
        assert_eq!(budget.usage().reserved_response_bytes(), 0);
        assert_eq!(
            budget.start(request(2), 10),
            Err(SessionBudgetError::RequestCountExhausted)
        );
    }
}
