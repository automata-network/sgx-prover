use core::{
    cmp::Ordering,
    ops::{Add, Sub},
};

use chrono::{DateTime, Utc};
use std::time::{Duration, SystemTime};

pub fn now() -> Duration {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
}

#[derive(Clone, Default, Copy, PartialEq, Eq)]
pub struct SignedDuration {
    is_neg: bool,
    dur: Duration,
}

impl SignedDuration {
    pub fn sub<T>(a: T, b: T) -> Self
    where
        T: Sub<Output = Duration> + PartialOrd<T>,
    {
        let mut is_neg = false;
        let dur = if a > b {
            a - b
        } else {
            is_neg = true;
            b - a
        };
        Self { is_neg, dur }
    }

    pub fn from_millis(millis: i64) -> Self {
        Self {
            is_neg: millis.is_negative(),
            dur: Duration::from_millis(millis.abs() as u64),
        }
    }

    pub fn duration(&self) -> Option<Duration> {
        match self.is_neg {
            true => None,
            false => Some(self.dur.clone()),
        }
    }
}

impl PartialOrd<Duration> for SignedDuration {
    fn partial_cmp(&self, other: &Duration) -> Option<Ordering> {
        if self.is_neg {
            Some(Ordering::Less)
        } else {
            Some(self.dur.cmp(other))
        }
    }
}

impl PartialEq<Duration> for SignedDuration {
    fn eq(&self, other: &Duration) -> bool {
        !self.is_neg && self.eq(other)
    }
}

impl std::fmt::Debug for SignedDuration {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}{:?}", if self.is_neg { "-" } else { "" }, self.dur)
    }
}

pub struct Date(DateTime<Utc>);

impl From<Duration> for Date {
    fn from(du: Duration) -> Self {
        let nano = du.subsec_nanos() / 1_000_000 * 1_000_000;
        Self(DateTime::from_timestamp(du.as_secs() as i64, nano).unwrap())
    }
}

impl From<Time> for Date {
    fn from(time: Time) -> Self {
        time.0.into()
    }
}

impl std::fmt::Debug for Date {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.format())
    }
}

impl std::fmt::Display for Date {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.format())
    }
}

impl Date {
    pub fn format(&self) -> String {
        use chrono::format::Numeric::*;
        use chrono::format::Pad::Zero;
        use chrono::format::{Fixed, Item};

        const PREFIX: &[Item<'static>] = &[
            Item::Numeric(Year, Zero),
            Item::Literal("-"),
            Item::Numeric(Month, Zero),
            Item::Literal("-"),
            Item::Numeric(Day, Zero),
            Item::Literal(" "),
            Item::Numeric(Hour, Zero),
            Item::Literal(":"),
            Item::Numeric(Minute, Zero),
            Item::Literal(":"),
            Item::Numeric(Second, Zero),
        ];

        let ssitem = Item::Fixed(Fixed::Nanosecond3);
        self.0
            .format_with_items(PREFIX.iter().chain([ssitem].iter()))
            .to_string()
    }
}

#[derive(Clone, Copy, Ord, Eq)]
pub struct Time(Duration);

impl From<Duration> for Time {
    fn from(du: Duration) -> Self {
        Self(du)
    }
}

impl Time {
    pub fn now() -> Self {
        Self(now())
    }

    pub fn from_secs(secs: u64) -> Self {
        Self(Duration::from_secs(secs))
    }

    pub fn saturating_duration_since(&self, earlier: Self) -> Duration {
        self.checked_duration_since(earlier).unwrap_or_default()
    }

    pub fn duration_since(&self, earlier: Self) -> SignedDuration {
        SignedDuration::sub(*self, earlier)
    }

    pub fn checked_duration_since(&self, earlier: Time) -> Option<Duration> {
        self.checked_sub_time(&earlier)
    }

    pub fn checked_sub_time(&self, other: &Time) -> Option<Duration> {
        self.0.checked_sub(other.0)
    }
}

impl Sub<Duration> for Time {
    type Output = Time;
    fn sub(self, rhs: Duration) -> Self::Output {
        Self(self.0 - rhs)
    }
}

impl Sub<Time> for Time {
    type Output = Duration;
    fn sub(self, rhs: Time) -> Self::Output {
        self.0.sub(rhs.0)
    }
}

impl Add<Duration> for Time {
    type Output = Time;
    fn add(self, rhs: Duration) -> Self::Output {
        Self(self.0.add(rhs))
    }
}

impl std::fmt::Debug for Time {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl PartialEq<Time> for Time {
    fn eq(&self, other: &Time) -> bool {
        self.0.eq(&other.0)
    }
}

impl PartialOrd<Time> for Time {
    fn partial_cmp(&self, other: &Time) -> Option<core::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}
