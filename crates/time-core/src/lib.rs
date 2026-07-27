#![no_std]
#![deny(unsafe_code)]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UtcDateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidDate,
    InvalidYear,
}

pub const fn leap_year(year: u16) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

pub const fn days_in_month(year: u16, month: u8) -> Option<u8> {
    Some(match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year(year) => 29,
        2 => 28,
        _ => return None,
    })
}

pub fn unix_seconds(date: UtcDateTime) -> Result<u64, Error> {
    if !(2020..=2099).contains(&date.year) {
        return Err(Error::InvalidYear);
    }
    let month_days = days_in_month(date.year, date.month).ok_or(Error::InvalidDate)?;
    if date.day == 0
        || date.day > month_days
        || date.hour > 23
        || date.minute > 59
        || date.second > 59
    {
        return Err(Error::InvalidDate);
    }
    let mut days = 0u64;
    for year in 1970..date.year {
        days += if leap_year(year) { 366 } else { 365 };
    }
    for month in 1..date.month {
        days += u64::from(days_in_month(date.year, month).ok_or(Error::InvalidDate)?);
    }
    days += u64::from(date.day - 1);
    Ok(days * 86_400
        + u64::from(date.hour) * 3_600
        + u64::from(date.minute) * 60
        + u64::from(date.second))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_valid_utc_to_unix_seconds() {
        assert_eq!(
            unix_seconds(UtcDateTime {
                year: 2024,
                month: 2,
                day: 29,
                hour: 12,
                minute: 34,
                second: 56,
            }),
            Ok(1_709_210_096)
        );
    }

    #[test]
    fn rejects_invalid_dates_and_years() {
        assert_eq!(
            unix_seconds(UtcDateTime {
                year: 2019,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
            }),
            Err(Error::InvalidYear)
        );
        assert_eq!(
            unix_seconds(UtcDateTime {
                year: 2023,
                month: 2,
                day: 29,
                hour: 0,
                minute: 0,
                second: 0,
            }),
            Err(Error::InvalidDate)
        );
        assert_eq!(
            unix_seconds(UtcDateTime {
                year: 2024,
                month: 13,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
            }),
            Err(Error::InvalidDate)
        );
    }

    #[test]
    fn utc_epoch_progress_is_separate_from_monotonic_elapsed_time() {
        let base = unix_seconds(UtcDateTime {
            year: 2025,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
        });
        assert_eq!(base, Ok(1_735_689_600));
        let monotonic_elapsed_seconds = 5u64;
        assert_eq!(
            base.map(|seconds| seconds + monotonic_elapsed_seconds),
            Ok(1_735_689_605)
        );
        assert_ne!(monotonic_elapsed_seconds, 1_735_689_605);
    }
}
