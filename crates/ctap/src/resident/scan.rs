// SPDX-License-Identifier: Apache-2.0
//! Synchronous slot traversal without owning payload or storage caches.
//!
//! Readers retain their existing scratch buffer and validation policy. Returned
//! values must own their fields; no payload lease crosses a scan invocation.

/// Ascending search, including `start`. Stops immediately on a match or error.
pub fn ascending<T, E>(
    start: u8,
    capacity: u8,
    mut read: impl FnMut(u8) -> Result<Option<T>, E>,
) -> Result<Option<(u8, T)>, E> {
    for index in start..capacity {
        if let Some(value) = read(index)? {
            return Ok(Some((index, value)));
        }
    }
    Ok(None)
}

/// Descending search. Consume the slot before reading, including on failure,
/// so continuation excludes the last attempted slot. Capacity is caller-owned.
pub fn descending<T, E>(
    next: &mut u8,
    mut read: impl FnMut(u8) -> Result<Option<T>, E>,
) -> Result<Option<(u8, T)>, E> {
    while *next != 0 {
        *next -= 1;
        if let Some(value) = read(*next)? {
            return Ok(Some((*next, value)));
        }
    }
    Ok(None)
}

/// Prefer an existing RP/user match over the first empty slot. The reader
/// returns None for empty, Some(true) for a match, Some(false) for another user.
pub fn replacement<E>(
    capacity: u8,
    mut read: impl FnMut(u8) -> Result<Option<bool>, E>,
) -> Result<Option<u8>, E> {
    let mut empty = None;
    for index in 0..capacity {
        match read(index)? {
            Some(true) => return Ok(Some(index)),
            None => {
                empty.get_or_insert(index);
            }
            Some(false) => {}
        }
    }
    Ok(empty)
}

pub fn count<E>(capacity: u8, mut included: impl FnMut(u8) -> Result<bool, E>) -> Result<u8, E> {
    let mut count = 0;
    for index in 0..capacity {
        if included(index)? {
            count += 1;
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_profiles_and_holes_preserve_order() {
        for capacity in [64, 100, u8::MAX] {
            assert_eq!(count(capacity, |_| Ok::<_, ()>(true)), Ok(capacity));
            assert_eq!(
                replacement(capacity, |_| Ok::<_, ()>(Some(false))),
                Ok(None)
            );
            assert_eq!(
                replacement(capacity, |index| Ok::<_, ()>(if index == 1 {
                    None
                } else {
                    Some(index == capacity - 1)
                })),
                Ok(Some(capacity - 1))
            );
            let mut next = capacity;
            for expected in (0..capacity).rev().filter(|index| index % 3 == 0) {
                assert_eq!(
                    descending(&mut next, |index| Ok::<_, ()>(
                        (index % 3 == 0).then_some(index)
                    )),
                    Ok(Some((expected, expected)))
                );
                assert_eq!(next, expected);
            }
            assert_eq!(descending(&mut next, |_| Ok::<_, ()>(None::<()>)), Ok(None));
            assert_eq!(next, 0);
        }
    }

    #[test]
    fn failures_stop_before_later_matches_and_consume_descending_cursor() {
        let mut calls = 0;
        let mut next = 5;
        assert_eq!(
            descending::<(), _>(&mut next, |index| {
                calls += 1;
                if index == 3 { Err(()) } else { Ok(None) }
            }),
            Err(())
        );
        assert_eq!((calls, next), (2, 3));
        assert_eq!(
            ascending(2, 5, |index| Ok::<_, ()>((index == 3).then_some(7))),
            Ok(Some((3, 7)))
        );
        assert_eq!(
            replacement(5, |index| match index {
                0 => Ok(None),
                1 => Err(()),
                _ => panic!("read beyond error"),
            }),
            Err(())
        );
        assert_eq!(
            replacement(0, |_| panic!("read empty capacity")),
            Ok::<_, ()>(None)
        );
        assert_eq!(count(0, |_| panic!("read empty capacity")), Ok::<_, ()>(0));
    }
}
