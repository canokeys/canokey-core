// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::selection::{self, Backend, Walk};
use std::cell::RefCell;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Error {
    Parse,
    Storage,
    Cancel,
    Timeout,
    Excluded,
    NoCredentials,
    Complete,
}

#[test]
fn borrowed_tail_validation_continues_without_opening_later_credentials() {
    for (walk, parsed, opened, result) in [
        (Walk::First, 2, 1, Ok(Some(1))),
        (Walk::ValidateTail, 4, 1, Err(Error::Parse)),
    ] {
        let mut parse_count = 0;
        let mut open_count = 0;
        let candidates = [Ok(None), Ok(Some(1)), Ok(Some(2)), Err(Error::Parse)]
            .into_iter()
            .inspect(|_| parse_count += 1);
        let actual = selection::listed(candidates, walk, |id| {
            open_count += 1;
            if id == 2 {
                Err(Error::Storage)
            } else {
                Ok(Some(id))
            }
        });
        assert_eq!(actual, result);
        assert_eq!((parse_count, open_count), (parsed, opened));
    }
}

#[test]
fn both_list_owners_keep_first_match_and_skip_foreign_handles() {
    for walk in [Walk::First, Walk::ValidateTail] {
        let mut opened = Vec::new();
        let selected = selection::listed(
            [Ok::<_, Error>(Some(0)), Ok(Some(1)), Ok(Some(2))],
            walk,
            |id| {
                opened.push(id);
                Ok((id != 0).then_some(id))
            },
        );
        assert_eq!(selected, Ok(Some(1)));
        assert_eq!(opened, vec![0, 1]);
    }
    assert_eq!(
        selection::listed([Ok::<_, Error>(None)], Walk::ValidateTail, |_: u8| Ok(
            Some(1)
        )),
        Ok(None)
    );
}

struct Operation<'a> {
    trace: &'a RefCell<Vec<&'static str>>,
    selected: Result<bool, Error>,
    presence: Result<(), Error>,
    complete: Result<(), Error>,
}
impl Backend for Operation<'_> {
    type Error = Error;
    type Output = ();
    fn select(&mut self) -> Result<bool, Error> {
        self.trace.borrow_mut().push("select");
        self.selected
    }
    fn presence(&mut self, up: bool) -> Result<(), Error> {
        self.trace
            .borrow_mut()
            .push(if up { "up" } else { "deadline" });
        self.presence
    }
    fn excluded(result: Result<(), Error>) -> Error {
        match result {
            Err(Error::Cancel) => Error::Cancel,
            _ => Error::Excluded,
        }
    }
    fn no_credentials() -> Error {
        Error::NoCredentials
    }
    fn consume_presence(&mut self) {
        self.trace.borrow_mut().push("consume");
    }
    fn complete(self) -> Result<(), Error> {
        self.trace.borrow_mut().push("complete");
        self.complete
    }
}

#[test]
fn exclusion_preserves_cancel_and_never_consumes_normal_presence() {
    for (presence, expected) in [
        (Ok(()), Error::Excluded),
        (Err(Error::Timeout), Error::Excluded),
        (Err(Error::Cancel), Error::Cancel),
    ] {
        let trace = RefCell::new(Vec::new());
        let result = selection::execute(
            true,
            true,
            Operation {
                trace: &trace,
                selected: Ok(true),
                presence,
                complete: Ok(()),
            },
        );
        assert_eq!(result, Err(expected));
        assert_eq!(*trace.borrow(), ["select", "up"]);
    }
}

#[test]
fn selection_failure_or_no_credential_precedes_presence() {
    for (selected, expected) in [
        (Err(Error::Storage), Error::Storage),
        (Ok(false), Error::NoCredentials),
    ] {
        let trace = RefCell::new(Vec::new());
        let result = selection::execute(
            false,
            true,
            Operation {
                trace: &trace,
                selected,
                presence: Err(Error::Cancel),
                complete: Ok(()),
            },
        );
        assert_eq!(result, Err(expected));
        assert_eq!(*trace.borrow(), ["select"]);
    }
}

#[test]
fn presence_failure_prevents_consumption_and_response_work() {
    for up in [false, true] {
        let trace = RefCell::new(Vec::new());
        let result = selection::execute(
            false,
            up,
            Operation {
                trace: &trace,
                selected: Ok(true),
                presence: Err(Error::Timeout),
                complete: Ok(()),
            },
        );
        assert_eq!(result, Err(Error::Timeout));
        assert_eq!(
            *trace.borrow(),
            ["select", if up { "up" } else { "deadline" }]
        );
    }
}

#[test]
fn normal_presence_is_consumed_before_extensions_and_create_or_sign() {
    for (make, selected) in [(false, true), (true, false)] {
        let trace = RefCell::new(Vec::new());
        let result = selection::execute(
            make,
            true,
            Operation {
                trace: &trace,
                selected: Ok(selected),
                presence: Ok(()),
                complete: Err(Error::Complete),
            },
        );
        assert_eq!(result, Err(Error::Complete));
        assert_eq!(*trace.borrow(), ["select", "up", "consume", "complete"]);
    }
}

#[test]
fn silent_assertion_rechecks_deadline_without_consuming_authorization() {
    let trace = RefCell::new(Vec::new());
    let result = selection::execute(
        false,
        false,
        Operation {
            trace: &trace,
            selected: Ok(true),
            presence: Ok(()),
            complete: Ok(()),
        },
    );
    assert_eq!(result, Ok(()));
    assert_eq!(*trace.borrow(), ["select", "deadline", "complete"]);
}
