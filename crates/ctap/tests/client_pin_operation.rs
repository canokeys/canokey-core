// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::client_pin::{
    operation::{self, AdmissionError, Backend, Kind, State},
    request::Command,
};
use std::{cell::RefCell, rc::Rc};

struct Loan {
    log: Rc<RefCell<Vec<&'static str>>>,
    release: &'static str,
}
impl Drop for Loan {
    fn drop(&mut self) {
        self.log.borrow_mut().push(self.release);
    }
}
struct Product {
    log: Rc<RefCell<Vec<&'static str>>>,
    configured: bool,
    retries: u8,
    attempts_blocked: bool,
    fail: Option<&'static str>,
}
impl Product {
    fn call(&mut self, event: &'static str) -> Result<(), &'static str> {
        self.log.borrow_mut().push(event);
        if self.fail == Some(event) {
            Err(event)
        } else {
            Ok(())
        }
    }
}
impl Backend for Product {
    type Error = &'static str;
    type Output = usize;
    type Shared = Loan;
    type CurrentPin = Loan;
    fn admission_error(error: AdmissionError) -> &'static str {
        match error {
            AdmissionError::AlreadyConfigured => "already configured",
            AdmissionError::NotConfigured => "not configured",
            AdmissionError::Blocked => "blocked",
            AdmissionError::PowerCycleBlocked => "power cycle blocked",
        }
    }
    fn state(&mut self) -> Result<State, Self::Error> {
        self.call("state")?;
        Ok(State {
            configured: self.configured,
            retries: self.retries,
            power_cycle_blocked: self.attempts_blocked,
        })
    }
    fn agree(&mut self) -> Result<Loan, Self::Error> {
        self.call("agree")?;
        Ok(Loan {
            log: self.log.clone(),
            release: "erase shared",
        })
    }
    fn authenticate_new_pin(&mut self, shared: &Loan, changing: bool) -> Result<(), Self::Error> {
        assert_eq!(shared.release, "erase shared");
        self.call(if changing { "mac new+old" } else { "mac new" })
    }
    fn prepare_current_pin(&mut self, shared: &Loan) -> Result<Loan, Self::Error> {
        assert_eq!(shared.release, "erase shared");
        self.call("prepare current")?;
        Ok(Loan {
            log: self.log.clone(),
            release: "erase current",
        })
    }
    fn set_pin(&mut self, _: &Loan) -> Result<usize, Self::Error> {
        self.call("set transaction")?;
        Ok(1)
    }
    fn change_pin(&mut self, _: &Loan, current: &Loan) -> Result<usize, Self::Error> {
        assert_eq!(current.release, "erase current");
        self.call("change transaction")?;
        Ok(1)
    }
    fn issue_token(&mut self, _: &Loan, current: &Loan) -> Result<usize, Self::Error> {
        assert_eq!(current.release, "erase current");
        self.call("token transaction")?;
        Ok(1)
    }
}
fn product(kind: Kind) -> Product {
    Product {
        log: Rc::new(RefCell::new(Vec::new())),
        configured: kind != Kind::Set,
        retries: 8,
        attempts_blocked: false,
        fail: None,
    }
}
fn path(kind: Kind) -> Vec<&'static str> {
    match kind {
        Kind::Set => vec!["state", "agree", "mac new", "set transaction"],
        Kind::Change => vec![
            "state",
            "agree",
            "mac new+old",
            "prepare current",
            "change transaction",
        ],
        Kind::Token => vec!["state", "agree", "prepare current", "token transaction"],
    }
}
#[test]
fn standard_commands_select_only_their_actual_operation() {
    for (command, expected) in [
        (Command::Set, Some(Kind::Set)),
        (Command::Change, Some(Kind::Change)),
        (Command::Token, Some(Kind::Token)),
        (Command::TokenPermissions, Some(Kind::Token)),
        (Command::Retries, None),
        (Command::Agreement, None),
    ] {
        assert_eq!(Kind::from_command(command), expected);
    }
}
#[test]
fn admission_matrix_preserves_first_error_and_set_ignores_existing_attempt_limits() {
    for kind in [Kind::Set, Kind::Change, Kind::Token] {
        for configured in [false, true] {
            for retries in [0, 1, 8] {
                for attempts_blocked in [false, true] {
                    let mut backend = product(kind);
                    backend.configured = configured;
                    backend.retries = retries;
                    backend.attempts_blocked = attempts_blocked;
                    let expected = if kind == Kind::Set {
                        configured.then_some("already configured")
                    } else if !configured {
                        Some("not configured")
                    } else if retries == 0 {
                        Some("blocked")
                    } else if attempts_blocked {
                        Some("power cycle blocked")
                    } else {
                        None
                    };
                    let result = operation::execute(kind, &mut backend);
                    assert_eq!(result, expected.map_or(Ok(1), Err));
                    if expected.is_some() {
                        assert_eq!(*backend.log.borrow(), ["state"]);
                    }
                }
            }
        }
    }
}
#[test]
fn each_failure_stops_before_later_transactions_and_releases_acquired_loans() {
    for kind in [Kind::Set, Kind::Change, Kind::Token] {
        let expected = path(kind);
        for fail_at in 0..=expected.len() {
            let mut backend = product(kind);
            backend.fail = expected.get(fail_at).copied();
            let result = operation::execute(kind, &mut backend);
            assert_eq!(result, backend.fail.map_or(Ok(1), Err));
            let completed = fail_at.min(expected.len() - 1);
            let mut events = expected[..=completed].to_vec();
            if expected[..completed].contains(&"prepare current") {
                events.push("erase current");
            }
            if completed >= 2 {
                events.push("erase shared");
            }
            assert_eq!(*backend.log.borrow(), events, "{kind:?}, {fail_at}");
        }
    }
}
