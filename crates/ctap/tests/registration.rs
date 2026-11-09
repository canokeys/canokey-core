// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::registration::{self, Backend, Commit};
use std::{cell::RefCell, rc::Rc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    Create,
    Commit,
    Respond,
}
#[derive(Default)]
struct State {
    events: Vec<&'static str>,
    durable: bool,
}
struct Credential(Rc<RefCell<State>>);
impl Drop for Credential {
    fn drop(&mut self) {
        self.0.borrow_mut().events.push("drop-credential");
    }
}
struct Fixture {
    state: Rc<RefCell<State>>,
    failure: Option<Failure>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.state.borrow_mut().events.push("drop-backend");
    }
}
impl Backend for Fixture {
    type Error = Failure;
    type Credential = Credential;
    type Output = usize;
    fn create(&mut self) -> Result<Credential, Failure> {
        self.state.borrow_mut().events.push("create");
        if self.failure == Some(Failure::Create) {
            return Err(Failure::Create);
        }
        Ok(Credential(self.state.clone()))
    }
    fn commit(&mut self, credential: &Credential) -> Result<(), Failure> {
        assert!(Rc::ptr_eq(&credential.0, &self.state));
        self.state.borrow_mut().events.push("commit");
        if self.failure == Some(Failure::Commit) {
            return Err(Failure::Commit);
        }
        self.state.borrow_mut().durable = true;
        Ok(())
    }
    fn respond(&mut self, credential: &Credential) -> Result<usize, Failure> {
        assert!(Rc::ptr_eq(&credential.0, &self.state));
        self.state.borrow_mut().events.push("respond");
        if self.failure == Some(Failure::Respond) {
            return Err(Failure::Respond);
        }
        Ok(37)
    }
}
#[test]
fn resident_transactions_preserve_commit_order_and_failure_boundaries() {
    for (commit, failure, expected, durable) in [
        (
            Commit::BeforeResponse,
            None,
            vec!["create", "commit", "respond"],
            true,
        ),
        (
            Commit::AfterResponse,
            None,
            vec!["create", "respond", "commit"],
            true,
        ),
        (
            Commit::BeforeResponse,
            Some(Failure::Create),
            vec!["create"],
            false,
        ),
        (
            Commit::AfterResponse,
            Some(Failure::Create),
            vec!["create"],
            false,
        ),
        (
            Commit::BeforeResponse,
            Some(Failure::Commit),
            vec!["create", "commit"],
            false,
        ),
        (
            Commit::AfterResponse,
            Some(Failure::Commit),
            vec!["create", "respond", "commit"],
            false,
        ),
        (
            Commit::BeforeResponse,
            Some(Failure::Respond),
            vec!["create", "commit", "respond"],
            true,
        ),
        (
            Commit::AfterResponse,
            Some(Failure::Respond),
            vec!["create", "respond"],
            false,
        ),
    ] {
        let state = Rc::new(RefCell::new(State::default()));
        let result = registration::execute(
            true,
            commit,
            Fixture {
                state: state.clone(),
                failure,
            },
        );
        assert_eq!(result, failure.map_or(Ok(37), Err));
        let mut expected = expected;
        if failure != Some(Failure::Create) {
            expected.push("drop-credential");
        }
        expected.push("drop-backend");
        let state = state.borrow();
        assert_eq!(state.events, expected);
        assert_eq!(state.durable, durable);
    }
}
#[test]
fn nonresident_credentials_never_enter_storage_for_either_profile() {
    for commit in [Commit::BeforeResponse, Commit::AfterResponse] {
        for failure in [None, Some(Failure::Commit), Some(Failure::Respond)] {
            let state = Rc::new(RefCell::new(State::default()));
            let result = registration::execute(
                false,
                commit,
                Fixture {
                    state: state.clone(),
                    failure,
                },
            );
            assert_eq!(
                result,
                if failure == Some(Failure::Respond) {
                    Err(Failure::Respond)
                } else {
                    Ok(37)
                }
            );
            let state = state.borrow();
            assert_eq!(
                state.events,
                ["create", "respond", "drop-credential", "drop-backend"]
            );
            assert!(!state.durable);
        }
    }
}
