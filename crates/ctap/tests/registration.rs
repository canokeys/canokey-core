// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::registration::{self, Backend, Publisher};
use std::{cell::RefCell, rc::Rc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    Create,
    Stage,
    Commit,
    Uncertain,
    Respond,
}
#[derive(Default)]
struct State {
    events: Vec<&'static str>,
    durable: bool,
    staged: bool,
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
    type Publication = ();
    type Output = usize;
    fn create(&mut self) -> Result<Credential, Failure> {
        self.state.borrow_mut().events.push("create");
        if self.failure == Some(Failure::Create) {
            return Err(Failure::Create);
        }
        Ok(Credential(self.state.clone()))
    }
    fn stage(&mut self, _: &Credential) -> Result<(), Failure> {
        self.state.borrow_mut().events.push("stage");
        if self.failure == Some(Failure::Stage) {
            return Err(Failure::Stage);
        }
        self.state.borrow_mut().staged = true;
        Ok(())
    }
    fn commit(&mut self, credential: &Credential, _: &()) -> Result<(), Failure> {
        assert!(Rc::ptr_eq(&credential.0, &self.state));
        assert!(self.state.borrow().staged);
        self.state.borrow_mut().events.push("commit");
        if self.failure == Some(Failure::Commit) {
            return Err(Failure::Commit);
        }
        self.state.borrow_mut().durable = true;
        self.state.borrow_mut().staged = false;
        if self.failure == Some(Failure::Uncertain) {
            return Err(Failure::Uncertain);
        }
        Ok(())
    }
    fn abort(&mut self, _: &()) {
        self.state.borrow_mut().events.push("abort");
        self.state.borrow_mut().staged = false;
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
impl Publisher<Credential, ()> for Fixture {
    type Error = Failure;
    fn commit(&mut self, credential: &Credential, publication: &()) -> Result<(), Failure> {
        Backend::commit(self, credential, publication)
    }
    fn abort(&mut self, publication: &()) {
        Backend::abort(self, publication);
    }
}
#[test]
fn resident_publication_requires_successful_response_and_discards_only_unpublished_state() {
    for (failure, expected, durable) in [
        (None, vec!["create", "stage", "respond", "commit"], true),
        (Some(Failure::Create), vec!["create"], false),
        (Some(Failure::Stage), vec!["create", "stage"], false),
        (
            Some(Failure::Respond),
            vec!["create", "stage", "respond", "abort"],
            false,
        ),
        (
            Some(Failure::Commit),
            vec!["create", "stage", "respond", "commit", "abort"],
            false,
        ),
        (
            Some(Failure::Uncertain),
            vec!["create", "stage", "respond", "commit", "abort"],
            true,
        ),
    ] {
        let state = Rc::new(RefCell::new(State::default()));
        let result = registration::execute(
            true,
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
        assert!(!state.staged);
    }
}
#[test]
fn nonresident_credentials_never_prepare_or_publish_storage() {
    for failure in [
        None,
        Some(Failure::Stage),
        Some(Failure::Commit),
        Some(Failure::Respond),
    ] {
        let state = Rc::new(RefCell::new(State::default()));
        let result = registration::execute(
            false,
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
        assert!(!state.staged);
    }
}

#[test]
fn deferred_response_releases_request_owner_before_commit_and_preserves_failure_order() {
    for failure in [
        None,
        Some(Failure::Respond),
        Some(Failure::Commit),
        Some(Failure::Uncertain),
    ] {
        let state = Rc::new(RefCell::new(State::default()));
        let mut request = Fixture {
            state: state.clone(),
            failure: None,
        };
        let (output, pending) = registration::prepare(true, &mut request).unwrap();
        assert_eq!(output, 37);
        assert!(state.borrow().staged);
        assert!(!state.borrow().durable);
        drop(request);
        state.borrow_mut().events.push("prepare-response");
        let mut publisher = Fixture {
            state: state.clone(),
            failure,
        };
        let prepared = if failure == Some(Failure::Respond) {
            Err(Failure::Respond)
        } else {
            Ok(output)
        };
        assert_eq!(
            pending.finish(prepared, &mut publisher),
            failure.map_or(Ok(37), Err)
        );
        let state = state.borrow();
        assert_eq!(
            &state.events[..5],
            [
                "create",
                "stage",
                "respond",
                "drop-backend",
                "prepare-response"
            ]
        );
        assert!(!state.staged);
        assert_eq!(
            state.durable,
            failure.is_none() || failure == Some(Failure::Uncertain)
        );
        if failure == Some(Failure::Respond) {
            assert!(!state.events.contains(&"commit"));
        }
        assert_eq!(state.events.contains(&"abort"), failure.is_some());
        assert_eq!(state.events.last(), Some(&"drop-credential"));
    }
}

#[test]
fn cancelling_deferred_work_never_publishes_and_nonresident_never_touches_staging() {
    for resident in [false, true] {
        let state = Rc::new(RefCell::new(State::default()));
        let mut backend = Fixture {
            state: state.clone(),
            failure: None,
        };
        let (_, pending) = registration::prepare(resident, &mut backend).unwrap();
        pending.cancel(&mut backend);
        let state = state.borrow();
        assert!(!state.durable);
        assert!(!state.staged);
        assert_eq!(state.events.contains(&"abort"), resident);
        assert!(!state.events.contains(&"commit"));
    }
}

#[test]
fn publication_can_drop_redundant_credential_before_deferred_work() {
    struct RecordPublisher(Rc<RefCell<State>>);
    impl Publisher<(), ()> for RecordPublisher {
        type Error = Failure;
        fn commit(&mut self, _: &(), _: &()) -> Result<(), Failure> {
            let mut state = self.0.borrow_mut();
            assert!(state.staged);
            state.events.push("record-commit");
            state.durable = true;
            state.staged = false;
            Ok(())
        }
        fn abort(&mut self, _: &()) {
            unreachable!()
        }
    }
    let state = Rc::new(RefCell::new(State::default()));
    let mut backend = Fixture {
        state: state.clone(),
        failure: None,
    };
    let (output, pending) = registration::prepare(true, &mut backend).unwrap();
    let mut slot = pending.map_credential(|_| ());
    let pending = slot.take();
    assert!(!slot.is_resident());
    assert_eq!(state.borrow().events.last(), Some(&"drop-credential"));
    assert!(!state.borrow().durable);
    assert_eq!(
        pending.finish(Ok(output), &mut RecordPublisher(state.clone())),
        Ok(37)
    );
    assert!(state.borrow().durable);
    // A second drain is idle and cannot publish the same stage again.
    assert_eq!(
        slot.take()
            .finish(Ok(output), &mut RecordPublisher(state.clone())),
        Ok(37)
    );
    assert_eq!(
        state
            .borrow()
            .events
            .iter()
            .filter(|event| **event == "record-commit")
            .count(),
        1
    );
    assert_eq!(
        state
            .borrow()
            .events
            .iter()
            .filter(|event| **event == "drop-credential")
            .count(),
        1
    );
}
