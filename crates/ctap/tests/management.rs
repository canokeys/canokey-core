// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::{
    management::{self, Backend, Fields, Request},
    status::Status,
};

#[derive(Default)]
struct Product {
    events: Vec<&'static str>,
    mode: u8,
    fail: Option<&'static str>,
}
impl Product {
    fn step(&mut self, event: &'static str) -> Result<(), Status> {
        self.events.push(event);
        if self.fail == Some(event) {
            Err(Status::PinAuthInvalid)
        } else {
            Ok(())
        }
    }
}
impl Backend for Product {
    type Error = Status;
    type Output = ();
    type Authenticated = ();
    fn reset_cursor(&mut self) {
        self.events.push("reset");
        self.mode = 0x00;
    }
    fn cursor_mode(&self) -> u8 {
        self.mode
    }
    fn continue_live(&mut self) -> Result<(), Status> {
        self.step("live")
    }
    fn authorize(&mut self, deferred: bool) -> Result<(), Status> {
        self.step(if deferred { "preflight" } else { "authorize" })
    }
    fn begin(&mut self) {
        self.events.push("begin");
    }
    fn metadata(&mut self) -> Result<(), Status> {
        self.step("metadata")
    }
    fn rps(&mut self, first: bool) -> Result<(), Status> {
        self.mode = management::RP_NEXT;
        self.step(if first { "first-rp" } else { "next-rp" })
    }
    fn credentials(&mut self, first: bool) -> Result<(), Status> {
        self.mode = management::CREDENTIAL_NEXT;
        self.step(if first {
            "first-credential"
        } else {
            "next-credential"
        })
    }
    fn mutate(&mut self, delete: bool, _: ()) -> Result<(), Status> {
        self.step("read-record")?;
        self.step("record-rp")?;
        self.step(if delete { "delete" } else { "update" })
    }
}
fn request(command: u8) -> Request {
    let mut request = Request::new(command, true, true, &Fields::default());
    request.rp = true;
    request.credential = true;
    request.user = true;
    request
}
#[test]
fn unauthorized_mutations_never_reach_records_and_scope_failure_never_writes() {
    for command in [management::DELETE, management::UPDATE_USER] {
        for failure in [
            Some("preflight"),
            Some("read-record"),
            Some("record-rp"),
            None,
        ] {
            let mut product = Product {
                fail: failure,
                ..Product::default()
            };
            let result = management::execute(request(command), &mut product);
            let mut expected = vec!["reset", "preflight"];
            if failure != Some("preflight") {
                expected.push("read-record");
                if failure != Some("read-record") {
                    expected.push("record-rp");
                    if failure.is_none() {
                        expected.push(if command == management::DELETE {
                            "delete"
                        } else {
                            "update"
                        });
                    }
                }
            }
            assert_eq!(product.events, expected);
            assert_eq!(result.is_ok(), failure.is_none());
            assert_eq!(product.mode, 0x00);
        }
    }
}
#[test]
fn continuation_requires_matching_live_cursor_without_reauthentication() {
    for (begin, next, other) in [
        (
            management::RP_BEGIN,
            management::RP_NEXT,
            management::CREDENTIAL_NEXT,
        ),
        (
            management::CREDENTIAL_BEGIN,
            management::CREDENTIAL_NEXT,
            management::RP_NEXT,
        ),
    ] {
        let mut product = Product::default();
        management::execute(request(begin), &mut product).unwrap();
        assert_eq!(&product.events[..3], ["reset", "authorize", "begin"]);
        product.events.clear();
        let mut continued = request(other);
        continued.authenticated = false;
        continued.protocol = false;
        assert_eq!(
            management::execute(continued, &mut product),
            Err(Status::NotAllowed)
        );
        assert!(product.events.is_empty());
        continued = request(next);
        continued.authenticated = false;
        continued.protocol = false;
        product.fail = Some("live");
        assert_eq!(
            management::execute(continued, &mut product),
            Err(Status::PinAuthInvalid)
        );
        assert_eq!(product.events, ["live"]);
        product.events.clear();
        product.fail = None;
        management::execute(request(next), &mut product).unwrap();
        assert_eq!(product.events[0], "live");
        assert_eq!(product.events.len(), 2);
    }
}
#[test]
fn required_fields_fail_before_authorization_or_record_io() {
    for command in management::METADATA..=management::UPDATE_USER {
        if matches!(command, management::RP_NEXT | management::CREDENTIAL_NEXT) {
            continue;
        }
        for missing in 0..5 {
            let mut request = request(command);
            match missing {
                0 => request.authenticated = false,
                1 => request.protocol = false,
                2 => request.rp = false,
                3 => request.credential = false,
                _ => request.user = false,
            }
            let expected = if missing == 0 {
                Some(Status::PuatRequired)
            } else if missing == 1
                || missing == 2 && command == management::CREDENTIAL_BEGIN
                || missing == 3 && matches!(command, management::DELETE | management::UPDATE_USER)
                || missing == 4 && command == management::UPDATE_USER
            {
                Some(Status::MissingParameter)
            } else {
                None
            };
            let mut product = Product::default();
            let result = management::execute(request, &mut product);
            if let Some(error) = expected {
                assert_eq!(result, Err(error));
                assert_eq!(product.events, ["reset"]);
            } else {
                assert!(result.is_ok());
            }
        }
    }
}
