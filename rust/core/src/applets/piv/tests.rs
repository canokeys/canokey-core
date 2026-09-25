// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::ports::*;

#[derive(Default)]
struct Store {
    bytes: Option<[u8; STATE_LEN]>,
    fail: bool,
    commit_on_error: bool,
    writes: usize,
}
impl Storage for Store {
    fn load(&mut self, _: Record, out: &mut [u8]) -> Result<usize, StorageError> {
        out.copy_from_slice(self.bytes.as_ref().ok_or(StorageError::Missing)?);
        Ok(STATE_LEN)
    }
    fn replace(&mut self, _: Record, input: &[u8]) -> Result<(), StorageError> {
        self.writes += 1;
        if !self.fail || self.commit_on_error {
            self.bytes = Some(input.try_into().unwrap());
        }
        if self.fail {
            Err(StorageError::Uncertain)
        } else {
            Ok(())
        }
    }
}
struct CryptoBackend;
impl Crypto for CryptoBackend {
    fn mac(&mut self, _: u8, _: &[u8], _: &[u8], _: &mut [u8; 64]) -> Result<(), CryptoError> {
        unreachable!()
    }
    fn random(&mut self, _: &mut [u8]) -> Result<(), CryptoError> {
        unreachable!()
    }
    fn hmac_sha1(&mut self, _: &[u8; 20], _: &[u8], _: &mut [u8; 20]) {
        unreachable!()
    }
}
struct DeviceBackend;
impl Device for DeviceBackend {
    fn serial(&mut self, _: &mut [u8; 4]) {
        unreachable!()
    }
    fn now(&mut self) -> u32 {
        0
    }
    fn touched(&mut self) -> bool {
        false
    }
    fn progress(&mut self) -> bool {
        true
    }
    fn led(&mut self, _: bool) {}
}
struct MemoryBackend;
impl Memory for MemoryBackend {
    fn wipe(&self, bytes: &mut [u8]) {
        bytes.fill(0);
    }
}

macro_rules! platform {
    ($store:expr) => {
        Platform {
            storage: $store,
            crypto: &mut CryptoBackend,
            device: &mut DeviceBackend,
            memory: &MemoryBackend,
        }
    };
}
fn command(piv: &mut Pins, store: &mut Store, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Sw {
    let h = Header {
        cla: 0,
        ins,
        p1,
        p2,
    };
    let mut p = platform!(store);
    match ins {
        0x20 => piv.verify(h, data, &mut p),
        0x24 => piv.change(h, data, &mut p),
        0x2c => piv.reset_retry(h, data, &mut p),
        _ => Err(Sw::INS_NOT_SUPPORTED),
    }
    .map(|_| Sw::SUCCESS)
    .unwrap_or_else(|sw| sw)
}
fn installed() -> (Pins, Store) {
    let mut piv = Pins::new();
    let mut store = Store::default();
    piv.install(&mut platform!(&mut store)).unwrap();
    (piv, store)
}
#[test]
fn verify_status_retries_logout_and_restart() {
    let (mut piv, mut store) = installed();
    assert_eq!(
        command(&mut piv, &mut store, 0x20, 0, 0x80, &[]),
        Sw::new(0x63c3).unwrap()
    );
    assert_eq!(
        command(&mut piv, &mut store, 0x20, 0, 0x80, b"00000000"),
        Sw::new(0x63c2).unwrap()
    );
    assert_eq!(
        command(&mut piv, &mut store, 0x20, 0, 0x80, PIN),
        Sw::SUCCESS
    );
    assert_eq!(piv.state.pin_tries, 3);
    assert_eq!(&store.bytes.unwrap()[3..5], &[3; 2]);
    let writes = store.writes;
    assert_eq!(
        command(&mut piv, &mut store, 0x20, 0, 0x80, &[]),
        Sw::SUCCESS
    );
    assert_eq!(
        command(&mut piv, &mut store, 0x20, 0xff, 0x80, &[]),
        Sw::SUCCESS
    );
    assert_eq!(store.writes, writes);
    assert_eq!(
        command(&mut piv, &mut store, 0x20, 0, 0x80, &[]),
        Sw::new(0x63c3).unwrap()
    );
    // Authorization is session-only and must not survive reinstallation.
    piv.install(&mut platform!(&mut store)).unwrap();
    assert!(!piv.state.pin_ok);
}
#[test]
fn failed_verify_revokes_session_and_block_survives_restart() {
    let (mut piv, mut store) = installed();
    assert_eq!(
        command(&mut piv, &mut store, 0x20, 0, 0x80, PIN),
        Sw::SUCCESS
    );
    for sw in [
        Sw::new(0x63c2).unwrap(),
        Sw::new(0x63c1).unwrap(),
        Sw::AUTHENTICATION_BLOCKED,
    ] {
        assert_eq!(
            command(&mut piv, &mut store, 0x20, 0, 0x80, b"00000000"),
            sw
        );
        assert!(!piv.state.pin_ok);
    }
    piv.install(&mut platform!(&mut store)).unwrap();
    assert_eq!(
        command(&mut piv, &mut store, 0x20, 0, 0x80, PIN),
        Sw::AUTHENTICATION_BLOCKED
    );
    assert_eq!(
        command(&mut piv, &mut store, 0x20, 0, 0x80, &[]),
        Sw::new(0x63c0).unwrap()
    );
}
#[test]
fn change_pin_and_puk_then_unblock_with_new_pin() {
    let (mut piv, mut store) = installed();
    assert_eq!(
        command(
            &mut piv,
            &mut store,
            0x24,
            0,
            0x80,
            b"123456\xff\xff654321\xff\xff"
        ),
        Sw::SUCCESS
    );
    assert!(!piv.state.pin_ok);
    assert_eq!(
        command(&mut piv, &mut store, 0x24, 0, 0x81, b"1234567887654321"),
        Sw::SUCCESS
    );
    for _ in 0..3 {
        command(&mut piv, &mut store, 0x20, 0, 0x80, PIN);
    }
    assert_eq!(
        command(
            &mut piv,
            &mut store,
            0x2c,
            0,
            0x80,
            b"12345678111111\xff\xff"
        ),
        Sw::new(0x63c2).unwrap()
    );
    assert_eq!(
        command(
            &mut piv,
            &mut store,
            0x2c,
            0,
            0x80,
            b"87654321111111\xff\xff"
        ),
        Sw::SUCCESS
    );
    assert_eq!(piv.state.puk_tries, 3);
    assert!(!piv.state.pin_ok);
    piv.install(&mut platform!(&mut store)).unwrap();
    assert_eq!(
        command(&mut piv, &mut store, 0x20, 0, 0x80, b"111111\xff\xff"),
        Sw::SUCCESS
    );
}
#[test]
fn malformed_commands_do_not_consume_retries() {
    let (mut piv, mut store) = installed();
    let writes = store.writes;
    for (ins, p1, p2, data, sw) in [
        (0x20, 0xff, 0x80, &PIN[..], Sw::WRONG_LENGTH),
        (0x20, 0, 0x81, &[][..], Sw::REFERENCE_NOT_FOUND),
        (0x24, 1, 0x80, &[][..], Sw::WRONG_P1P2),
        (0x24, 0, 0x82, &[][..], Sw::REFERENCE_NOT_FOUND),
        (0x2c, 0, 0x80, &PUK[..], Sw::WRONG_LENGTH),
    ] {
        assert_eq!(command(&mut piv, &mut store, ins, p1, p2, data), sw);
    }
    assert_eq!(writes, store.writes);
}
#[test]
fn uncertain_storage_never_authorizes_or_uses_cached_credentials() {
    for commit_on_error in [false, true] {
        let (mut piv, mut store) = installed();
        command(&mut piv, &mut store, 0x20, 0, 0x80, b"00000000");
        store.fail = true;
        store.commit_on_error = commit_on_error;
        assert_eq!(
            command(&mut piv, &mut store, 0x20, 0, 0x80, PIN),
            Sw::UNABLE_TO_PROCESS
        );
        assert!(!piv.state.pin_ok);
        store.fail = false;
        assert_eq!(
            command(&mut piv, &mut store, 0x20, 0, 0x80, PIN),
            Sw::UNABLE_TO_PROCESS
        );
        piv.install(&mut platform!(&mut store)).unwrap();
        assert_eq!(piv.state.pin_tries, if commit_on_error { 3 } else { 2 });
        assert_eq!(
            command(&mut piv, &mut store, 0x20, 0, 0x80, PIN),
            Sw::SUCCESS
        );
    }
}

#[test]
fn wrong_change_consumes_retries_and_blocked_puk_cannot_reset_pin() {
    let (mut piv, mut store) = installed();
    for reference in [0x80, 0x81] {
        for sw in [
            Sw::new(0x63c2).unwrap(),
            Sw::new(0x63c1).unwrap(),
            Sw::AUTHENTICATION_BLOCKED,
        ] {
            assert_eq!(
                command(
                    &mut piv,
                    &mut store,
                    0x24,
                    0,
                    reference,
                    b"0000000099999999"
                ),
                sw
            );
        }
    }
    piv.install(&mut platform!(&mut store)).unwrap();
    assert_eq!(
        command(&mut piv, &mut store, 0x2c, 0, 0x80, b"1234567811111111"),
        Sw::AUTHENTICATION_BLOCKED
    );
}

#[test]
fn uncertain_pin_change_requires_reload_of_actual_committed_value() {
    for commit_on_error in [false, true] {
        let (mut piv, mut store) = installed();
        store.fail = true;
        store.commit_on_error = commit_on_error;
        assert_eq!(
            command(
                &mut piv,
                &mut store,
                0x24,
                0,
                0x80,
                b"123456\xff\xff99999999"
            ),
            Sw::UNABLE_TO_PROCESS
        );
        assert!(!piv.state.pin_ok);
        piv.reset();
        assert_eq!(
            command(&mut piv, &mut store, 0x20, 0, 0x80, b"99999999"),
            Sw::UNABLE_TO_PROCESS
        );
        store.fail = false;
        piv.install(&mut platform!(&mut store)).unwrap();
        let expected = if commit_on_error { b"99999999" } else { PIN };
        assert_eq!(
            command(&mut piv, &mut store, 0x20, 0, 0x80, expected),
            Sw::SUCCESS
        );
    }
}
