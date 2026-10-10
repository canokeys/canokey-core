// SPDX-License-Identifier: Apache-2.0
//! Core behavior regressions migrated from the C dispatcher fixture.
use canokey_protocol::response::StatusWord as Sw;
use canokey_test_card::Card;
const RESPONSE_BYTES: usize = 258;
const OWNER_CCID: u8 = 1;
#[cfg(feature = "ctap")]
const OWNER_WEBUSB: u8 = 3;
#[cfg(any(feature = "ctap", feature = "piv", feature = "openpgp"))]
const OWNER_NFC: u8 = 4;
const INS_SELECT: u8 = 0xa4;
#[cfg(any(
    feature = "admin",
    feature = "ndef",
    feature = "ctap",
    feature = "openpgp",
    feature = "piv"
))]
const INS_GET_RESPONSE: u8 = 0xc0;
const SELECT_BY_NAME: u8 = 4;
const ADMIN_AID: &[u8] = &[0xf0, 0, 0, 0, 0];
#[cfg(feature = "oath")]
const OATH_AID: &[u8] = &[0xa0, 0, 0, 5, 0x27, 0x21, 1];
#[cfg(feature = "openpgp")]
const OPENPGP_AID: &[u8] = &[0xd2, 0x76, 0, 1, 0x24, 1];
#[cfg(feature = "piv")]
const PIV_AID: &[u8] = &[0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0];
#[cfg(feature = "ctap")]
const FIDO_AID: &[u8] = &[0xa0, 0, 0, 6, 0x47, 0x2f, 0, 1];
#[cfg(feature = "ndef")]
const NDEF_AID: &[u8] = &[0xd2, 0x76, 0, 0, 0x85, 1, 1];
// Short ISO 7816 GET RESPONSE, Le=0 requests 256 bytes.
#[cfg(any(
    feature = "admin",
    feature = "ndef",
    feature = "ctap",
    feature = "openpgp",
    feature = "piv"
))]
const GET_RESPONSE: &[u8] = &[0, INS_GET_RESPONSE, 0, 0, 0];
struct Fixture {
    card: Card,
    owner: u8,
    buffer: [u8; RESPONSE_BYTES],
}
impl Fixture {
    fn new() -> Self {
        // Every scenario runs serially with exclusive native crypto access.
        let mut card = unsafe { Card::new() };
        assert!(card.install());
        Self {
            card,
            owner: OWNER_CCID,
            buffer: [0; RESPONSE_BYTES],
        }
    }
    fn raw(&mut self, bytes: &[u8], expected: Sw) -> usize {
        let n = self
            .card
            .exchange_owner(self.owner, bytes, &mut self.buffer)
            .unwrap();
        assert!(n >= 2);
        assert_eq!(
            &self.buffer[n - 2..n],
            &expected.bytes(),
            "owner={} request={bytes:02x?}",
            self.owner
        );
        n - 2
    }
    fn command(
        &mut self,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
        le: Option<u8>,
        expected: Sw,
    ) -> usize {
        self.frame(0, ins, p1, p2, data, le, expected)
    }
    fn frame(
        &mut self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
        le: Option<u8>,
        expected: Sw,
    ) -> usize {
        assert!(data.len() <= u8::MAX as usize);
        let mut bytes = vec![cla, ins, p1, p2];
        if !data.is_empty() {
            bytes.push(data.len() as u8);
            bytes.extend_from_slice(data);
        }
        if let Some(le) = le {
            bytes.push(le);
        }
        self.raw(&bytes, expected)
    }
    fn select(&mut self, aid: &[u8], expected: Sw) {
        self.command(INS_SELECT, SELECT_BY_NAME, 0, aid, None, expected);
    }
    #[cfg(any(
        feature = "admin",
        feature = "ctap",
        feature = "openpgp",
        feature = "piv"
    ))]
    fn reset(&mut self) {
        self.card.reset();
    }
}
#[cfg(feature = "admin")]
const INS_VERIFY: u8 = 0x20;
#[cfg(feature = "admin")]
const INS_INFO: u8 = 0x31;
#[cfg(feature = "admin")]
const INS_CONFIG: u8 = 0x40;
#[cfg(all(feature = "admin", feature = "pass"))]
const INS_PASS_CONFIG: u8 = 0x44;
#[cfg(all(feature = "admin", feature = "pass"))]
const INS_PASS_READ: u8 = 0x43;
#[cfg(feature = "admin")]
fn authenticate(f: &mut Fixture) {
    f.command(INS_VERIFY, 0, 0, b"123456", None, Sw::SUCCESS);
}

#[cfg(all(feature = "admin", feature = "pass"))]
fn pass_lifecycle() {
    let mut f = Fixture::new();
    f.select(ADMIN_AID, Sw::SUCCESS);
    authenticate(&mut f);
    f.command(INS_VERIFY, 0, 0, &[], None, Sw::SUCCESS);
    // PASS eject command uses the legacy FF EE FF EE four-byte envelope.
    const EJECT: &[u8] = &[0xff, 0xee, 0xff, 0xee];
    let sample = |f: &mut Fixture, pressed, now, ready| {
        f.card
            .run(|core, p| core.sample_output(pressed, now, ready, p))
    };
    f.raw(EJECT, Sw::SUCCESS);
    assert_eq!(sample(&mut f, false, 100, false), None);
    assert_eq!(sample(&mut f, false, 101, true), Some(3));
    assert_eq!(sample(&mut f, false, 102, true), None);
    f.raw(EJECT, Sw::SUCCESS);
    f.card.run(|core, p| core.cancel_output(false, p));
    assert_eq!(sample(&mut f, false, 103, true), None);
    // PASS slot zero: type 2, length 3, append-CR flag 1.
    f.command(
        INS_PASS_CONFIG,
        1,
        0,
        &[2, 3, b'a', b'b', b'c', 1],
        None,
        Sw::SUCCESS,
    );
    f.select(ADMIN_AID, Sw::SUCCESS);
    f.command(INS_VERIFY, 0, 0, &[], None, Sw::SUCCESS);
    f.command(INS_PASS_READ, 0, 0, &[], None, Sw::SUCCESS);
    assert_eq!(&f.buffer[..3], &[2, 1, 0]);
    assert_eq!(f.card.touch(0, &mut f.buffer), Some(4));
    assert_eq!(&f.buffer[..4], b"abc\r");
    for (pressed, now, ready, expected) in [
        (false, 1501, true, None),
        (true, 2100, true, None),
        (false, 2200, true, Some(b'a')),
        (false, 2201, false, None),
        (false, 2202, true, Some(b'b')),
        (false, 2203, true, Some(b'c')),
        (false, 2204, true, Some(b'\r')),
        (false, 2205, true, None),
    ] {
        assert_eq!(sample(&mut f, pressed, now, ready), expected);
    }
    f.command(INS_PASS_READ, 0, 0, &[], Some(1), Sw::remaining(2));
    assert_eq!(f.buffer[0], 2);
    f.command(INS_GET_RESPONSE, 0, 0, &[], Some(2), Sw::SUCCESS);
    assert_eq!(&f.buffer[..2], &[1, 0]);
    // RFC 2202 HMAC-SHA1: 20 copies of 0x0b and message "Hi There".
    let mut config = vec![3, 20];
    config.extend_from_slice(&[0x0b; 20]);
    f.command(INS_PASS_CONFIG, 2, 0, &config, None, Sw::SUCCESS);
    let mut digest = [0; 20];
    assert!(
        f.card
            .run(|core, p| core.challenge(1, b"Hi There", &mut digest, p))
            .is_ok()
    );
    const RFC2202: [u8; 20] = [
        0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c,
        0x8e, 0xf1, 0x46, 0xbe, 0x00,
    ];
    assert_eq!(digest, RFC2202);
    const CHANGE_PIN: u8 = 0x21;
    f.command(CHANGE_PIN, 0, 0, b"654321", None, Sw::SUCCESS);
    f.command(INS_VERIFY, 0, 0, &[], None, Sw::retries(3));
    f.command(INS_VERIFY, 0, 0, b"654321", None, Sw::SUCCESS);
    f.reset();
    assert!(f.card.install());
    assert_eq!(f.card.touch(0, &mut f.buffer), Some(4));
    assert_eq!(&f.buffer[..4], b"abc\r");
    f.select(ADMIN_AID, Sw::SUCCESS);
    f.command(
        INS_PASS_READ,
        0,
        0,
        &[],
        None,
        Sw::SECURITY_STATUS_NOT_SATISFIED,
    );
    f.command(INS_VERIFY, 0, 0, b"654321", None, Sw::SUCCESS);
    const RESET_PASS: u8 = 0x13;
    f.command(RESET_PASS, 0, 0, &[], None, Sw::SUCCESS);
    assert_eq!(f.card.touch(0, &mut f.buffer), Some(0));
    f.command(
        INS_PASS_CONFIG,
        1,
        0,
        &[2, 3, b'x', b'y', b'z', 0],
        None,
        Sw::SUCCESS,
    );
    for remaining in [2, 1, 0] {
        f.command(
            INS_VERIFY,
            0,
            0,
            b"000000",
            None,
            if remaining == 0 {
                Sw::AUTHENTICATION_BLOCKED
            } else {
                Sw::retries(remaining)
            },
        );
    }
    const FACTORY_RESET: u8 = 0x50;
    f.command(FACTORY_RESET, 0, 0, b"RESET", None, Sw::SUCCESS);
    authenticate(&mut f);
    assert_eq!(f.card.touch(0, &mut f.buffer), Some(0));
}

#[cfg(feature = "admin")]
fn admin_policy() {
    let mut f = Fixture::new();
    f.select(ADMIN_AID, Sw::SUCCESS);
    const INS_TOUCH: u8 = 0x14;
    const INS_CONFIG_READ: u8 = 0x42;
    f.command(
        INS_TOUCH,
        1,
        0,
        &[],
        None,
        Sw::SECURITY_STATUS_NOT_SATISFIED,
    );
    for setting in [6, 1] {
        f.command(
            INS_CONFIG,
            setting,
            0,
            &[],
            None,
            Sw::SECURITY_STATUS_NOT_SATISFIED,
        );
    }
    f.command(INS_CONFIG_READ, 1, 0, &[], Some(6), Sw::WRONG_P1P2);
    f.command(INS_CONFIG_READ, 0, 0, &[], Some(5), Sw::WRONG_LENGTH);
    f.command(INS_CONFIG_READ, 0, 0, &[], Some(6), Sw::SUCCESS);
    assert_eq!(f.buffer[0], 1);
    assert_eq!(f.buffer[1], 0);
    assert_eq!(&f.buffer[3..6], &[1, 1, 0x3f]);
    f.command(INS_TOUCH, 0, 0, &[], Some(1), Sw::SUCCESS);
    assert_eq!(f.buffer[0], 1);
    authenticate(&mut f);
    f.command(INS_CONFIG, 6, 0x80, &[], None, Sw::WRONG_P1P2);
    f.command(INS_CONFIG, 6, 0x3f, &[0], None, Sw::WRONG_LENGTH);
    f.command(INS_CONFIG, 0x7f, 0, &[], None, Sw::WRONG_P1P2);
    for setting in [1, 5, 6, 4] {
        f.command(INS_CONFIG, setting, 0, &[], None, Sw::SUCCESS);
    }
    f.command(INS_TOUCH, 1, 0, &[], None, Sw::SUCCESS);
    f.reset();
    f.select(ADMIN_AID, Sw::SUCCESS);
    f.command(INS_TOUCH, 0, 0, &[], Some(1), Sw::SUCCESS);
    assert_eq!(f.buffer[0], 0);
    f.command(INS_CONFIG_READ, 0, 0, &[], Some(6), Sw::SUCCESS);
    assert_eq!(&f.buffer[3..6], &[0, 0, 0]);
    assert_eq!(f.buffer[0], 0);
    #[cfg(feature = "ndef")]
    f.select(NDEF_AID, Sw::FILE_NOT_FOUND);
    #[cfg(feature = "openpgp")]
    f.select(OPENPGP_AID, Sw::FILE_NOT_FOUND);
    #[cfg(feature = "piv")]
    f.select(&PIV_AID[..5], Sw::FILE_NOT_FOUND);
    #[cfg(feature = "ctap")]
    f.select(FIDO_AID, Sw::FILE_NOT_FOUND);
    f.select(ADMIN_AID, Sw::SUCCESS);
    authenticate(&mut f);
    const SERIAL_READ: u8 = 0x32;
    const SERIAL_WRITE: u8 = 0x30;
    f.command(SERIAL_READ, 0, 0, &[], Some(4), Sw::SUCCESS);
    assert_eq!(&f.buffer[..4], &[0; 4]);
    f.command(
        SERIAL_WRITE,
        0,
        0,
        &[0x12, 0x34, 0x56, 0x78],
        None,
        Sw::SUCCESS,
    );
    f.command(
        SERIAL_WRITE,
        0,
        0,
        &[0xff; 4],
        None,
        Sw::CONDITIONS_NOT_SATISFIED,
    );
    f.command(SERIAL_READ, 0, 0, &[], Some(4), Sw::SUCCESS);
    assert_eq!(&f.buffer[..4], &[0x12, 0x34, 0x56, 0x78]);
    f.command(SERIAL_READ, 0, 0, &[], Some(3), Sw::WRONG_LENGTH);
    const RECOVERY: u8 = 0xff;
    const RECOVERY_COOKIE: &[u8] = b"D3549Fa2dcb$23n";
    f.command(RECOVERY, 0xff, 0, &[0], None, Sw::WRONG_P1P2);
    f.command(RECOVERY, 0xfe, 0, RECOVERY_COOKIE, None, Sw::WRONG_P1P2);
    f.command(RECOVERY, 0xff, 2, RECOVERY_COOKIE, None, Sw::WRONG_P1P2);
    f.command(
        RECOVERY,
        0xff,
        0,
        RECOVERY_COOKIE,
        None,
        Sw::UNABLE_TO_PROCESS,
    );
    f.reset();
    f.select(ADMIN_AID, Sw::SUCCESS);
    f.command(
        RECOVERY,
        0xff,
        0,
        RECOVERY_COOKIE,
        None,
        Sw::SECURITY_STATUS_NOT_SATISFIED,
    );
    const USAGE: u8 = 0x41;
    f.command(USAGE, 0, 0, &[], Some(2), Sw::SUCCESS);
    assert!(f.buffer[0] >= 4);
    assert_eq!(f.buffer[1], 128);
    for (p1, p2, le, sw) in [
        (0, 0, 1, Sw::WRONG_LENGTH),
        (1, 0, 47, Sw::WRONG_LENGTH),
        (2, 0, 48, Sw::WRONG_P1P2),
        (0, 1, 2, Sw::WRONG_P1P2),
    ] {
        f.command(USAGE, p1, p2, &[], Some(le), sw);
    }
    f.command(USAGE, 1, 0, &[], Some(48), Sw::SUCCESS);
    for i in 0..7 {
        assert_eq!(f.buffer[i * 6], (i + 1) as u8);
    }
    assert_eq!(&f.buffer[42..48], &[0, 0, 0, 0, 0x10, 0]);
    for (kind, prefix) in [(0, b"0.0"), (1, b"Can"), (2, b"unk")] {
        assert_eq!(f.command(INS_INFO, kind, 0, &[], Some(3), Sw::SUCCESS), 3);
        assert_eq!(&f.buffer[..3], prefix);
    }
    f.raw(GET_RESPONSE, Sw::COMMAND_NOT_ALLOWED);
    assert_eq!(f.command(INS_INFO, 2, 0, &[], Some(0), Sw::SUCCESS), 7);
    assert_eq!(&f.buffer[..7], b"unknown");
    f.command(INS_INFO, 2, 1, &[], Some(0), Sw::WRONG_P1P2);
    f.command(INS_INFO, 3, 0, &[], Some(4), Sw::WRONG_P1P2);
    f.command(INS_INFO, 0, 0, &[0], None, Sw::WRONG_LENGTH);
    assert_eq!(f.command(SERIAL_READ, 1, 0, &[], Some(13), Sw::SUCCESS), 13);
    assert_eq!(f.command(SERIAL_READ, 1, 0, &[], Some(3), Sw::SUCCESS), 3);
    f.command(SERIAL_READ, 2, 0, &[], Some(4), Sw::WRONG_P1P2);
}

#[cfg(feature = "admin")]
fn keymap() {
    let mut f = Fixture::new();
    f.select(ADMIN_AID, Sw::SUCCESS);
    authenticate(&mut f);
    const WRITE: u8 = 0x45;
    const READ: u8 = 0x46;
    const DELETE: u8 = 0x47;
    const MAP_ID: u8 = 17;
    f.command(READ, 0, 0, &[], Some(1), Sw::REFERENCE_NOT_FOUND);
    f.command(WRITE, 1, MAP_ID, &[], None, Sw::WRONG_P1P2);
    let mut data = [0; 128];
    f.frame(0x10, WRITE, 0, MAP_ID, &data, None, Sw::SUCCESS);
    f.command(WRITE, 0, MAP_ID, &data[..127], None, Sw::WRONG_LENGTH);
    f.frame(0x10, WRITE, 0, MAP_ID, &data, None, Sw::SUCCESS);
    // ASCII A is the second two-byte entry in the second half of the keymap.
    data[2] = 0x40;
    data[3] = 0x1d;
    f.command(WRITE, 0, MAP_ID, &data, None, Sw::SUCCESS);
    f.command(READ, 0, 0, &[], Some(1), Sw::SUCCESS);
    assert_eq!(f.buffer[0], MAP_ID);
    f.command(READ, 0, 0x7f, &[], Some(1), Sw::WRONG_P1P2);
    f.raw(&[0, READ, 0, 1, 1, 0, 0], Sw::WRONG_LENGTH);
    f.command(DELETE, 0, 1, &[], None, Sw::WRONG_P1P2);
    f.command(DELETE, 0, 0, &[0], None, Sw::WRONG_LENGTH);
    f.command(READ, 0, 1, &[], Some(255), Sw::WRONG_LENGTH);
    f.command(READ, 0, 1, &[], Some(0), Sw::SUCCESS);
    for i in 0..256 {
        assert_eq!(
            f.buffer[i],
            if i == 130 {
                0x40
            } else if i == 131 {
                0x1d
            } else {
                0
            }
        );
    }
    #[cfg(feature = "pass")]
    {
        assert_eq!(
            canokey_rust_core::runtime::config::keyboard_usage(&mut f.card.records, b'A').unwrap(),
            (0x40, 0x1d)
        );
        assert!(
            canokey_rust_core::runtime::config::keyboard_usage(&mut f.card.records, b'B').is_none()
        );
    }
    f.reset();
    f.select(ADMIN_AID, Sw::SUCCESS);
    f.command(READ, 0, 0, &[], Some(1), Sw::SECURITY_STATUS_NOT_SATISFIED);
    authenticate(&mut f);
    f.command(READ, 0, 0, &[], Some(1), Sw::SUCCESS);
    assert_eq!(f.buffer[0], MAP_ID);
    f.command(DELETE, 0, 0, &[], None, Sw::SUCCESS);
    f.command(READ, 0, 0, &[], Some(1), Sw::REFERENCE_NOT_FOUND);
    #[cfg(feature = "pass")]
    assert_eq!(
        canokey_rust_core::runtime::config::keyboard_usage(&mut f.card.records, b'A').unwrap(),
        (2, 4)
    );
    const TOUCH: u8 = 0x14;
    f.command(TOUCH, 1, 1, &[], None, Sw::SUCCESS);
    f.command(INS_CONFIG, 6, 0x3f, &[], None, Sw::SUCCESS);
    for setting in [4, 1, 5] {
        f.command(INS_CONFIG, setting, 1, &[], None, Sw::SUCCESS);
    }
}

#[cfg(feature = "ndef")]
fn ndef() {
    let mut f = Fixture::new();
    const READ: u8 = 0xb0;
    const UPDATE: u8 = 0xd6;
    #[cfg(feature = "admin")]
    {
        const READ_ONLY: u8 = 0x08;
        const RESET_NDEF: u8 = 0x07;
        f.select(ADMIN_AID, Sw::SUCCESS);
        for ins in [READ_ONLY, RESET_NDEF] {
            f.command(
                ins,
                u8::from(ins == READ_ONLY),
                0,
                &[],
                None,
                Sw::SECURITY_STATUS_NOT_SATISFIED,
            );
        }
        authenticate(&mut f);
        f.command(READ_ONLY, 2, 0, &[], None, Sw::WRONG_P1P2);
        f.command(READ_ONLY, 1, 0, &[], None, Sw::SUCCESS);
        f.select(NDEF_AID, Sw::SUCCESS);
        f.command(INS_SELECT, 0, 12, &[0, 1], None, Sw::SUCCESS);
        f.command(UPDATE, 0, 0, &[0], None, Sw::SECURITY_STATUS_NOT_SATISFIED);
        f.select(ADMIN_AID, Sw::SUCCESS);
        authenticate(&mut f);
        f.command(RESET_NDEF, 0, 0, &[], None, Sw::SUCCESS);
    }
    f.select(NDEF_AID, Sw::SUCCESS);
    f.command(INS_SELECT, 0, 12, &[0xe1, 3], None, Sw::SUCCESS);
    f.command(READ, 0, 0, &[], Some(15), Sw::SUCCESS);
    // NFC Type 4 CC: length 15, version 2.0, MLe/MLc=1024, file 0001,
    // maximum message 1024 and unrestricted reads/writes.
    const CAPABILITY: &[u8] = &[0, 15, 0x20, 4, 0, 4, 0, 4, 6, 0, 1, 4, 0, 0, 0];
    assert_eq!(&f.buffer[..CAPABILITY.len()], CAPABILITY);
    f.command(INS_SELECT, 0, 12, &[0, 1], None, Sw::SUCCESS);
    f.frame(0x10, UPDATE, 0, 100, &[0xaa, 0xbb], None, Sw::SUCCESS);
    f.command(UPDATE, 0, 100, &[0xcc], None, Sw::SUCCESS);
    f.command(READ, 0, 100, &[], Some(3), Sw::SUCCESS);
    assert_eq!(&f.buffer[..3], &[0xaa, 0xbb, 0xcc]);
    // Extended Le=1024; response is drained through four short chunks.
    f.raw(&[0, READ, 0, 0, 0, 4, 0], Sw::remaining(768));
    for remaining in [512, 256, 0] {
        f.raw(
            GET_RESPONSE,
            if remaining == 0 {
                Sw::SUCCESS
            } else {
                Sw::remaining(remaining)
            },
        );
    }
}

#[cfg(feature = "ctap")]
fn ctap_sessions() {
    let mut f = Fixture::new();
    const U2F_VERSION: u8 = 3;
    for owner in [OWNER_CCID, OWNER_WEBUSB, OWNER_NFC] {
        f.owner = owner;
        f.reset();
        f.command(U2F_VERSION, 0, 0, &[], Some(6), Sw::FILE_NOT_FOUND);
        f.select(FIDO_AID, Sw::SUCCESS);
        f.command(U2F_VERSION, 0, 0, &[], Some(6), Sw::SUCCESS);
        assert_eq!(&f.buffer[..6], b"U2F_V2");
    }
    f.owner = OWNER_CCID;
    f.reset();
    f.command(0x11, 0, 0, &[], None, Sw::FILE_NOT_FOUND);
    f.command(INS_SELECT, SELECT_BY_NAME, 1, &[0], None, Sw::WRONG_P1P2);
    #[cfg(feature = "admin")]
    {
        f.select(ADMIN_AID, Sw::SUCCESS);
        f.frame(0x80, 0x10, 0, 0, &[4], None, Sw::CLA_NOT_SUPPORTED);
        authenticate(&mut f);
        f.command(INS_CONFIG, 6, 0x1f, &[], None, Sw::SUCCESS);
        f.reset();
        f.command(U2F_VERSION, 0, 0, &[], Some(6), Sw::FILE_NOT_FOUND);
        f.select(ADMIN_AID, Sw::SUCCESS);
        authenticate(&mut f);
        f.command(INS_CONFIG, 6, 0x3f, &[], None, Sw::SUCCESS);
    }
    f.reset();
    f.owner = OWNER_NFC;
    f.select(FIDO_AID, Sw::SUCCESS);
    // NFC extended CTAP GetInfo: CLA 80, INS 10, extended Lc=1, command 04.
    const GET_INFO: &[u8] = &[0x80, 0x10, 0, 0, 0, 0, 1, 4];
    let n = f
        .card
        .exchange_owner(f.owner, GET_INFO, &mut f.buffer)
        .unwrap();
    assert_eq!(n, RESPONSE_BYTES);
    assert_eq!(f.buffer[256], 0x61);
    assert_eq!(f.buffer[0], 0);
    assert_eq!(f.buffer[1] & 0xe0, 0xa0);
    let mut total = 256;
    let mut complete = false;
    for _ in 0..8 {
        let n = f
            .card
            .exchange_owner(f.owner, GET_RESPONSE, &mut f.buffer)
            .unwrap();
        assert!(n >= 2);
        total += n - 2;
        if f.buffer[n - 2] == 0x90 {
            assert_eq!(f.buffer[n - 1], 0);
            complete = true;
            break;
        }
        assert_eq!(f.buffer[n - 2], 0x61);
    }
    assert!(complete && total > 256);
}

#[cfg(feature = "admin")]
fn selection() {
    let mut f = Fixture::new();
    f.select(ADMIN_AID, Sw::SUCCESS);
    let mut invalid = ADMIN_AID.to_vec();
    invalid.push(0);
    f.select(&invalid, Sw::FILE_NOT_FOUND);
    #[cfg(feature = "piv")]
    {
        f.select(PIV_AID, Sw::SUCCESS);
        let mut aid = PIV_AID.to_vec();
        aid.extend_from_slice(&[1, 0]);
        f.select(&aid, Sw::SUCCESS);
        f.select(&PIV_AID[..5], Sw::SUCCESS);
        for len in 6..=8 {
            f.select(&PIV_AID[..len], Sw::FILE_NOT_FOUND);
        }
        aid.pop();
        f.select(&aid, Sw::FILE_NOT_FOUND);
        aid.push(1);
        f.select(&aid, Sw::FILE_NOT_FOUND);
    }
    f.select(ADMIN_AID, Sw::SUCCESS);
    f.frame(0x80, INS_INFO, 0, 0, &[], Some(0), Sw::CLA_NOT_SUPPORTED);
    f.command(INS_INFO, 0, 0, &[0xff], None, Sw::WRONG_LENGTH);
    f.command(
        INS_SELECT,
        SELECT_BY_NAME,
        12,
        &[0xff],
        None,
        Sw::WRONG_P1P2,
    );
    #[cfg(feature = "oath")]
    {
        f.select(OATH_AID, Sw::SUCCESS);
        f.frame(0xfe, 0xa1, 0, 0, &[], Some(0), Sw::CLA_NOT_SUPPORTED);
    }
}

#[cfg(any(feature = "openpgp", feature = "piv"))]
fn replace_response(f: &mut Fixture, aid: &[u8]) {
    #[cfg(feature = "admin")]
    {
        let _ = aid;
        f.select(ADMIN_AID, Sw::SUCCESS);
        f.command(INS_INFO, 0, 0, &[], Some(0), Sw::SUCCESS);
    }
    #[cfg(not(feature = "admin"))]
    f.select(aid, Sw::SUCCESS);
}

#[cfg(any(feature = "openpgp", feature = "piv"))]
fn response_cleanup() {
    let mut f = Fixture::new();
    for owner in [OWNER_CCID, OWNER_NFC] {
        for capacity in [2, 3] {
            for reset in [false, true] {
                f.owner = owner;
                f.reset();
                #[cfg(feature = "piv")]
                {
                    f.select(PIV_AID, Sw::SUCCESS);
                    let mut output = vec![0; capacity];
                    assert_eq!(
                        f.card.exchange_owner(owner, &[0, 0xfd, 0, 0], &mut output),
                        Some(capacity)
                    );
                    assert_eq!(output[capacity - 2], 0x61);
                    assert_eq!(output[capacity - 1], (5 - capacity) as u8);
                    if reset {
                        f.reset();
                    } else {
                        replace_response(&mut f, PIV_AID);
                    }
                    f.raw(GET_RESPONSE, Sw::COMMAND_NOT_ALLOWED);
                }
                #[cfg(feature = "openpgp")]
                {
                    use canokey_ports::{Record, Storage};
                    let payload = (0..600).map(|i| (i * 7 + 1) as u8).collect::<Vec<_>>();
                    f.card
                        .records
                        .replace(Record::PgpCertSig, &payload)
                        .unwrap();
                    f.reset();
                    f.select(OPENPGP_AID, Sw::SUCCESS);
                    let mut output = vec![0; capacity];
                    assert_eq!(
                        f.card
                            .exchange_owner(owner, &[0, 0xca, 0x7f, 0x21, 0], &mut output),
                        Some(capacity)
                    );
                    assert_eq!(output[capacity - 2], 0x61);
                    if reset {
                        f.reset();
                    } else {
                        replace_response(&mut f, OPENPGP_AID);
                    }
                    f.raw(GET_RESPONSE, Sw::COMMAND_NOT_ALLOWED);
                }
            }
        }
    }
}
fn main() {
    let mut f = Fixture::new();
    let expected = [
        cfg!(feature = "admin"),
        cfg!(feature = "oath"),
        cfg!(feature = "openpgp"),
        cfg!(feature = "piv"),
        cfg!(feature = "ctap"),
        cfg!(feature = "ndef"),
    ]
    .into_iter()
    .filter(|&v| v)
    .count();
    assert_eq!(canokey_rust_core::Core::applet_count() as usize, expected);
    f.select(
        ADMIN_AID,
        if cfg!(feature = "admin") {
            Sw::SUCCESS
        } else {
            Sw::FILE_NOT_FOUND
        },
    );
    #[cfg(all(feature = "admin", feature = "pass"))]
    pass_lifecycle();
    #[cfg(feature = "admin")]
    {
        admin_policy();
        keymap();
        selection();
    }
    #[cfg(feature = "ndef")]
    ndef();
    #[cfg(feature = "ctap")]
    ctap_sessions();
    #[cfg(any(feature = "openpgp", feature = "piv"))]
    response_cleanup();
    println!("Rust core behavior regressions passed");
}
