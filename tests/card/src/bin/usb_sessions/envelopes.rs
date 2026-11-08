// SPDX-License-Identifier: Apache-2.0
//! Real applets behind USB EP0 and NFC Link/Request. NFC hardware/WTX and
//! aggregation are covered by the separate ffi facade and RF acceptance.
use super::*;
use canokey_protocol::{apdu, nfc as wire};
use canokey_rust_core::runtime::{
    engine::Reply,
    nfc::{
        Event, Link,
        request::{Backend, Rejection, Request},
    },
};
use canokey_rust_ffi::composition::Staging;
use canokey_test_card::transport::Scratch;

const SELECT_OPENPGP: &[u8] = b"\x00\xa4\x04\x00\x06\xd2\x76\x00\x01\x24\x01";
const VERIFY_PW3: &[u8] = b"\x00\x20\x00\x83\x0812345678";
const READ_CERT: &[u8] = &[0, 0xca, 0x7f, 0x21, 0];

fn extended(header: [u8; 4], body: &[u8], le: Option<u16>) -> Vec<u8> {
    let mut bytes = header.to_vec();
    bytes.push(0);
    bytes.extend_from_slice(&(body.len() as u16).to_be_bytes());
    bytes.extend_from_slice(body);
    if let Some(le) = le {
        bytes.extend_from_slice(&le.to_be_bytes());
    }
    bytes
}

// Non-FIDO admission uses the actual Runtime check. These cases must never
// acquire the accelerator, including rejected Lc280/281 envelopes that fit288.
struct Stage {
    fido: bool,
}
impl Backend for Stage {
    fn prepare(&mut self, prefix: &[u8; 7]) -> Result<(), Rejection> {
        let limit = unsafe { core::with_core::<Fake, _>(|core, p| core.prepare_nfc(prefix, p)) }
            .map_err(Rejection::Status)?;
        assert!(self.fido, "non-FIDO request admitted to PKE");
        let length = usize::from(u16::from_be_bytes([prefix[5], prefix[6]]));
        if length > limit as usize {
            return Err(Rejection::TooLarge);
        }
        assert!(Scratch::acquire(4));
        Ok(())
    }
    fn write(&mut self, offset: usize, bytes: &[u8]) -> bool {
        assert!(self.fido);
        Scratch::write(offset, bytes)
    }
    fn read(&mut self, offset: usize, out: &mut [u8]) -> bool {
        assert!(self.fido);
        Scratch::read(offset, out)
    }
    fn close(&mut self) {
        assert!(self.fido);
        assert!(Scratch::clear());
        assert!(Scratch::release(4));
    }
}

fn nfc(bytes: &[u8]) -> Vec<u8> {
    nfc_receive(bytes, false)
}
fn nfc_receive(bytes: &[u8], fido: bool) -> Vec<u8> {
    let mut link = Link::new();
    let mut request = Request::new();
    let mut inline = [0; apdu::SHORT_FRAME_BYTES];
    let mut stage = Stage { fido };
    const INF_BYTES: usize = 13;
    for (index, body) in bytes.chunks(INF_BYTES).enumerate() {
        let last = (index + 1) * INF_BYTES >= bytes.len();
        let mut frame = vec![
            wire::PCB_I
                | (index as u8 & wire::PCB_NUMBER)
                | if last { 0 } else { wire::PCB_CHAIN_OR_NAK },
        ];
        frame.extend_from_slice(body);
        frame.extend_from_slice(&[0; 2]); // FM11NT has checked these CRC bytes.
        let event = link
            .receive_with(&frame, |offset, bytes| {
                assert_eq!(offset, request.len());
                request.append(bytes, &mut inline, &mut stage);
                Ok(())
            })
            .unwrap();
        if last {
            assert!(matches!(event, Event::Execute(n) if n == bytes.len()));
        } else {
            assert!(matches!(event, Event::Send(_)));
            link.receive_with(&frame, |_, _| panic!("duplicate delivery"))
                .unwrap();
        }
    }
    let result = request.finish(&mut stage);
    let malformed = request.is_malformed();
    let reply = unsafe {
        core::with_core::<Fake, _>(|core, p| {
            let mut error = match result {
                Ok(()) => core.begin_frame(4, request.len(), p).err(),
                Err(Rejection::Status(sw)) => Some(sw),
                Err(Rejection::TooLarge) => {
                    request.reset(&mut stage);
                    return vec![0x39, 0x90, 0];
                }
            };
            let mut offset = 0;
            let mut window = [0; 64];
            while offset < request.len() && error.is_none() {
                let n = window.len().min(request.len() - offset);
                assert!(request.read(offset, &mut window[..n], &inline, &mut stage));
                error = core.feed_frame(&window[..n], p).err();
                offset += n;
            }
            request.reset(&mut stage);
            window.fill(0);
            clean_scratch(); // Parsing must release PKE before execution.
            let reply = if let Some(sw) = error {
                if result.is_ok() || malformed {
                    core.abort_request(4, p);
                }
                Reply::Status(sw)
            } else {
                core.end_frame(p)
            };
            let mut output = [0; 258];
            let n = core.transmit(reply, &mut output, p).unwrap();
            output[..n].to_vec()
        })
    };
    clean_scratch();
    reply
}

fn collect(mut reply: Vec<u8>, mut exchange: impl FnMut(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let mut output = Vec::new();
    loop {
        output.extend_from_slice(&reply[..reply.len() - 2]);
        if reply[reply.len() - 2] != 0x61 {
            sw(&reply, 0x9000);
            return output;
        }
        assert!(output.len() < 1152);
        reply = exchange(REST);
    }
}
fn web(bytes: &[u8]) -> Vec<u8> {
    web_send(bytes);
    assert!(!hw(|h| h.halted[1]));
    setup(0xc1, 1, 0, 1, APDU_RESPONSE_BYTES as u16);
    read_control()
}

#[cfg(feature = "ctap")]
pub(super) fn capacity(cid: u32) {
    // clientPIN getPinRetries with an ignored byte string. Include the command
    // byte in each logical size; APDU headers and Le are outside that budget.
    fn request(length: usize) -> Vec<u8> {
        let mut body = vec![6, 0xa2, 2, 1, 0x18, 99, 0x59];
        body.extend_from_slice(&((length - 9) as u16).to_be_bytes());
        body.resize(length, 0x5a);
        body
    }
    const RETRIES: &[u8] = &[0, 0xa1, 3, 8];
    const SIZES: [usize; 6] = [1023, 1024, 1025, 1295, 1296, 1297];
    unsafe { core::reset::<Fake>() };
    for length in SIZES {
        let body = request(length);
        if length <= hid_wire::CTAP_MAX_REQUEST {
            hid_send(cid, hid_wire::CBOR, &body);
            assert_eq!(hid_read(cid, hid_wire::CBOR), RETRIES);
        } else {
            let mut report = hid_packet(cid, hid_wire::CBOR, length);
            report[7] = 6;
            assert_eq!(out(usb_wire::EP_HID, &report), 0);
            hid_poll();
            assert_eq!(hid_read(cid, hid_wire::ERROR), [0x03]);
        }
        clean_scratch();
    }
    hid_send(cid, hid_wire::CBOR, &[6, 0xa1, 2, 1]);
    assert_eq!(hid_read(cid, hid_wire::CBOR), RETRIES);

    for webusb in [false, true] {
        unsafe { core::reset::<Fake>() };
        let exchange = |bytes: &[u8]| {
            if webusb {
                web(bytes)
            } else {
                ccid_send(ccid_wire::TRANSFER, bytes);
                ccid_read()[ccid_wire::HEADER..].to_vec()
            }
        };
        sw(&exchange(SELECT_FIDO), 0x9000);
        for length in SIZES {
            let body = request(length);
            for (index, part) in body.chunks(255).enumerate() {
                let last = (index + 1) * 255 >= body.len();
                let mut apdu = vec![if last { 0x80 } else { 0x90 }, 0x10, 0, 0, part.len() as u8];
                apdu.extend_from_slice(part);
                let reply = exchange(&apdu);
                if last && length > hid_wire::CTAP_MAX_REQUEST {
                    sw(&reply, 0x6700);
                } else if last {
                    assert_eq!(&reply[..reply.len() - 2], RETRIES);
                    sw(&reply, 0x9000);
                } else {
                    assert_eq!(reply, [0x90, 0]);
                }
            }
            assert_eq!(
                exchange(&[0x80, 0x10, 0, 0, 4, 6, 0xa1, 2, 1]),
                [0, 0xa1, 3, 8, 0x90, 0]
            );
            clean_scratch();
        }
    }
    unsafe { core::reset::<Fake>() };
    sw(
        &nfc(b"\x00\xa4\x04\x00\x08\xa0\x00\x00\x06\x47\x2f\x00\x01"),
        0x9000,
    );
    for length in SIZES {
        for le in [None, Some(0)] {
            let reply = nfc_receive(&extended([0x80, 0x10, 0, 0], &request(length), le), true);
            assert_eq!(
                reply,
                if length <= hid_wire::CTAP_MAX_REQUEST {
                    vec![0, 0xa1, 3, 8, 0x90, 0]
                } else {
                    vec![0x39, 0x90, 0]
                }
            );
            clean_scratch();
        }
    }
    // At maximum size the key-agreement command invokes native crypto after
    // the Link/Request path has drained, wiped and released its body lease.
    let mut agreement = vec![6, 0xa3, 1, 1, 2, 2, 0x18, 99, 0x59];
    agreement.extend_from_slice(&((hid_wire::CTAP_MAX_REQUEST - 11) as u16).to_be_bytes());
    agreement.resize(hid_wire::CTAP_MAX_REQUEST, 0x5a);
    let reply = nfc_receive(&extended([0x80, 0x10, 0, 0], &agreement, None), true);
    assert_eq!(reply[0], 0);
    sw(&reply, 0x9000);
    clean_scratch();
}

pub(super) fn run() {
    #[cfg(feature = "openpgp")]
    {
        unsafe { core::reset::<Fake>() };
        sw(&nfc(SELECT_OPENPGP), 0x9000);
        sw(&nfc(VERIFY_PW3), 0x9000);
        // Retain the old extended OpenPGP key vectors on an admitted transport.
        // Fresh default RSA-2048 produces271 public bytes, crossing short Le.
        sw(&nfc(&[0, 0xe6, 0, 0]), 0x9000);
        sw(&nfc(&[0, 0x44, 0, 0]), 0x9000);
        sw(&nfc(SELECT_OPENPGP), 0x9000);
        sw(&nfc(VERIFY_PW3), 0x9000);
        let public = extended([0, 0x47, 0x81, 0], &[0xb6, 0], Some(271));
        sw(&nfc(&public), 0x6a88);
        let generated = collect(
            nfc(&extended([0, 0x47, 0x80, 0], &[0xb6, 0], Some(271))),
            nfc,
        );
        assert_eq!(generated.len(), 271);
        assert_eq!(collect(nfc(&public), nfc), generated);
        for length in [1, 254, 255, 279] {
            for le in [None, Some(0)] {
                let body = vec![length as u8; length];
                let command = extended([0, 0xda, 0x7f, 0x21], &body, le);
                sw(&nfc(&command), 0x9000);
                assert_eq!(collect(nfc(READ_CERT), nfc), body);
            }
        }
        for length in [280, 281, 282] {
            for le in [None, Some(0)] {
                sw(
                    &nfc(&extended([0, 0xda, 0x7f, 0x21], &vec![0xa5; length], le)),
                    0x6700,
                );
                assert_eq!(collect(nfc(READ_CERT), nfc), vec![279u16 as u8; 279]);
            }
        }
        for le in [1u16, 256, 0] {
            let mut command = vec![0, 0xca, 0x7f, 0x21, 0];
            command.extend_from_slice(&le.to_be_bytes());
            assert_eq!(collect(nfc(&command), nfc), vec![279u16 as u8; 279]);
        }
        unsafe { core::reset::<Fake>() };
        sw(&web(SELECT_OPENPGP), 0x9000);
        sw(&web(VERIFY_PW3), 0x9000);
        for (length, le) in [(280, None), (281, None), (279, Some(0))] {
            let body = vec![length as u8; length];
            let bytes = extended([0, 0xda, 0x7f, 0x21], &body, le);
            assert!(bytes.len() <= 288);
            sw(&web(&bytes), 0x9000);
            assert_eq!(collect(web(READ_CERT), web), body);
        }
        setup(0x41, 0, 0, 1, 289);
        assert!(hw(|h| h.halted[1]));
        // Structural error drains the full admitted EP0 request and recovers.
        let mut malformed = extended([0, 0xda, 0x7f, 0x21], &[0xa5; 279], Some(0));
        malformed[6] -= 1;
        sw(&web(&malformed), 0x6700);
        assert_eq!(collect(web(READ_CERT), web), vec![279u16 as u8; 279]);
    }
    #[cfg(feature = "ctap")]
    {
        unsafe { core::reset::<Fake>() };
        sw(
            &nfc(b"\x00\xa4\x04\x00\x08\xa0\x00\x00\x06\x47\x2f\x00\x01"),
            0x9000,
        );
        for instruction in [0, 4, 0xff] {
            for suffix in [&[0][..], &[0, 0, 0][..], &[0, 0, 1, b'x', 0, 0][..]] {
                let mut bytes = vec![0, instruction, 0, 0];
                bytes.extend_from_slice(suffix);
                sw(&nfc(&bytes), 0x6d00);
            }
        }
    }
    #[cfg(feature = "piv")]
    {
        unsafe { core::reset::<Fake>() };
        const SELECT_PIV: &[u8] = b"\x00\xa4\x04\x00\x09\xa0\x00\x00\x03\x08\x00\x00\x10\x00";
        sw(&nfc(SELECT_PIV), 0x9000);
        for length in [1, 254, 255, 279] {
            for le in [None, Some(0)] {
                sw(
                    &nfc(&extended([0, 0xfd, 0, 0], &vec![0; length], le)),
                    0x6700,
                );
            }
        }
        for le in [1u16, 256, 0] {
            let mut command = vec![0, 0xfd, 0, 0, 0];
            command.extend_from_slice(&le.to_be_bytes());
            sw(&nfc(&command), 0x6700);
        }
        assert_eq!(nfc(&[0, 0xfd, 0, 0]), [0x61, 3]);
        let version = nfc(&[0, 0xc0, 0, 0, 0]);
        sw(&version, 0x9000);
        assert_eq!(version.len(), 5);
        assert_eq!(nfc(&[0, 0x84, 0, 0]), [0x67, 0]);
    }
    #[cfg(feature = "ndef")]
    {
        unsafe { core::reset::<Fake>() };
        const SELECT_NDEF: &[u8] = b"\x00\xa4\x04\x00\x07\xd2\x76\x00\x00\x85\x01\x01";
        const SELECT_FILE: &[u8] = &[0, 0xa4, 0, 12, 2, 0, 1];
        fn read(length: u16) -> Vec<u8> {
            let mut bytes = vec![0, 0xb0, 0, 0, 0];
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes
        }
        sw(&nfc(SELECT_NDEF), 0x9000);
        sw(&nfc(SELECT_FILE), 0x9000);
        for length in [1, 254, 255, 279] {
            for le in [None, Some(0)] {
                let body = vec![length as u8; length];
                sw(&nfc(&extended([0, 0xd6, 0, 0], &body, le)), 0x9000);
                assert_eq!(collect(nfc(&read(length as u16)), nfc), body);
            }
        }
        for length in [280, 281, 282] {
            for le in [None, Some(0)] {
                sw(
                    &nfc(&extended([0, 0xd6, 0, 0], &vec![0xa5; length], le)),
                    0x6700,
                );
                assert_eq!(collect(nfc(&read(279)), nfc), vec![279u16 as u8; 279]);
            }
        }
        assert_eq!(collect(nfc(&read(1)), nfc), [279u16 as u8]);
        assert_eq!(collect(nfc(&read(256)), nfc), vec![279u16 as u8; 256]);
        sw(&nfc(&read(0)), 0x6700); // Le65536 exceeds the1024-byte NDEF file.
        unsafe { core::reset::<Fake>() };
        sw(&web(SELECT_NDEF), 0x9000);
        sw(&web(SELECT_FILE), 0x9000);
        let body = vec![0x5a; 281];
        sw(&web(&extended([0, 0xd6, 0, 0], &body, None)), 0x9000);
        assert_eq!(collect(web(&read(281)), web), body);
    }
    unsafe { core::reset::<Fake>() };
}
