// SPDX-License-Identifier: Apache-2.0
// Standalone GetInfo over portable dependencies, with no Core/vcap linkage.
use canokey_ctap::{
    info::{self, Flag, Part, State, Value},
    request::{Parameterless, parameterless},
};
use canokey_protocol::cbor::{EncodeError, Encoder, SliceDecoder};

// CTAP 2.3 section 6.4: map of versions (1), AAGUID (3), options (4),
// maxMsgSize (5), forcePINChange (12), minPINLength (13), longReset (24).
// Fragment bytes use RFC 8949 shortest forms and contain no card state.
const SCHEMA: &[Part] = &[
    Part::Encoded(&[
        0xa7, 0x01, 0x81, 0x68, b'F', b'I', b'D', b'O', b'_', b'2', b'_', b'1', 0x03,
    ]),
    Part::Value(Value::Aaguid),
    Part::Encoded(&[
        0x04, 0xa1, 0x69, b'c', b'l', b'i', b'e', b'n', b't', b'P', b'i', b'n',
    ]),
    Part::Value(Value::ClientPin),
    Part::Encoded(&[0x05]),
    Part::Choice(Flag::Nfc, &[0x19, 0x08, 0x00], &[0x19, 0x05, 0x10]),
    Part::Encoded(&[0x0c]),
    Part::Value(Value::ForceChange),
    Part::Encoded(&[0x0d]),
    Part::Value(Value::MinimumPinLength),
    Part::Encoded(&[0x18, 0x18]),
    Part::Value(Value::LongReset),
];

#[test]
fn parse_get_info_and_encode_without_product_crates() {
    assert_eq!(
        parameterless(Some(0x04), false),
        Ok(Some(Parameterless::GetInfo))
    );
    let aaguid = [0x42; 16];
    for nfc in [false, true] {
        for client_pin in [false, true] {
            let state = State {
                aaguid: &aaguid,
                always_uv: false,
                client_pin,
                force_change: client_pin,
                minimum_pin_length: 8,
                remaining_credentials: 0,
                long_reset: true,
                nfc,
                algorithm: -7,
            };
            let mut output = [0xa5; 128];
            let mut encoder = Encoder::new(&mut output[..]);
            info::encode(SCHEMA, &state, &mut encoder).unwrap();
            let length = 128 - encoder.writer().len();
            let mut reader = SliceDecoder::new(&output[..length]);
            assert_eq!(reader.map().unwrap(), Some(7));
            assert_eq!(reader.u64().unwrap(), 1);
            reader.skip().unwrap();
            assert!(
                output[..length]
                    .windows(8)
                    .any(|bytes| bytes == b"FIDO_2_1")
            );
            assert_eq!(reader.u64().unwrap(), 3);
            assert_eq!(reader.bytes().unwrap(), aaguid);
            assert_eq!(reader.u64().unwrap(), 4);
            assert_eq!(reader.map().unwrap(), Some(1));
            assert_eq!(reader.str().unwrap(), "clientPin");
            assert_eq!(reader.bool().unwrap(), client_pin);
            assert_eq!(reader.u64().unwrap(), 5);
            assert_eq!(reader.u64().unwrap(), if nfc { 2048 } else { 1296 });
            assert_eq!(reader.u64().unwrap(), 12);
            assert_eq!(reader.bool().unwrap(), client_pin);
            assert_eq!(reader.u64().unwrap(), 13);
            assert_eq!(reader.u64().unwrap(), 8);
            assert_eq!(reader.u64().unwrap(), 24);
            assert!(reader.bool().unwrap());
            for capacity in 0..length {
                let mut guarded = [0xa5; 130];
                let mut encoder = Encoder::new(&mut guarded[1..1 + capacity]);
                assert_eq!(info::encode(SCHEMA, &state, &mut encoder), Err(EncodeError));
                assert_eq!(guarded[0], 0xa5);
                assert!(guarded[1 + capacity..].iter().all(|byte| *byte == 0xa5));
            }
        }
    }
}
