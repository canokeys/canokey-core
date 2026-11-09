// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::response::{
    credential::{self as reply, Body, Envelope, Error},
    encoding::{EncodeError, Encoder},
};

// Independent CTAP map encoding, retaining the product field/read sequence.
fn reference(
    e: &mut Encoder<&mut [u8]>,
    make: bool,
    algorithm: Option<i32>,
    user: bool,
    count: u8,
    blob: bool,
) {
    e.map(3 + u64::from(user) + u64::from(count > 1) + u64::from(blob));
    if make {
        e.u8(0x01).str("packed").u8(0x02);
    } else {
        e.u8(0x01)
            .map(2)
            .str("id")
            .bytes(b"ID")
            .str("type")
            .str("public-key")
            .u8(0x02);
    }
    e.bytes(&[0x33; 37]).u8(0x03);
    if make {
        if let Some(algorithm) = algorithm {
            e.map(2).str("alg").i32(algorithm).str("sig");
        } else {
            e.map(3).str("alg").i32(-7).str("sig");
        }
    }
    e.bytes(&[0x44; 64]);
    if make && algorithm.is_none() {
        e.str("x5c").array(1).bytes(&[0x55; 70]);
    }
    if user {
        e.u8(0x04).map(1).str("id").bytes(b"USER");
    }
    if count > 1 {
        e.u8(0x05).u8(count);
    }
    if blob {
        e.u8(if make { 0x05 } else { 0x07 }).bytes(&[0x66; 32]);
    }
}
fn user(e: &mut Encoder<&mut [u8]>) -> Result<(), u8> {
    e.map(1).str("id").bytes(b"USER");
    e.finish().map_err(|_| 0x91)
}

#[test]
fn classic_envelopes_match_independent_maps_at_every_output_capacity() {
    for make in [false, true] {
        for algorithm in [None, Some(-7), Some(-8), Some(-65537)] {
            for include_user in [false, true] {
                for count in [0, 1, 2, 255] {
                    for blob in [false, true] {
                        let envelope = Envelope {
                            make,
                            id: b"ID",
                            user: include_user,
                            count,
                            blob_key: blob.then_some(&[0x66; 32][..]),
                        };
                        let certificate =
                            (make && algorithm.is_none()).then_some(Body::Bytes(&[0x55; 70]));
                        let mut expected = [0x00; 384];
                        let mut e = Encoder::new(&mut expected[..]);
                        reference(&mut e, make, algorithm, include_user, count, blob);
                        e.finish().unwrap();
                        let length = 384 - e.writer().len();
                        for capacity in 0..=length {
                            let mut backing = [0xa5; 386];
                            let mut e = Encoder::new(&mut backing[1..1 + capacity]);
                            let result = reply::assemble(
                                &mut e,
                                &envelope,
                                Body::Bytes(&[0x33; 37]),
                                algorithm,
                                &[0x44; 64],
                                certificate,
                                user,
                            );
                            if capacity == length {
                                assert!(result.is_ok());
                                assert_eq!(&backing[1..1 + capacity], &expected[..length]);
                            } else {
                                assert!(result.is_err());
                            }
                            assert_eq!(backing[0], 0xa5);
                            assert!(backing[1 + capacity..].iter().all(|b| *b == 0xa5));
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn external_auth_and_certificate_insertions_reconstruct_the_exact_reply() {
    for include_user in [false, true] {
        for count in [0, 2] {
            let envelope = Envelope {
                make: true,
                id: b"ID",
                user: include_user,
                count,
                blob_key: Some(&[0x66; 32]),
            };
            let mut backing = [0x00; 256];
            let mut e = Encoder::new(&mut backing[..]);
            let layout = reply::assemble(
                &mut e,
                &envelope,
                Body::External(37),
                None,
                &[0x44; 64],
                Some(Body::External(70)),
                user,
            )
            .unwrap();
            let used = 256 - e.writer().len();
            let auth_at = 256 - layout.auth_remaining;
            let cert_at = 256 - layout.certificate_remaining.unwrap();
            let mut reconstructed = Vec::new();
            reconstructed.extend_from_slice(&backing[..auth_at]);
            reconstructed.extend_from_slice(&[0x33; 37]);
            reconstructed.extend_from_slice(&backing[auth_at..cert_at]);
            reconstructed.extend_from_slice(&[0x55; 70]);
            reconstructed.extend_from_slice(&backing[cert_at..used]);
            let mut expected = [0x00; 384];
            let mut e = Encoder::new(&mut expected[..]);
            reference(&mut e, true, None, include_user, count, true);
            e.finish().unwrap();
            let length = 384 - e.writer().len();
            assert_eq!(reconstructed, expected[..length]);
        }
    }
}

#[test]
fn deferred_user_read_keeps_encoding_error_precedence_and_partial_prefix() {
    let envelope = Envelope {
        make: false,
        id: b"ID",
        user: true,
        count: 2,
        blob_key: None,
    };
    let mut wire = [0x00; 256];
    let mut e = Encoder::new(&mut wire[..]);
    reply::start(&mut e, &envelope, Body::Bytes(&[0x33; 37])).unwrap();
    reply::statement(&mut e, false, None, &[0x44; 64], None).unwrap();
    let user_key_at = 256 - e.writer().len();
    for capacity in 0..=user_key_at + 8 {
        let mut output = [0xa5; 256];
        let mut e = Encoder::new(&mut output[..capacity]);
        let mut calls = 0;
        let result = reply::assemble(
            &mut e,
            &envelope,
            Body::Bytes(&[0x33; 37]),
            None,
            &[0x44; 64],
            None,
            |e| {
                calls += 1;
                e.encoded(&[0x77]);
                Err(0x92)
            },
        );
        if capacity <= user_key_at {
            assert_eq!(calls, 0);
            assert_eq!(result, Err(Error::Encoding));
        } else {
            assert_eq!(calls, 1);
            assert_eq!(result, Err(Error::User(0x92)));
        }
        assert!(output[capacity..].iter().all(|b| *b == 0xa5));
    }
}

#[test]
fn staged_materialized_user_and_complete_envelopes_match() {
    let envelope = Envelope {
        make: true,
        id: b"ID",
        user: true,
        count: 2,
        blob_key: None,
    };
    let mut expected = [0x00; 256];
    let mut e = Encoder::new(&mut expected[..]);
    reply::assemble(
        &mut e,
        &envelope,
        Body::External(37),
        Some(-8),
        &[0x44; 64],
        None,
        user,
    )
    .unwrap();
    let length = 256 - e.writer().len();
    for capacity in 0..=length {
        let mut output = [0xa5; 258];
        let mut e = Encoder::new(&mut output[1..1 + capacity]);
        let result = (|| {
            reply::start(&mut e, &envelope, Body::External(37))?;
            reply::statement(&mut e, true, Some(-8), &[0x44; 64], None)?;
            reply::tail(&mut e, &envelope, user).map_err(|_| EncodeError)
        })();
        if capacity == length {
            assert_eq!(result, Ok(()));
            assert_eq!(&output[1..1 + capacity], &expected[..length]);
        } else {
            assert_eq!(result, Err(EncodeError));
        }
        assert_eq!(output[0], 0xa5);
        assert!(output[1 + capacity..].iter().all(|b| *b == 0xa5));
    }
}
