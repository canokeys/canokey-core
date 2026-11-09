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

// Physical framing excludes the external authData, signature and certificate.
// Assertion signatures insert raw bytes; packed attestation inserts an encoded
// DER byte string, including its header, before the x5c field.
#[test]
fn pq_markers_reconstruct_both_profiles_and_reject_every_short_framing() {
    for params in [canokey_ports::mldsa::DSA44, canokey_ports::mldsa::DSA65] {
        for make in [false, true] {
            for with_user in [false, true] {
                for with_blob in [false, true] {
                    let with_user = with_user && !make;
                    let count = if with_user { 2 } else { 0 };
                    let auth = vec![0x33; 37 + if make { params.public_bytes } else { 0 }];
                    let signature = vec![0x44; if make { 71 } else { params.signature_bytes }];
                    let certificate = [0x55; 70];
                    let mut expected = vec![0x00; 8192];
                    let mut reference = Encoder::new(&mut expected[..]);
                    reference.map(
                        3 + u64::from(with_user) + u64::from(count > 1) + u64::from(with_blob),
                    );
                    if make {
                        reference.u8(0x01).str("packed").u8(0x02);
                    } else {
                        reference
                            .u8(0x01)
                            .map(2)
                            .str("id")
                            .bytes(b"ID")
                            .str("type")
                            .str("public-key")
                            .u8(0x02);
                    }
                    reference.bytes(&auth).u8(0x03);
                    if make {
                        reference.map(3).str("alg").i32(-7).str("sig");
                    }
                    reference.bytes(&signature);
                    if make {
                        reference.str("x5c").array(1).bytes(&certificate);
                    }
                    if with_user {
                        reference.u8(0x04);
                        user(&mut reference).unwrap();
                    }
                    if count > 1 {
                        reference.u8(0x05).u8(count);
                    }
                    if with_blob {
                        reference
                            .u8(if make { 0x05 } else { 0x07 })
                            .bytes(&[0x66; 32]);
                    }
                    reference.finish().unwrap();
                    let expected_len = 8192 - reference.writer().len();
                    let mut framing = [0xa5; 258];
                    let mut e = Encoder::new(&mut framing[1..257]);
                    let auth_at = 256
                        - reply::start_fields(
                            &mut e,
                            reply::Fields {
                                make,
                                user: with_user,
                                count,
                                blob_key: with_blob,
                            },
                            b"ID",
                            Body::External(auth.len()),
                        )
                        .unwrap();
                    let signature_at = if make {
                        reply::statement_prefix(&mut e, true, None).unwrap();
                        256 - e.writer().len()
                    } else {
                        256 - reply::signature_header(&mut e, signature.len())
                    };
                    let certificate_at = if make {
                        256 - reply::certificate_body(&mut e, Body::External(certificate.len()))
                    } else {
                        signature_at
                    };
                    reply::tail_fields(&mut e, with_user, count, user).unwrap();
                    if with_blob {
                        reply::blob_key(&mut e, make, &[0x66; 32]);
                    }
                    e.finish().unwrap();
                    let used = 256 - e.writer().len();
                    let physical = &framing[1..1 + used];
                    let mut reconstructed = Vec::from(&physical[..auth_at]);
                    reconstructed.extend_from_slice(&auth);
                    reconstructed.extend_from_slice(&physical[auth_at..signature_at]);
                    if make {
                        let mut encoded = [0x00; 80];
                        let mut e = Encoder::new(&mut encoded[..]);
                        e.bytes(&signature).finish().unwrap();
                        let length = 80 - e.writer().len();
                        reconstructed.extend_from_slice(&encoded[..length]);
                    } else {
                        reconstructed.extend_from_slice(&signature);
                    }
                    reconstructed.extend_from_slice(&physical[signature_at..certificate_at]);
                    if make {
                        reconstructed.extend_from_slice(&certificate);
                    }
                    reconstructed.extend_from_slice(&physical[certificate_at..]);
                    assert_eq!(reconstructed, expected[..expected_len]);
                    for capacity in 0..=used {
                        let mut output = [0xa5; 258];
                        let mut e = Encoder::new(&mut output[1..1 + capacity]);
                        let result = (|| {
                            reply::start_fields(
                                &mut e,
                                reply::Fields {
                                    make,
                                    user: with_user,
                                    count,
                                    blob_key: with_blob,
                                },
                                b"ID",
                                Body::External(auth.len()),
                            )?;
                            if make {
                                reply::statement_prefix(&mut e, true, None)?;
                                reply::certificate_body(&mut e, Body::External(certificate.len()));
                            } else {
                                reply::signature_header(&mut e, signature.len());
                            }
                            reply::tail_fields(&mut e, with_user, count, user)
                                .map_err(|_| EncodeError)?;
                            if with_blob {
                                reply::blob_key(&mut e, make, &[0x66; 32]);
                            }
                            e.finish()
                        })();
                        assert_eq!(result.is_ok(), capacity == used);
                        assert_eq!(output[0], 0xa5);
                        assert!(output[1 + capacity..].iter().all(|b| *b == 0xa5));
                    }
                }
            }
        }
    }
}
