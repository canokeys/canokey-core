// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::response::{encoding::Encoder, extensions::Fields};

#[test]
fn extension_outputs_match_independent_maps_at_every_capacity() {
    for make in [false, true] {
        for mask in 0..128 {
            for hmac_length in [32, 48, 64, 80] {
                let fields = Fields {
                    make,
                    protection: (mask & 0x01 != 0).then_some(3),
                    min_pin_length: (mask & 0x02 != 0).then_some(8),
                    cred_blob: (make && mask & 0x04 != 0).then_some(mask & 0x08 != 0),
                    get_cred_blob: !make && mask & 0x04 != 0,
                    hmac_secret: make && mask & 0x10 != 0,
                    hmac: mask & 0x20 != 0,
                    third_party_payment: mask & 0x40 != 0,
                };
                let blob = [0x77; 32];
                let ciphertext = [0x88; 80];
                let hmac = if fields.hmac {
                    &ciphertext[..hmac_length]
                } else {
                    &[]
                };
                let mut expected = [0x00; 256];
                let mut e = Encoder::new(&mut expected[..]);
                let count = usize::from(mask & 0x01 != 0)
                    + usize::from(mask & 0x02 != 0)
                    + usize::from(mask & 0x04 != 0)
                    + usize::from(make && mask & 0x10 != 0)
                    + usize::from(mask & 0x20 != 0)
                    + usize::from(!make && mask & 0x40 != 0);
                assert_eq!(fields.count(), count as u64);
                e.map(count as u64);
                if mask & 0x04 != 0 {
                    e.str("credBlob");
                    if make {
                        e.bool(mask & 0x08 != 0);
                    } else {
                        e.bytes(&blob);
                    }
                }
                if mask & 0x01 != 0 {
                    e.str("credProtect").u8(3);
                }
                if make && mask & 0x10 != 0 {
                    e.str("hmac-secret").bool(true);
                }
                if !make && mask & 0x20 != 0 {
                    e.str("hmac-secret").bytes(hmac);
                }
                if mask & 0x02 != 0 {
                    e.str("minPinLength").u8(8);
                }
                if make && mask & 0x20 != 0 {
                    e.str("hmac-secret-mc").bytes(hmac);
                }
                if !make && mask & 0x40 != 0 {
                    e.str("thirdPartyPayment").bool(mask & 0x08 != 0);
                }
                e.finish().unwrap();
                let length = 256 - e.writer().len();
                for capacity in 0..=length {
                    let mut output = [0xa5; 258];
                    let mut e = Encoder::new(&mut output[1..1 + capacity]);
                    let result = fields.encode(&mut e, &blob, hmac, || mask & 0x08 != 0);
                    assert_eq!(result.is_ok(), capacity == length);
                    if capacity == length {
                        assert_eq!(&output[1..1 + capacity], &expected[..length]);
                    }
                    assert_eq!(output[0], 0xa5);
                    assert!(output[1 + capacity..].iter().all(|b| *b == 0xa5));
                }
            }
        }
    }
}

#[test]
fn blob_lengths_and_lazy_third_party_inspection_preserve_capability_boundaries() {
    for length in 0..=32 {
        for make in [false, true] {
            let fields = Fields {
                make,
                get_cred_blob: true,
                third_party_payment: true,
                ..Default::default()
            };
            let blob = [0x77; 32];
            let mut output = [0x00; 96];
            let mut e = Encoder::new(&mut output[..]);
            let mut inspections = 0;
            fields
                .encode(&mut e, &blob[..length], &[], || {
                    inspections += 1;
                    true
                })
                .unwrap();
            assert_eq!(inspections, usize::from(!make));
            let used = 96 - e.writer().len();
            let mut expected = [0x00; 96];
            let mut e = Encoder::new(&mut expected[..]);
            e.map(if make { 1 } else { 2 })
                .str("credBlob")
                .bytes(&blob[..length]);
            if !make {
                e.str("thirdPartyPayment").bool(true);
            }
            e.finish().unwrap();
            assert_eq!(used, 96 - e.writer().len());
            assert_eq!(&output[..used], &expected[..used]);
        }
    }
}
