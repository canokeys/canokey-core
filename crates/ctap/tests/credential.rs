// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::credential::{self, ExtensionDomain, HandleDomain, Id, Mac, Scheme, Transcript};

struct Capture {
    root: [u8; 32],
    expected: Vec<u8>,
    calls: usize,
    fail: bool,
}
impl Mac for Capture {
    type Error = ();
    fn hmac_sha256(
        &mut self,
        root: &[u8; 32],
        transcript: &Transcript<'_>,
        out: &mut [u8; 32],
    ) -> Result<(), ()> {
        self.calls += 1;
        assert_eq!(root, &self.root);
        let mut streamed = Vec::new();
        transcript.for_each_part(|part| streamed.extend_from_slice(part));
        assert_eq!(streamed, self.expected);
        for capacity in 0..=credential::EXTENSION_TRANSCRIPT_BYTES + 1 {
            let mut buffer = vec![0xa5; capacity];
            if capacity < self.expected.len() {
                assert_eq!(transcript.copy_to(&mut buffer), None);
                assert!(buffer.iter().all(|&byte| byte == 0xa5));
            } else {
                assert_eq!(transcript.copy_to(&mut buffer), Some(self.expected.len()));
                assert_eq!(&buffer[..self.expected.len()], &self.expected);
                assert!(
                    buffer[self.expected.len()..]
                        .iter()
                        .all(|&byte| byte == 0xa5)
                );
            }
        }
        if self.fail {
            return Err(());
        }
        out.fill(0x7a);
        Ok(())
    }
}
fn reference(domain: u8, id: &[u8], rp: &[u8; 32], settings: &[u8]) -> Vec<u8> {
    // Fixed pre-extraction product recipe: domain byte, ID prefix/full ID,
    // 32-byte RP hash, then eight SM2 setting bytes for handle MACs only.
    let mut bytes = vec![domain];
    bytes.extend_from_slice(id);
    bytes.extend_from_slice(rp);
    bytes.extend_from_slice(settings);
    bytes
}
#[test]
fn streamed_and_contiguous_handle_transcripts_match_both_product_recipes() {
    let root = [0x69; 32];
    let rp = [0x31; 32];
    let settings = [0x11, 0x80, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x01];
    let mut cases = 0;
    for scheme in 0x00..=0x04 {
        for nonce in 0x00..=0xff {
            let mut id: Id = [nonce; 34];
            id[0] = scheme;
            id[1] = 0x07;
            for (domain, byte) in [(HandleDomain::Tag, 0x00), (HandleDomain::Seed, 0x01)] {
                for suffix in [None, Some(&settings)] {
                    let expected = reference(
                        byte,
                        &id[..18],
                        &rp,
                        suffix.map_or(&[][..], |bytes| bytes.as_slice()),
                    );
                    let mut mac = Capture {
                        root,
                        expected,
                        calls: 0,
                        fail: false,
                    };
                    let mut out = [0x00; 32];
                    credential::derive_handle(&root, &id, &rp, domain, suffix, &mut out, &mut mac)
                        .unwrap();
                    assert_eq!(out, [0x7a; 32]);
                    assert_eq!(mac.calls, 1);
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 5120);
}
#[test]
fn extension_domains_bind_full_id_and_never_include_sm2_settings() {
    let root = [0x69; 32];
    let rp = [0x31; 32];
    let mut cases = 0;
    for scheme in 0x00..=0x04 {
        for tag in 0x00..=0xff {
            let mut id = [0x22; 34];
            id[0] = scheme;
            id[18..].fill(tag);
            for (domain, byte) in [
                (ExtensionDomain::LargeBlobKey, 0x02),
                (ExtensionDomain::HmacSecretWithoutUv, 0x03),
                (ExtensionDomain::HmacSecretWithUv, 0x04),
            ] {
                let mut mac = Capture {
                    root,
                    expected: reference(byte, &id, &rp, &[]),
                    calls: 0,
                    fail: false,
                };
                credential::derive_extension(&root, &id, &rp, domain, &mut [0x00; 32], &mut mac)
                    .unwrap();
                assert_eq!(mac.calls, 1);
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 3840);
}
#[test]
fn scheme_discriminators_and_layout_are_fixed_and_not_native_algorithm_ids() {
    let schemes = [
        Scheme::P256,
        Scheme::Ed25519,
        Scheme::Sm2,
        Scheme::MlDsa65,
        Scheme::MlDsa44,
    ];
    for byte in 0x00..=0xff {
        assert_eq!(
            Scheme::decode(byte),
            schemes.get(usize::from(byte)).copied()
        );
    }
    assert_eq!((credential::NONCE_OFFSET, credential::NONCE_BYTES), (2, 16));
    assert_eq!(
        (
            credential::TAG_OFFSET,
            credential::TAG_BYTES,
            credential::ID_BYTES
        ),
        (18, 16, 34)
    );
    assert_eq!(credential::HANDLE_TRANSCRIPT_MAX_BYTES, 59);
    assert_eq!(credential::EXTENSION_TRANSCRIPT_BYTES, 67);
    assert_eq!(
        (
            credential::RESIDENT,
            credential::CRED_PROTECT_MASK,
            credential::THIRD_PARTY_PAYMENT
        ),
        (0x04, 0x03, 0x10)
    );
}
#[test]
fn mac_failure_propagates_once_and_does_not_initialize_product_output() {
    let root = [0x69; 32];
    let id = [0x22; 34];
    let rp = [0x31; 32];
    let mut mac = Capture {
        root,
        expected: reference(0x00, &id[..18], &rp, &[]),
        calls: 0,
        fail: true,
    };
    let mut out = [0xa5; 32];
    assert_eq!(
        credential::derive_handle(&root, &id, &rp, HandleDomain::Tag, None, &mut out, &mut mac),
        Err(())
    );
    assert_eq!(out, [0xa5; 32]);
    assert_eq!(mac.calls, 1);
    mac.expected = reference(0x04, &id, &rp, &[]);
    assert_eq!(
        credential::derive_extension(
            &root,
            &id,
            &rp,
            ExtensionDomain::HmacSecretWithUv,
            &mut out,
            &mut mac
        ),
        Err(())
    );
    assert_eq!(out, [0xa5; 32]);
    assert_eq!(mac.calls, 2);
}
