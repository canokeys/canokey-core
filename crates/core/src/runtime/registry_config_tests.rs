// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::ports::{Crypto, CryptoError, Device, Memory, Record, Storage, StorageError};
struct Disk {
    page: [u8; 512],
    fail: bool,
}
impl Storage for Disk {
    fn load(&mut self, _: Record, _: &mut [u8]) -> Result<usize, StorageError> {
        Err(StorageError::Missing)
    }
    fn replace(&mut self, _: Record, _: &[u8]) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    fn config_read(&mut self, off: usize, bytes: &mut [u8]) -> Result<(), StorageError> {
        if self.fail {
            return Err(StorageError::Unavailable);
        }
        bytes.copy_from_slice(&self.page[off..off + bytes.len()]);
        Ok(())
    }
    fn config_write(&mut self, page: &[u8; 512]) -> Result<(), StorageError> {
        self.page = *page;
        Ok(())
    }
}
struct Hardware(bool);
impl Device for Hardware {
    fn contactless(&mut self) -> bool {
        self.0
    }
    fn serial(&mut self, _: &mut [u8; 4]) {}
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
impl Crypto for Hardware {
    fn random(&mut self, _: &mut [u8]) -> Result<(), CryptoError> {
        panic!("configuration cannot run crypto")
    }
    fn mac(&mut self, _: u8, _: &[u8], _: &[u8], _: &mut [u8; 64]) -> Result<(), CryptoError> {
        unreachable!()
    }
    fn hmac_sha1(&mut self, _: &[u8; 20], _: &[u8], _: &mut [u8; 20]) {
        unreachable!()
    }
}
impl Memory for Hardware {
    fn wipe(&self, bytes: &mut [u8]) {
        bytes.fill(0);
    }
}
#[test]
fn independent_transport_bits_and_failed_reads_guard_actual_select() {
    use super::super::config;
    for nfc in [false, true] {
        for flag in [
            config::OPENPGP_USB,
            config::OPENPGP_NFC,
            config::PIV_USB,
            config::PIV_NFC,
        ] {
            let mut disk = Disk {
                page: [0xff; 512],
                fail: false,
            };
            let mut hardware = Hardware(nfc);
            let mut crypto = Hardware(false);
            let mut p = Platform {
                storage: &mut disk,
                device: &mut hardware,
                crypto: &mut crypto,
                memory: &Hardware(false),
            };
            config::update(p.storage, config::FEATURES, flag).unwrap();
            let pgp = flag
                == if nfc {
                    config::OPENPGP_NFC
                } else {
                    config::OPENPGP_USB
                };
            let piv = flag
                == if nfc {
                    config::PIV_NFC
                } else {
                    config::PIV_USB
                };
            assert_eq!(Selected::OpenPgp.enabled(&mut p), pgp);
            assert_eq!(Selected::Piv.enabled(&mut p), piv);
            assert!(Selected::Admin.enabled(&mut p));
            let mut core = crate::Core::new();
            for (allowed, aid) in [
                (pgp, crate::applets::openpgp::protocol::AID),
                (piv, crate::applets::piv::AID),
            ] {
                if allowed {
                    continue;
                }
                let mut request = [0u8; 32];
                request[..5].copy_from_slice(&[0, 0xa4, 4, 0, aid.len() as u8]);
                request[5..5 + aid.len()].copy_from_slice(aid);
                let reply =
                    core.receive(if nfc { 4 } else { 1 }, &request[..5 + aid.len()], &mut p);
                let mut out = [0; 258];
                let n = core.transmit(reply, &mut out, &mut p).unwrap();
                assert_eq!(&out[..n], &[0x6a, 0x82]);
            }
            config::update(p.storage, config::NDEF, 0).unwrap();
            assert!(!Selected::Ndef.enabled(&mut p));
            config::reset_admin(p.storage).unwrap();
            assert!(
                Selected::OpenPgp.enabled(&mut p)
                    && Selected::Piv.enabled(&mut p)
                    && Selected::Ndef.enabled(&mut p)
            );
            disk.fail = true;
            let mut p = Platform {
                storage: &mut disk,
                device: &mut hardware,
                crypto: &mut crypto,
                memory: &Hardware(false),
            };
            assert!(!Selected::Piv.enabled(&mut p) && !Selected::OpenPgp.enabled(&mut p));
            assert!(Selected::Admin.enabled(&mut p)); // Recovery stays reachable.
        }
    }
}
