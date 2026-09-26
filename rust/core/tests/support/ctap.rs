// SPDX-License-Identifier: Apache-2.0
use canokey_rust_core::{Core, ports::*};
#[derive(Default)]
pub struct Backend {
    pub generated: usize,
}
impl Storage for Backend {
    fn load(&mut self, _: Record, _: &mut [u8]) -> Result<usize, StorageError> {
        Err(StorageError::Missing)
    }
    fn replace(&mut self, _: Record, _: &[u8]) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
}
impl Crypto for Backend {
    fn key_operation(
        &mut self,
        op: KeyOperation,
        _: u8,
        key: &mut KeyMaterial,
        _: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        match op {
            KeyOperation::Generate => {
                self.generated += 1;
                key.bytes[..32].fill(7);
                Ok(0)
            }
            KeyOperation::Public => {
                assert_eq!(&key.bytes[..32], &[7; 32]);
                out[..64].fill(8);
                Ok(64)
            }
            _ => Err(CryptoError::Failure),
        }
    }
    fn mac(&mut self, _: u8, _: &[u8], _: &[u8], _: &mut [u8; 64]) -> Result<(), CryptoError> {
        Err(CryptoError::Failure)
    }
    fn random(&mut self, _: &mut [u8]) -> Result<(), CryptoError> {
        Err(CryptoError::Failure)
    }
    fn hmac_sha1(&mut self, _: &[u8; 20], _: &[u8], _: &mut [u8; 20]) {
        unreachable!()
    }
}
impl Device for Backend {
    fn now(&mut self) -> u32 {
        0
    }
    fn serial(&mut self, _: &mut [u8; 4]) {
        unreachable!()
    }
    fn touched(&mut self) -> bool {
        false
    }
    fn progress(&mut self) -> bool {
        true
    }
    fn led(&mut self, _: bool) {}
}
impl Memory for Backend {
    fn wipe(&self, bytes: &mut [u8]) {
        bytes.fill(0);
    }
}
pub fn with_platform<T>(crypto: &mut Backend, run: impl FnOnce(&mut Platform<'_>) -> T) -> T {
    run(&mut Platform {
        storage: &mut Backend::default(),
        crypto,
        device: &mut Backend::default(),
        memory: &Backend::default(),
    })
}
pub fn execute(
    core: &mut Core,
    command: Result<
        canokey_rust_core::applets::ctap::Command,
        canokey_rust_core::applets::ctap::Status,
    >,
) -> Vec<u8> {
    with_platform(&mut Backend::default(), |p| {
        let n = core.execute_ctap(command, p);
        let mut out = vec![0; n];
        core.read_ctap(0, &mut out, p).unwrap();
        out
    })
}
