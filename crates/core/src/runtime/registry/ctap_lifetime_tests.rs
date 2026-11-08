// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::ports::{Crypto, CryptoError, Device, Memory, Record, Storage, StorageError};

struct NoIo;
impl Storage for NoIo {
    fn load(&mut self, _: Record, _: &mut [u8]) -> Result<usize, StorageError> {
        panic!("response close must not read storage")
    }
    fn replace(&mut self, _: Record, _: &[u8]) -> Result<(), StorageError> {
        panic!("response close must not write storage")
    }
}
impl Crypto for NoIo {
    fn random(&mut self, _: &mut [u8]) -> Result<(), CryptoError> {
        panic!("response close must not generate keys")
    }
    fn mac(&mut self, _: u8, _: &[u8], _: &[u8], _: &mut [u8; 64]) -> Result<(), CryptoError> {
        panic!("response close must not calculate MACs")
    }
    fn hmac_sha1(&mut self, _: &[u8; 20], _: &[u8], _: &mut [u8; 20]) {
        panic!("response close must not calculate PASS HMACs")
    }
}
impl Device for NoIo {
    fn serial(&mut self, _: &mut [u8; 4]) {
        panic!("unexpected identity access")
    }
    fn now(&mut self) -> u32 {
        panic!("unexpected clock access")
    }
    fn touched(&mut self) -> bool {
        panic!("unexpected presence access")
    }
    fn progress(&mut self) -> bool {
        panic!("close must not yield")
    }
    fn led(&mut self, _: bool) {
        panic!("unexpected LED access")
    }
}
struct Wipe;
impl Memory for Wipe {
    fn wipe(&self, bytes: &mut [u8]) {
        bytes.fill(0x00);
    }
}

#[test]
fn iso_response_close_erases_classic_backing() {
    let mut registry = Registry::new();
    registry.applet = AppletState::Ctap;
    let mut storage = NoIo;
    let mut crypto = NoIo;
    let mut device = NoIo;
    let mut platform = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
        storage: &mut storage,
        crypto: &mut crypto,
        device: &mut device,
        memory: &Wipe,
    };
    // Every response kind can leave bytes in the shared classic backing. Closing
    // must erase the backing even when its response metadata is already empty.
    let workspace = registry.workspace.classic_with(&Wipe);
    workspace.key.bytes.fill(0x37);
    workspace.key.bits = 256;
    workspace.input.fill(0x38);
    workspace.output.fill(0x39);
    registry.view().close_response(&mut platform);
    registry.view().close_response(&mut platform);
    let workspace = registry.workspace.classic_with(&Wipe);
    assert!(workspace.key.bytes.iter().all(|byte| *byte == 0x00));
    assert_eq!(workspace.key.bits, 0);
    assert!(workspace.input.iter().all(|byte| *byte == 0x00));
    assert!(workspace.output.iter().all(|byte| *byte == 0x00));
}

#[test]
fn unselected_ctap_close_does_not_erase_another_applets_workspace() {
    let mut registry = Registry::new();
    let mut storage = NoIo;
    let mut crypto = NoIo;
    let mut device = NoIo;
    let mut platform = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
        storage: &mut storage,
        crypto: &mut crypto,
        device: &mut device,
        memory: &Wipe,
    };
    registry.workspace.classic_with(&Wipe).input.fill(0x37);
    registry.view().close_response(&mut platform);
    assert!(
        registry
            .workspace
            .classic_with(&Wipe)
            .input
            .iter()
            .all(|byte| *byte == 0x37)
    );
}

struct Abort {
    calls: usize,
    fail: bool,
}
impl Crypto for Abort {
    fn random(&mut self, _: &mut [u8]) -> Result<(), CryptoError> {
        unreachable!()
    }
    fn mac(&mut self, _: u8, _: &[u8], _: &[u8], _: &mut [u8; 64]) -> Result<(), CryptoError> {
        unreachable!()
    }
    fn hmac_sha1(&mut self, _: &[u8; 20], _: &[u8], _: &mut [u8; 20]) {
        unreachable!()
    }
    fn stream(
        &mut self,
        operation: crate::ports::StreamOperation,
        _: u8,
        scratch: &mut crate::ports::CryptoScratch,
        _: &[u8],
        _: &mut [u8],
    ) -> Result<usize, CryptoError> {
        assert!(matches!(operation, crate::ports::StreamOperation::Abort));
        // The opaque primitive must be released while its handle is intact.
        assert!(scratch.bytes.iter().all(|byte| *byte == 0xc7));
        self.calls += 1;
        if self.fail {
            Err(CryptoError::Failure)
        } else {
            Ok(0)
        }
    }
}

#[test]
fn iso_stream_close_aborts_before_erasing_even_when_abort_fails() {
    for fail in [false, true] {
        let mut registry = Registry::new();
        registry.applet = AppletState::Ctap;
        let mut storage = NoIo;
        let mut crypto = Abort { calls: 0, fail };
        let mut device = NoIo;
        let mut platform = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
            storage: &mut storage,
            crypto: &mut crypto,
            device: &mut device,
            memory: &Wipe,
        };
        let mut scratch = crate::ports::CryptoScratch::new();
        scratch.bytes.fill(0xc7);
        let super::super::workspace::SessionWorkspace::Working(working) = &mut registry.workspace
        else {
            unreachable!()
        };
        working.primitive = super::super::workspace::Primitive::Ctap(scratch);
        working.framing.bytes.fill(0xa6);
        registry.view().close_response(&mut platform);
        let stream = registry.workspace.ctap_stream().unwrap();
        assert!(stream.crypto.bytes.iter().all(|byte| *byte == 0x00));
        assert!(stream.framing.bytes.iter().all(|byte| *byte == 0x00));
        assert_eq!(crypto.calls, 1);
    }
}
