// SPDX-License-Identifier: Apache-2.0
extern crate std;
use super::*;
use crate::ports::*;
use canokey_ports::{DigestOperation as Hash, StreamOperation as Op};
use std::{cell::RefCell, rc::Rc, vec, vec::Vec};

type Trace = Rc<RefCell<Vec<&'static str>>>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    Key,
    Sign,
    PublicOpen,
    PublicRead,
    Digest,
    Reopen,
    Commit,
    Uncertain,
}
struct Disk {
    group: Option<Vec<u8>>,
    stage: Vec<u8>,
    fault: Fault,
    trace: Trace,
}
impl Storage for Disk {
    fn size(&mut self, id: Record) -> Result<u32, StorageError> {
        if id == Record::CtapCertificate {
            return Ok(10);
        }
        if id == Record::ctap_group(0).unwrap() {
            return self
                .group
                .as_ref()
                .map(|b| b.len() as u32)
                .ok_or(StorageError::Missing);
        }
        Err(StorageError::Missing)
    }
    fn read_at(&mut self, id: Record, offset: u32, out: &mut [u8]) -> Result<(), StorageError> {
        assert_eq!(id, Record::ctap_group(0).unwrap());
        let bytes = self.group.as_ref().unwrap();
        out.copy_from_slice(&bytes[offset as usize..offset as usize + out.len()]);
        Ok(())
    }
    fn load(&mut self, id: Record, out: &mut [u8]) -> Result<usize, StorageError> {
        match id {
            Record::CtapAttestationKey => {
                self.trace.borrow_mut().push("key");
                out.fill(0x17);
                if self.fault == Fault::Key {
                    Err(StorageError::Unavailable)
                } else {
                    Ok(32)
                }
            }
            Record::CtapMaster => {
                out.copy_from_slice(&[0x69; 32]);
                Ok(32)
            }
            Record::CtapPin | Record::CtapCounter | Record::CtapSm2 => Err(StorageError::Missing),
            _ => panic!("unexpected registration load {id:?}"),
        }
    }
    fn replace(&mut self, id: Record, _: &[u8]) -> Result<(), StorageError> {
        assert_eq!(id, Record::CtapCounter);
        // A record replacement must not overwrite the separate staged group.
        assert!(!self.stage.is_empty());
        self.trace.borrow_mut().push("counter");
        Ok(())
    }
    fn stage_begin(&mut self) -> Result<(), StorageError> {
        self.trace.borrow_mut().push("stage");
        self.stage.clear();
        Ok(())
    }
    fn stage_append(&mut self, bytes: &[u8]) -> Result<(), StorageError> {
        self.stage.extend_from_slice(bytes);
        Ok(())
    }
    fn stage_commit(&mut self, id: Record) -> Result<(), StorageError> {
        assert_eq!(id, Record::ctap_group(0).unwrap());
        self.trace.borrow_mut().push("commit");
        if self.fault == Fault::Commit {
            return Err(StorageError::Uncertain);
        }
        self.group = Some(core::mem::take(&mut self.stage));
        if self.fault == Fault::Uncertain {
            Err(StorageError::Uncertain)
        } else {
            Ok(())
        }
    }
    fn stage_abort(&mut self) {
        self.trace.borrow_mut().push("abort");
        self.stage.clear();
    }
}
struct Primitives {
    fault: Fault,
    trace: Trace,
    opens: usize,
}
impl Crypto for Primitives {
    fn sha256(&mut self, _: &[u8], out: &mut [u8; 32]) -> Result<(), CryptoError> {
        out.fill(0x31);
        Ok(())
    }
    fn mac(&mut self, _: u8, _: &[u8], _: &[u8], out: &mut [u8; 64]) -> Result<(), CryptoError> {
        out.fill(0x22);
        Ok(())
    }
    fn random(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        out.fill(0x11);
        Ok(())
    }
    fn hmac_sha1(&mut self, _: &[u8; 20], _: &[u8], _: &mut [u8; 20]) {
        unreachable!()
    }
    fn key_operation(
        &mut self,
        op: KeyOperation,
        algorithm: u8,
        _: &mut KeyMaterial,
        _: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        assert_eq!(algorithm, alg::P256);
        match op {
            KeyOperation::Public => {
                out[..64].fill(0x44);
                Ok(64)
            }
            KeyOperation::EcSign => {
                self.trace.borrow_mut().push("signed");
                out[..64].fill(0x11);
                if self.fault == Fault::Sign {
                    Err(CryptoError::Failure)
                } else {
                    Ok(64)
                }
            }
            _ => unreachable!(),
        }
    }
    fn p256_sign(
        &mut self,
        _: &[u8; 32],
        _: &[u8; 32],
        out: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        self.trace.borrow_mut().push("signed");
        out.fill(0x11);
        if self.fault == Fault::Sign {
            Err(CryptoError::Failure)
        } else {
            Ok(())
        }
    }
    fn digest(
        &mut self,
        op: Hash,
        _: &mut HashState,
        _: &[u8],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        if matches!(op, Hash::Final) {
            if self.fault == Fault::Digest {
                return Err(CryptoError::Failure);
            }
            out.fill(0x42);
        }
        Ok(())
    }
    fn stream(
        &mut self,
        op: Op,
        algorithm: u8,
        scratch: &mut CryptoScratch,
        _: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if matches!(op, Op::Abort) {
            scratch.bytes.fill(0x00);
            return Ok(0);
        }
        let params = mldsa::parameters(algorithm).unwrap();
        match op {
            Op::PublicInit => {
                self.opens += 1;
                self.trace.borrow_mut().push("public-open");
                scratch.bytes.fill(0xc7);
                if self.fault == Fault::PublicOpen
                    || (self.opens == 2 && self.fault == Fault::Reopen)
                {
                    Err(CryptoError::Failure)
                } else {
                    Ok(params.public_bytes)
                }
            }
            Op::Read => {
                out.fill(0x43);
                if self.fault == Fault::PublicRead {
                    Err(CryptoError::Failure)
                } else {
                    Ok(out.len())
                }
            }
            _ => unreachable!(),
        }
    }
}
struct DeviceFixture;
impl Device for DeviceFixture {
    fn serial(&mut self, _: &mut [u8; 4]) {
        unreachable!()
    }
    fn now(&mut self) -> u32 {
        0
    }
    fn touched(&mut self) -> bool {
        true
    }
    fn contactless(&mut self) -> bool {
        true
    }
    fn progress(&mut self) -> bool {
        true
    }
    fn led(&mut self, _: bool) {}
}
fn request(algorithm: i32) -> Parameters {
    const REQUEST_BYTES: usize = 160;
    let mut bytes = [0x00; REQUEST_BYTES];
    let mut e = Encoder::new(&mut bytes[..]);
    e.map(5)
        .u8(0x01)
        .bytes(&[0x42; 32])
        .u8(0x02)
        .map(1)
        .str("id")
        .str("x")
        .u8(0x03)
        .map(1)
        .str("id")
        .bytes(b"u")
        .u8(0x04)
        .array(1)
        .map(2)
        .str("alg")
        .i32(algorithm)
        .str("type")
        .str("public-key")
        .u8(0x07)
        .map(1)
        .str("rk")
        .bool(true)
        .finish()
        .unwrap();
    let length = REQUEST_BYTES - e.writer().len();
    let mut parser = super::super::credential_request::Parser::new(true);
    parser.consume(&bytes[..length]);
    let super::super::Command::Credential(params) = parser.finish().unwrap() else {
        unreachable!()
    };
    params
}
fn populated_group() -> Vec<u8> {
    use canokey_ctap::resident::{
        self as codec,
        group::{self, Replacement},
    };
    let mut header = group::empty();
    let mut output = vec![0x00; group::HEADER_BYTES];
    for slot in 0..group::MEMBERS {
        let mut value = vec![0x00; codec::MAX_BYTES];
        value[..codec::ID_BYTES].fill(0x77);
        value[1] = codec::RESIDENT;
        value[codec::ID_BYTES..codec::FIXED_BYTES].fill(0x31);
        let text = [0x72; 64];
        let user = [slot as u8; 64];
        let n = codec::encode_fields(
            &mut value[codec::FIXED_BYTES..],
            &[
                &text[..32],
                if slot == 0 { b"u" } else { &user },
                &text,
                &text,
                &text[..32],
            ],
        );
        value.truncate(codec::FIXED_BYTES + n);
        codec::Entry::decode(&value).unwrap();
        Replacement::set_length(&mut header, slot, value.len());
        output.extend_from_slice(&value);
    }
    output[..group::HEADER_BYTES].copy_from_slice(&header);
    output
}
#[test]
fn actual_registration_stages_before_signing_and_publishes_only_after_complete_classic_or_pq_reply()
{
    for algorithm in [-7, -49, -48] {
        for existing in [false, true] {
            for fault in [
                Fault::None,
                Fault::Key,
                Fault::Sign,
                Fault::PublicOpen,
                Fault::PublicRead,
                Fault::Digest,
                Fault::Reopen,
                Fault::Commit,
                Fault::Uncertain,
            ] {
                if algorithm == -7
                    && matches!(
                        fault,
                        Fault::PublicOpen | Fault::PublicRead | Fault::Digest | Fault::Reopen
                    )
                {
                    continue;
                }
                let trace = Trace::default();
                let old = existing.then(populated_group);
                let mut disk = Disk {
                    group: old.clone(),
                    stage: Vec::new(),
                    fault,
                    trace: trace.clone(),
                };
                let mut crypto = Primitives {
                    fault,
                    trace: trace.clone(),
                    opens: 0,
                };
                let mut device = DeviceFixture;
                let memory = canokey_ports::default_memory();
                let mut workspace = SessionWorkspace::new();
                let mut session = Session::new();
                let mut platform = Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
                    storage: &mut disk,
                    crypto: &mut crypto,
                    device: &mut device,
                    memory: &memory,
                };
                let response = session.execute(
                    &mut Ok(super::super::Command::Credential(request(algorithm))),
                    &mut workspace,
                    &mut platform,
                );
                if cfg!(feature = "ctap-restrict-algorithms") && algorithm != -7 {
                    assert!(matches!(response,
                        super::super::Response::Error(Status::UnsupportedAlgorithm)));
                    assert!(trace.borrow().is_empty());
                    assert_eq!(disk.group, old);
                    assert!(disk.stage.is_empty());
                    assert!(session.auth_response.is_none());
                    continue;
                }
                if fault == Fault::None {
                    assert!(!matches!(response, super::super::Response::Error(_)));
                    if let Some(mut stream) = workspace.ctap_stream() {
                        stream.close(&mut platform);
                    }
                } else {
                    assert!(
                        matches!(response, super::super::Response::Error(Status::Other)),
                        "algorithm={algorithm} existing={existing} fault={fault:?}"
                    );
                    assert!(session.auth_response.is_none());
                    let view = workspace.classic_with(&memory);
                    assert!(
                        view.key
                            .bytes
                            .iter()
                            .chain(view.input.iter())
                            .chain(view.output.iter())
                            .all(|b| *b == 0x00)
                    );
                }
                let events = trace.borrow();
                assert_eq!(events[0], "stage");
                let committed = matches!(fault, Fault::None | Fault::Uncertain);
                assert_eq!(disk.group != old, committed);
                assert!(disk.stage.is_empty());
                if let Some(at) = events.iter().position(|e| *e == "commit") {
                    assert!(events[..at].contains(&"signed"));
                    if algorithm != -7 {
                        assert_eq!(crypto.opens, 2);
                    }
                }
                if fault != Fault::None {
                    assert_eq!(events.last(), Some(&"abort"));
                }
            }
        }
    }
}
