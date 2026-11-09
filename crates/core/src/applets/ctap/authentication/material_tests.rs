// SPDX-License-Identifier: Apache-2.0
extern crate std;
use super::*;
use crate::ports::*;
use crate::runtime::workspace::SessionWorkspace;
use canokey_ctap::attestation::Backend as _;
use std::{cell::RefCell, vec, vec::Vec};

const PRIVATE_BYTES: usize = canokey_ctap::provision::PRIVATE_KEY_BYTES;
const KEY_BYTE: u8 = 0x37;
const WORKSPACE_BYTE: u8 = 0xa5;
struct Store {
    certificate: Result<usize, StorageError>,
    key: Result<usize, StorageError>,
    events: Vec<&'static str>,
    counter_writes: usize,
}
impl Store {
    fn new(certificate: Result<usize, StorageError>, key: Result<usize, StorageError>) -> Self {
        Self {
            certificate,
            key,
            events: Vec::new(),
            counter_writes: 0,
        }
    }
}
impl Storage for Store {
    fn size(&mut self, record: Record) -> Result<u32, StorageError> {
        assert_eq!(record, Record::CtapCertificate);
        self.events.push("certificate");
        self.certificate.map(|length| length as u32)
    }
    fn load(&mut self, record: Record, output: &mut [u8]) -> Result<usize, StorageError> {
        match record {
            Record::CtapAttestationKey => {
                self.events.push("key");
                output.fill(KEY_BYTE);
                self.key
            }
            Record::CtapPin | Record::CtapCounter | Record::CtapSm2 => Err(StorageError::Missing),
            Record::CtapMaster => {
                output.copy_from_slice(&[0x69; PRIVATE_BYTES]);
                Ok(PRIVATE_BYTES)
            }
            _ => panic!("unexpected material-selection read: {record:?}"),
        }
    }
    fn replace(&mut self, record: Record, _: &[u8]) -> Result<(), StorageError> {
        // Ordinary nonresident registration still reserves a counter before
        // material selection. This fixture does not model a resident commit.
        assert_eq!(record, Record::CtapCounter);
        self.counter_writes += 1;
        Ok(())
    }
}
#[derive(Default)]
struct Primitives {
    signs: usize,
}
impl Crypto for Primitives {
    fn sha256(&mut self, _: &[u8], out: &mut [u8; 32]) -> Result<(), CryptoError> {
        out.fill(0x31);
        Ok(())
    }
    fn mac(
        &mut self,
        algorithm: u8,
        _: &[u8],
        _: &[u8],
        out: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        assert_eq!(algorithm, 0x02); // Native HMAC-SHA-256 selector.
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
        operation: KeyOperation,
        algorithm: u8,
        _: &mut KeyMaterial,
        _: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        assert_eq!(algorithm, alg::P256);
        match operation {
            KeyOperation::Public => {
                output[..64].fill(0x44);
                Ok(64)
            }
            KeyOperation::EcSign => {
                self.signs += 1;
                panic!("material rejection must precede signing")
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
#[derive(Default)]
struct Wipes(RefCell<Vec<Vec<u8>>>);
impl Memory for Wipes {
    fn wipe(&self, output: &mut [u8]) {
        self.0.borrow_mut().push(output.to_vec());
        output.fill(0x00);
    }
}

#[test]
fn classic_material_owner_admits_certificate_before_reading_key_and_erases_temporary_key() {
    for certificate in [
        Ok(0),
        Ok(1),
        Ok(super::super::provision::CERT_LIMIT),
        Ok(super::super::provision::CERT_LIMIT + 1),
        Err(StorageError::Missing),
        Err(StorageError::Unavailable),
        Err(StorageError::Uncertain),
    ] {
        for key in [
            Ok(0),
            Ok(PRIVATE_BYTES - 1),
            Ok(PRIVATE_BYTES),
            Ok(PRIVATE_BYTES + 1),
            Err(StorageError::Missing),
            Err(StorageError::Unavailable),
            Err(StorageError::Uncertain),
        ] {
            let mut store = Store::new(certificate, key);
            let mut crypto = Primitives::default();
            let memory = Wipes::default();
            let mut device = DeviceFixture;
            let mut backing = SessionWorkspace::new();
            let mut workspace = backing.classic();
            workspace.key.bytes.fill(WORKSPACE_BYTE);
            workspace.input.fill(WORKSPACE_BYTE);
            workspace.output.fill(WORKSPACE_BYTE);
            let hmac = super::super::hmac_secret::Prepared::new();
            let request = Signing {
                id: &[0x00; credential::ID_BYTES],
                rp: &[0x31; 32],
                client_hash: &[0x42; 32],
                algorithm: alg::P256,
                sm2: super::super::settings::Sm2::DEFAULT,
                make: true,
                up: true,
                uv: false,
                user_slot: None,
                count: 0,
                details: false,
                protection: None,
                min_pin_length: None,
                hmac_secret: false,
                hmac: &hmac,
                cred_blob: None,
                get_cred_blob: false,
                third_party_payment: false,
            };
            let mut response = None;
            let result = ClassicResponse {
                request: &request,
                workspace: &mut workspace,
                platform: &mut Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
                    storage: &mut store,
                    crypto: &mut crypto,
                    device: &mut device,
                    memory: &memory,
                },
                response: &mut response,
                auth_len: 0,
            }
            .select();
            let reads_key = matches!(certificate, Ok(length) if length != 0 && length <= super::super::provision::CERT_LIMIT);
            let expected = match certificate {
                Ok(0) | Err(StorageError::Missing) => Ok(0),
                Ok(length) if reads_key && key == Ok(PRIVATE_BYTES) => Ok(length),
                _ => Err(Status::Other),
            };
            assert_eq!(result, expected);
            assert_eq!(
                store.events,
                if reads_key {
                    vec!["certificate", "key"]
                } else {
                    vec!["certificate"]
                }
            );
            assert_eq!(store.counter_writes, 0);
            assert_eq!(crypto.signs, 0);
            assert!(response.is_none());
            assert!(
                workspace
                    .input
                    .iter()
                    .chain(workspace.output.iter())
                    .all(|byte| *byte == WORKSPACE_BYTE)
            );
            let provisioned = expected.is_ok_and(|length| length != 0);
            if provisioned {
                assert_eq!(
                    &workspace.key.bytes[..PRIVATE_BYTES],
                    &[KEY_BYTE; PRIVATE_BYTES]
                );
                assert!(
                    workspace.key.bytes[PRIVATE_BYTES..]
                        .iter()
                        .all(|byte| *byte == 0x00)
                );
            } else {
                // The selector owns its temporary key. Outer credential cleanup
                // owns the existing credential key on a material error.
                assert!(
                    workspace
                        .key
                        .bytes
                        .iter()
                        .all(|byte| *byte == WORKSPACE_BYTE)
                );
            }
            assert!(memory.0.borrow().iter().any(|bytes| bytes == &[if reads_key { KEY_BYTE } else { 0x00 }; PRIVATE_BYTES]));
        }
    }
}

fn make_parameters() -> Parameters {
    let mut wire = [0x00; 128];
    let mut encoder = Encoder::new(&mut wire[..]);
    // CTAP makeCredential: clientDataHash, RP, user, publicKeyCredParams.
    encoder
        .map(4)
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
        .i32(-7)
        .str("type")
        .str("public-key")
        .finish()
        .unwrap();
    let length = 128 - encoder.writer().len();
    let mut parser = super::super::credential_request::Parser::new(true);
    parser.consume(&wire[..length]);
    let super::super::Command::Credential(params) = parser.finish().unwrap() else {
        unreachable!()
    };
    params
}

#[test]
fn actual_credential_failure_never_signs_or_publishes_and_erases_all_caller_workspace() {
    for (certificate, key, events) in [
        (
            Ok(1),
            Err(StorageError::Missing),
            vec!["certificate", "key"],
        ),
        (Ok(1), Ok(PRIVATE_BYTES - 1), vec!["certificate", "key"]),
        (
            Ok(1),
            Err(StorageError::Unavailable),
            vec!["certificate", "key"],
        ),
        (
            Ok(1),
            Err(StorageError::Uncertain),
            vec!["certificate", "key"],
        ),
        (
            Ok(super::super::provision::CERT_LIMIT + 1),
            Err(StorageError::Missing),
            vec!["certificate"],
        ),
        (
            Err(StorageError::Unavailable),
            Err(StorageError::Missing),
            vec!["certificate"],
        ),
        (
            Err(StorageError::Uncertain),
            Err(StorageError::Missing),
            vec!["certificate"],
        ),
    ] {
        let params = make_parameters();
        let mut store = Store::new(certificate, key);
        let mut crypto = Primitives::default();
        let mut device = DeviceFixture;
        let memory = Wipes::default();
        let mut backing = SessionWorkspace::new();
        let workspace = backing.classic();
        workspace.key.bytes.fill(WORKSPACE_BYTE);
        workspace.input.fill(WORKSPACE_BYTE);
        workspace.output.fill(WORKSPACE_BYTE);
        let mut session = Session::new();
        let response = session.execute(
            &mut Ok(super::super::Command::Credential(params)),
            &mut backing,
            &mut Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
                storage: &mut store,
                crypto: &mut crypto,
                device: &mut device,
                memory: &memory,
            },
        );
        let workspace = backing.classic();
        assert!(matches!(
            response,
            super::super::Response::Error(Status::Other)
        ));
        assert_eq!(store.events, events);
        assert_eq!(store.counter_writes, 1);
        assert_eq!(crypto.signs, 0);
        assert!(session.auth_response.is_none());
        assert!(
            workspace
                .key
                .bytes
                .iter()
                .chain(workspace.input.iter())
                .chain(workspace.output.iter())
                .all(|byte| *byte == 0x00)
        );
    }
}
