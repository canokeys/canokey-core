// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::ports::*;
use crate::runtime::workspace::SessionWorkspace;

struct Forbidden;
impl Storage for Forbidden {
    fn load(&mut self, _: Record, _: &mut [u8]) -> Result<usize, StorageError> {
        panic!("rejected request read policy");
    }
    fn replace(&mut self, _: Record, _: &[u8]) -> Result<(), StorageError> {
        panic!("rejected request wrote storage");
    }
}
impl Crypto for Forbidden {
    fn sha256(&mut self, _: &[u8], _: &mut [u8; 32]) -> Result<(), CryptoError> {
        panic!("rejected request hashed RP");
    }
    fn mac(&mut self, _: u8, _: &[u8], _: &[u8], _: &mut [u8; 64]) -> Result<(), CryptoError> {
        panic!("rejected request authenticated token");
    }
    fn random(&mut self, _: &mut [u8]) -> Result<(), CryptoError> {
        panic!("rejected request generated key material");
    }
    fn hmac_sha1(&mut self, _: &[u8; 20], _: &[u8], _: &mut [u8; 20]) {
        panic!("rejected request used crypto");
    }
}
impl Device for Forbidden {
    fn serial(&mut self, _: &mut [u8; 4]) {
        panic!("rejected request read device");
    }
    fn now(&mut self) -> u32 {
        panic!("rejected request entered timer");
    }
    fn touched(&mut self) -> bool {
        panic!("rejected request checked presence");
    }
    fn progress(&mut self) -> bool {
        panic!("rejected request entered progress");
    }
    fn led(&mut self, _: bool) {
        panic!("rejected request prompted presence");
    }
}

#[test]
fn silent_secret_rejection_precedes_policy_rp_crypto_and_probe_with_outer_erasure() {
    for auth_length in [None, Some(0), Some(16), Some(32)] {
        let mut bytes = [0x00; 128];
        let mut encoder = Encoder::new(&mut bytes[..]);
        encoder
            .map(3)
            .u8(0x01)
            .str("x")
            .u8(0x02)
            .bytes(&[0x42; 32])
            .u8(0x05)
            .map(1)
            .str("up")
            .bool(false)
            .finish()
            .unwrap();
        let length = 128 - encoder.writer().len();
        let mut parser = super::super::credential_request::Parser::new(false);
        parser.consume(&bytes[..length]);
        let Ok(super::super::Command::Credential(mut params)) = parser.finish() else {
            panic!("valid silent assertion schema");
        };
        params.hmac = Some(canokey_ctap::request::hmac_secret::Parameters::new());
        params.auth_len = auth_length;
        let mut session = Session::new();
        session
            .pin
            .token
            .with_secret_mut(|secret| secret.fill(0x55));
        session.pin.commit_agreement();
        let mut backing = SessionWorkspace::new();
        let workspace = backing.classic();
        workspace.input.fill(0xa5);
        workspace.output.fill(0xa5);
        workspace.key.bytes.fill(0xa5);
        assert_eq!(
            session.credential(
                Some(&params),
                &mut backing,
                &mut Platform::<canokey_ports::BackendTypes<_, _, _, _>> {
                    storage: &mut Forbidden,
                    crypto: &mut Forbidden,
                    device: &mut Forbidden,
                    memory: &canokey_ports::default_memory(),
                }
            ),
            Err(Status::UnsupportedOption)
        );
        let workspace = backing.classic();
        assert!(
            workspace
                .input
                .iter()
                .chain(workspace.output.iter())
                .chain(workspace.key.bytes.iter())
                .all(|byte| *byte == 0x00)
        );
        assert!(session.pin.agreement_ready());
        assert_eq!(session.pin.token.with_secret(|secret| *secret), [0x55; 32]);
    }
}
