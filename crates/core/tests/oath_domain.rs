#![cfg(feature = "oath")]
// SPDX-License-Identifier: Apache-2.0
//! Normal service flows. OpenSSL supplies real host HMAC primitives; no device
//! or legacy applet is used and no boundary/fault/fuzz campaign is run.
use canokey_rust_core::applets::oath::{
    Algorithm, Crypto, Error, auth, codec,
    credential::{Credential, Kind, Properties},
    service::{self, CredentialId, Presence, Repository},
};
use std::{
    io::Write,
    process::{Command, Stdio},
};
#[derive(Default)]
struct Primitives {
    random: u8,
}
impl Crypto for Primitives {
    fn hmac(
        &mut self,
        algorithm: Algorithm,
        key: &[u8],
        input: &[u8],
        out: &mut [u8; 64],
    ) -> Result<(), Error> {
        let flag = match algorithm {
            Algorithm::Sha1 => "-sha1",
            Algorithm::Sha256 => "-sha256",
            Algorithm::Sha512 => "-sha512",
        };
        let key = key.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let mut child = Command::new("openssl")
            .args([
                "dgst",
                flag,
                "-mac",
                "HMAC",
                "-macopt",
                &format!("hexkey:{key}"),
                "-binary",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(result.status.success());
        assert_eq!(result.stdout.len(), algorithm.digest_length());
        out.fill(0);
        out[..result.stdout.len()].copy_from_slice(&result.stdout);
        Ok(())
    }
    fn random(&mut self, out: &mut [u8]) -> Result<(), Error> {
        self.random += 1;
        out.fill(self.random);
        Ok(())
    }
    fn wipe(&mut self, bytes: &mut [u8]) {
        bytes.fill(0);
    }
}
#[derive(Default)]
struct Store {
    rows: Vec<Option<Vec<u8>>>,
    writes: usize,
}
impl Repository for Store {
    fn first(&mut self) -> Result<Option<CredentialId>, Error> {
        self.next(CredentialId(0))
    }
    fn next(&mut self, id: CredentialId) -> Result<Option<CredentialId>, Error> {
        Ok(self
            .rows
            .iter()
            .enumerate()
            .skip(id.0 as usize)
            .find(|(_, row)| row.is_some())
            .map(|(i, _)| CredentialId(i as u32 + 1)))
    }
    fn load(&mut self, id: CredentialId) -> Result<Credential, Error> {
        codec::decode(
            self.rows
                .get(id.0 as usize - 1)
                .and_then(Option::as_ref)
                .ok_or(Error::Missing)?,
        )
    }
    fn insert(&mut self, value: &Credential) -> Result<CredentialId, Error> {
        let mut bytes = [0; codec::LENGTH];
        let n = codec::encode(value, &mut bytes);
        self.rows.push(Some(bytes[..n].to_vec()));
        self.writes += 1;
        Ok(CredentialId(self.rows.len() as u32))
    }
    fn replace(&mut self, id: CredentialId, value: &Credential) -> Result<(), Error> {
        let mut bytes = [0; codec::LENGTH];
        let n = codec::encode(value, &mut bytes);
        self.rows[id.0 as usize - 1] = Some(bytes[..n].to_vec());
        self.writes += 1;
        Ok(())
    }
    fn delete(&mut self, id: CredentialId) -> Result<(), Error> {
        self.rows[id.0 as usize - 1] = None;
        self.writes += 1;
        Ok(())
    }
}
#[derive(Default)]
struct AuthStore(Option<Vec<u8>>);
impl auth::Repository for AuthStore {
    fn load(&mut self) -> Result<Option<auth::Metadata>, Error> {
        self.0
            .as_ref()
            .map(|b| auth::Metadata::decode(b))
            .transpose()
    }
    fn replace(&mut self, value: &auth::Metadata) -> Result<(), Error> {
        let mut bytes = [0; auth::METADATA_LENGTH];
        let n = value.encode(&mut bytes);
        self.0 = Some(bytes[..n].to_vec());
        Ok(())
    }
}
fn credential(
    name: &[u8],
    key: &[u8],
    kind: Kind,
    algorithm: Algorithm,
    properties: u8,
) -> Credential {
    Credential::new(
        name,
        key,
        kind,
        algorithm,
        8,
        Properties::new(properties).unwrap(),
        [0; 8],
    )
    .unwrap()
}
#[test]
fn hotp_preserves_c_preincrement_and_persistence() {
    let mut store = Store::default();
    let mut crypto = Primitives::default();
    let record = Credential::new(
        b"counter",
        b"12345678901234567890",
        Kind::Hotp,
        Algorithm::Sha1,
        6,
        Properties::new(0).unwrap(),
        [0; 8],
    )
    .unwrap();
    let id = service::put(&mut store, &mut crypto, &record).unwrap();
    // RFC 4226 counters 1 and 2: C increments before computing (not counter 0).
    for (counter, expected) in [(1, 287082), (2, 359152)] {
        let mut digest =
            service::calculate(&mut store, &mut crypto, id, &[], Presence::NotConfirmed).unwrap();
        assert_eq!(digest.digits(), 6);
        assert_eq!(digest.truncated() % 1_000_000, expected);
        assert_eq!(
            store.load(id).unwrap().moving_factor(),
            u64::to_be_bytes(counter)
        );
        digest.clear(&mut crypto);
    }
    assert_eq!(store.writes, 3);
}
#[test]
fn totp_rfc6238_all_existing_algorithms() {
    let mut store = Store::default();
    let mut crypto = Primitives::default();
    for (alg, key, expected) in [
        (Algorithm::Sha1, &b"12345678901234567890"[..], 94287082),
        (
            Algorithm::Sha256,
            &b"12345678901234567890123456789012"[..],
            46119246,
        ),
        (
            Algorithm::Sha512,
            &b"1234567890123456789012345678901234567890123456789012345678901234"[..],
            90693936,
        ),
    ] {
        let record = credential(&[alg as u8], key, Kind::Totp, alg, 0);
        let id = service::put(&mut store, &mut crypto, &record).unwrap();
        let mut result = service::calculate(
            &mut store,
            &mut crypto,
            id,
            &1u64.to_be_bytes(),
            Presence::NotConfirmed,
        )
        .unwrap();
        assert_eq!(result.bytes().len(), alg.digest_length());
        assert_eq!(result.truncated() % 100_000_000, expected);
        result.clear(&mut crypto);
    }
    assert_eq!(store.writes, 3); // Ordinary TOTP calculations do not write counters.
}
#[test]
fn increasing_challenge_and_confirmed_touch() {
    let mut store = Store::default();
    let mut crypto = Primitives::default();
    let record = credential(
        b"touch",
        b"12345678901234567890",
        Kind::Totp,
        Algorithm::Sha1,
        3,
    );
    let id = service::put(&mut store, &mut crypto, &record).unwrap();
    for value in [1u64, 1, 2] {
        // C accepts an equal challenge; the requirement is nondecreasing.
        let mut result = service::calculate(
            &mut store,
            &mut crypto,
            id,
            &value.to_be_bytes(),
            Presence::Confirmed,
        )
        .unwrap();
        assert_eq!(store.load(id).unwrap().moving_factor(), value.to_be_bytes());
        result.clear(&mut crypto);
    }
}
#[test]
fn naming_enumeration_and_explicit_codec_reload() {
    let mut store = Store::default();
    let mut crypto = Primitives::default();
    let first = service::put(
        &mut store,
        &mut crypto,
        &credential(b"first", b"secret", Kind::Hotp, Algorithm::Sha1, 0),
    )
    .unwrap();
    let second = service::put(
        &mut store,
        &mut crypto,
        &credential(b"second", b"secret", Kind::Totp, Algorithm::Sha256, 0),
    )
    .unwrap();
    service::rename(&mut store, &mut crypto, b"first", b"renamed").unwrap();
    assert_eq!(
        service::find(&mut store, &mut crypto, b"renamed").unwrap(),
        first
    );
    assert_eq!(store.first().unwrap(), Some(first));
    assert_eq!(store.next(first).unwrap(), Some(second));
    store.delete(first).unwrap();
    assert_eq!(store.first().unwrap(), Some(second));
    let loaded = store.load(second).unwrap();
    assert_eq!(loaded.name(), b"second");
    assert_eq!(loaded.algorithm(), Algorithm::Sha256);
}
#[test]
fn access_code_select_validate_clear_and_reset() {
    let mut repository = AuthStore::default();
    let mut crypto = Primitives::default();
    auth::install(&mut repository, &mut crypto).unwrap();
    let mut session = auth::Session::default();
    let first = session.select(&mut repository, &mut crypto).unwrap();
    assert!(first.challenge.is_none());
    assert!(session.authorized());
    let key = [0x42; 16];
    let host_challenge = b"hostdata";
    let mut expected = [0; 64];
    crypto
        .hmac(Algorithm::Sha1, &key, host_challenge, &mut expected)
        .unwrap();
    session
        .set_code(
            &mut repository,
            &mut crypto,
            &key,
            host_challenge,
            expected[..20].try_into().unwrap(),
        )
        .unwrap();
    assert!(!session.authorized());
    session.reset(&mut crypto);
    let selected = session.select(&mut repository, &mut crypto).unwrap();
    assert_eq!(first.handle, selected.handle);
    let mut response = [0; 64];
    crypto
        .hmac(
            Algorithm::Sha1,
            &key,
            &selected.challenge.unwrap(),
            &mut response,
        )
        .unwrap();
    let mut output = [0; 20];
    session
        .validate(
            &mut repository,
            &mut crypto,
            response[..20].try_into().unwrap(),
            host_challenge,
            &mut output,
        )
        .unwrap();
    assert!(session.authorized());
    assert_eq!(output, expected[..20]);
    session.clear_code(&mut repository, &mut crypto).unwrap();
    session.reset(&mut crypto);
    auth::install(&mut repository, &mut crypto).unwrap();
    assert!(
        session
            .select(&mut repository, &mut crypto)
            .unwrap()
            .challenge
            .is_none()
    );
}
