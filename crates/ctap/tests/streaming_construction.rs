// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "streaming")]
use canokey_ctap::{
    credential::{ID_BYTES, Id},
    provision::{self, CertificatePolicy},
    resident::Entry,
    response::encoding::Encoder,
    streaming::{
        Framing, Mode,
        reply::{self, Buffers, Construction, CredentialFields},
    },
};
use canokey_ports::{alg, mldsa};
use std::cell::RefCell;

// Fixed WebAuthn header and the existing workspace capacities, in bytes.
const AUTH_BYTES: usize = 37;
const HASH_BYTES: usize = 32;
const SEED_BYTES: usize = 32;
const MATERIAL_BYTES: usize = HASH_BYTES + SEED_BYTES;
const INPUT_BYTES: usize = 544;
const OUTPUT_BYTES: usize = 528;
const KEY_BACKING_BYTES: usize = 512;
// Synthetic resident record: ID, user ID, UTF-8 name/display, then RP hash.
const USER_BYTES: usize = 64;
const USER_AT: usize = ID_BYTES;
const NAME_AT: usize = USER_AT + USER_BYTES;
const DISPLAY_AT: usize = NAME_AT + USER_BYTES;
const RP_AT: usize = DISPLAY_AT + USER_BYTES;
const RECORD_END: usize = RP_AT + HASH_BYTES;
const AAGUID_AT: usize = AUTH_BYTES;
const ID_LENGTH_AT: usize = AAGUID_AT + 16;
const ID_AT: usize = ID_LENGTH_AT + 2;
const CERTIFICATE_LIMIT: usize = 1024;
const CERTIFICATE: &[u8] = b"cert123";
const DER: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
// CTAP extension map {"x": h'ee'}, used as opaque already-encoded authData.
const EXTENSION: &[u8] = &[0xa1, 0x61, 0x78, 0x41, 0xee];
const AAGUID: [u8; 16] = [0xa6; 16];
struct Request {
    id: Id,
    hash: [u8; HASH_BYTES],
    algorithm: u8,
    count: u8,
    details: bool,
    blob: bool,
    user: bool,
    extension: bool,
}
impl Request {
    fn new(algorithm: u8) -> Self {
        Self {
            id: [0x5a; ID_BYTES],
            hash: [0x44; HASH_BYTES],
            algorithm,
            count: 1,
            details: false,
            blob: false,
            user: false,
            extension: false,
        }
    }
}
struct Workspace {
    key: [u8; KEY_BACKING_BYTES],
    input: [u8; INPUT_BYTES],
    output: [u8; OUTPUT_BYTES],
    capacity: usize,
}
impl Workspace {
    fn new() -> Self {
        Self {
            key: [0x55; KEY_BACKING_BYTES],
            input: [0x33; INPUT_BYTES],
            output: [0xa5; OUTPUT_BYTES],
            capacity: OUTPUT_BYTES,
        }
    }
}
struct Platform {
    events: RefCell<Vec<&'static str>>,
    fail: Option<&'static str>,
    certificate_length: usize,
}
impl Platform {
    fn new() -> Self {
        Self {
            events: RefCell::new(Vec::new()),
            fail: None,
            certificate_length: CERTIFICATE.len(),
        }
    }
    fn event(&self, name: &'static str) -> Result<(), &'static str> {
        self.events.borrow_mut().push(name);
        if self.fail == Some(name) {
            Err(name)
        } else {
            Ok(())
        }
    }
}
impl canokey_ctap::ports::Attestation for Platform {
    type Error = &'static str;
    fn key(&mut self, _: &mut [u8; HASH_BYTES]) -> Result<usize, Self::Error> {
        panic!("plan construction must not read an attestation key");
    }
    fn certificate_length(&mut self) -> Result<usize, Self::Error> {
        self.event("certificate")?;
        Ok(self.certificate_length)
    }
}
struct Profile;
impl Construction for Profile {
    type Request = Request;
    type Workspace = Workspace;
    type Platform = Platform;
    type Error = &'static str;
    fn invalid() -> Self::Error {
        "invalid"
    }
    fn fields(request: &Request) -> CredentialFields<'_> {
        CredentialFields {
            id: &request.id,
            client_hash: &request.hash,
            algorithm: request.algorithm,
            count: request.count,
            details: request.details,
            blob_key: request.blob,
        }
    }
    fn buffers(workspace: &mut Workspace) -> Buffers<'_> {
        Buffers {
            key: &mut workspace.key,
            input: &mut workspace.input,
            output: &mut workspace.output[..workspace.capacity],
        }
    }
    fn certificate(platform: &mut Platform) -> Result<usize, Self::Error> {
        provision::certificate_length(platform, CERTIFICATE_LIMIT, CertificatePolicy::Required)
            .map_err(|_| "certificate-length")
    }
    fn extensions(
        platform: &mut Platform,
        request: &Request,
        workspace: &mut Workspace,
        cursor: usize,
    ) -> Result<usize, Self::Error> {
        platform.event("extensions")?;
        if !request.extension {
            return Ok(cursor);
        }
        workspace.input[HASH_BYTES] |= 0x80;
        workspace.input[cursor..cursor + EXTENSION.len()].copy_from_slice(EXTENSION);
        Ok(cursor + EXTENSION.len())
    }
    fn user<'a>(
        request: &Request,
        key: &'a mut [u8],
        platform: &mut Platform,
    ) -> Result<Option<Entry<'a>>, Self::Error> {
        platform.event("user")?;
        if !request.user {
            return Ok(None);
        }
        // Loading the record destroys the private seed in this same backing.
        key.fill(0x4e);
        key[USER_AT..NAME_AT].fill(0x42);
        key[DISPLAY_AT..RP_AT].fill(0x44);
        Ok(Some(Entry {
            id: (&key[..ID_BYTES]).try_into().unwrap(),
            rp_hash: (&key[RP_AT..RECORD_END]).try_into().unwrap(),
            rp: "",
            user: &key[USER_AT..NAME_AT],
            name: std::str::from_utf8(&key[NAME_AT..DISPLAY_AT]).unwrap(),
            display: std::str::from_utf8(&key[DISPLAY_AT..RP_AT]).unwrap(),
            blob: &[],
        }))
    }
    fn blob_key(
        _: &Request,
        output: &mut [u8; HASH_BYTES],
        platform: &mut Platform,
    ) -> Result<(), Self::Error> {
        platform.event("blob")?;
        output.fill(0x77);
        Ok(())
    }
    fn wipe(platform: &Platform, bytes: &mut [u8]) {
        platform.event("wipe").unwrap();
        assert_eq!(bytes, [0x77; HASH_BYTES]);
        bytes.fill(0x00);
    }
    fn attested(output: &mut [u8], id: &Id) {
        // Independent WebAuthn attested credential data: AAGUID16, ID length
        // in big-endian bytes, then ID (WebAuthn section 6.1).
        output[AAGUID_AT..ID_LENGTH_AT].copy_from_slice(&AAGUID);
        output[ID_LENGTH_AT..ID_AT].copy_from_slice(&(ID_BYTES as u16).to_be_bytes());
        output[ID_AT..ID_AT + ID_BYTES].copy_from_slice(id);
    }
}
fn encoded(encode: impl FnOnce(&mut Encoder<&mut [u8]>)) -> Vec<u8> {
    let mut bytes = vec![0x00; 8192];
    let mut encoder = Encoder::new(&mut bytes[..]);
    encode(&mut encoder);
    encoder.finish().unwrap();
    let length = 8192 - encoder.writer().len();
    bytes.truncate(length);
    bytes
}
fn reference(request: &Request, make: bool, auth: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut wire = vec![0x00];
    wire.extend(encoded(|e| {
        e.map(
            3 + u64::from(!make && request.user)
                + u64::from(!make && request.count > 1)
                + u64::from(request.blob),
        )
        .u8(0x01);
        if make {
            e.str("packed");
        } else {
            e.map(2)
                .str("id")
                .bytes(&request.id)
                .str("type")
                .str("public-key");
        }
        e.u8(0x02).bytes(auth).u8(0x03);
        if make {
            e.map(3).str("alg").i8(-7).str("sig");
        }
        e.bytes(signature);
        if make {
            e.str("x5c").array(1).bytes(CERTIFICATE);
        }
        if !make && request.user {
            e.u8(0x04)
                .map(if request.details { 3 } else { 1 })
                .str("id")
                .bytes(&[0x42; USER_BYTES]);
            if request.details {
                e.str("name")
                    .str(&"N".repeat(USER_BYTES))
                    .str("displayName")
                    .str(&"D".repeat(USER_BYTES));
            }
        }
        if !make && request.count > 1 {
            e.u8(0x05).u8(request.count);
        }
        if request.blob {
            e.u8(if make { 0x05 } else { 0x07 })
                .bytes(&[0x77; HASH_BYTES]);
        }
    }));
    wire
}
#[test]
fn assertion_plans_preserve_seed_before_record_reuse_and_full_wire() {
    for algorithm in [alg::MLDSA44, alg::MLDSA65] {
        let params = mldsa::parameters(algorithm).unwrap();
        let signature = vec![0x66; params.signature_bytes];
        for user in [false, true] {
            for details in [false, true] {
                for count in [0, 1, 2, 23, 24, 255] {
                    for blob in [false, true] {
                        let mut request = Request::new(algorithm);
                        request.user = user;
                        request.details = details;
                        request.count = count;
                        request.blob = blob;
                        let expected = reference(&request, false, &[0x33; AUTH_BYTES], &signature);
                        let physical = expected.len() - AUTH_BYTES - signature.len();
                        for capacity in 1..=physical + 1 {
                            let mut workspace = Workspace::new();
                            workspace.capacity = capacity;
                            let mut platform = Platform::new();
                            let result = reply::assertion::<Profile>(
                                &mut platform,
                                &request,
                                &mut workspace,
                                37,
                            );
                            assert!(workspace.output[capacity..].iter().all(|&v| v == 0xa5));
                            assert_eq!(
                                &workspace.input[AUTH_BYTES..AUTH_BYTES + HASH_BYTES],
                                request.hash
                            );
                            assert_eq!(
                                &workspace.input
                                    [AUTH_BYTES + HASH_BYTES..AUTH_BYTES + MATERIAL_BYTES],
                                &[0x55; SEED_BYTES]
                            );
                            if user {
                                assert_eq!(workspace.key[0], 0x4e);
                            }
                            if capacity < physical {
                                assert!(result.is_err());
                                continue;
                            }
                            let (plan, length) = result.unwrap();
                            assert_eq!(
                                *platform.events.borrow(),
                                if blob {
                                    vec!["user", "blob", "wipe"]
                                } else {
                                    vec!["user"]
                                }
                            );
                            assert_eq!(length, expected.len());
                            assert!(matches!(plan.mode, Mode::Assert));
                            assert_eq!(plan.output, physical);
                            assert_eq!(plan.certificate, None);
                            assert_eq!(plan.hash_prefix, (plan.prefix, AUTH_BYTES));
                            assert_eq!(plan.hash_suffix, plan.hash_prefix);
                            let mut wire = workspace.output[..plan.prefix].to_vec();
                            wire.extend_from_slice(&workspace.input[..AUTH_BYTES]);
                            wire.extend_from_slice(
                                &workspace.output[plan.prefix..plan.signature_at],
                            );
                            wire.extend_from_slice(&signature);
                            wire.extend_from_slice(
                                &workspace.output[plan.signature_at..plan.output],
                            );
                            assert_eq!(wire, expected);
                            let mut framing = Framing::new();
                            framing.bytes[..physical]
                                .copy_from_slice(&workspace.output[..physical]);
                            framing
                                .stage(plan, &workspace.input, &canokey_ports::MemoryBackend)
                                .unwrap();
                            assert_eq!(
                                &framing.bytes[plan.prefix..plan.prefix + AUTH_BYTES],
                                &[0x33; AUTH_BYTES]
                            );
                            assert_eq!(&framing.material()[..HASH_BYTES], request.hash);
                            assert_eq!(&framing.material()[HASH_BYTES..], &[0x55; SEED_BYTES]);
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn registration_plans_match_full_wire_and_segmented_hash_transcript() {
    for algorithm in [alg::MLDSA44, alg::MLDSA65] {
        let params = mldsa::parameters(algorithm).unwrap();
        let public = vec![0x88; params.public_bytes];
        for extension in [false, true] {
            for blob in [false, true] {
                let mut request = Request::new(algorithm);
                request.extension = extension;
                request.blob = blob;
                let mut auth = vec![0x33; AUTH_BYTES];
                if extension {
                    auth[HASH_BYTES] |= 0x80;
                }
                auth.extend_from_slice(&AAGUID);
                auth.extend_from_slice(&(ID_BYTES as u16).to_be_bytes());
                auth.extend_from_slice(&request.id);
                auth.extend(encoded(|e| {
                    e.map(3)
                        .u8(0x01)
                        .u8(0x07)
                        .u8(0x03)
                        .i32(params.cose)
                        .i8(-1)
                        .bytes(&public);
                }));
                if extension {
                    auth.extend_from_slice(EXTENSION);
                }
                let expected = reference(&request, true, &auth, DER);
                let mut workspace = Workspace::new();
                let mut platform = Platform::new();
                let (plan, length) =
                    reply::make::<Profile>(&mut platform, &request, &mut workspace, AUTH_BYTES)
                        .unwrap();
                assert!(matches!(plan.mode, Mode::Make));
                assert_eq!(plan.auth, 0);
                assert_eq!(
                    length
                        + encoded(|e| {
                            e.bytes(DER);
                        })
                        .len(),
                    expected.len()
                );
                let (certificate_at, certificate_length) = plan.certificate.unwrap();
                assert_eq!(certificate_length, CERTIFICATE.len());
                let mut wire = workspace.output[..plan.public_at].to_vec();
                wire.extend_from_slice(&public);
                wire.extend_from_slice(&workspace.output[plan.public_at..plan.signature_at]);
                wire.extend(encoded(|e| {
                    e.bytes(DER);
                }));
                wire.extend_from_slice(&workspace.output[plan.signature_at..certificate_at]);
                wire.extend_from_slice(CERTIFICATE);
                wire.extend_from_slice(&workspace.output[certificate_at..plan.output]);
                assert_eq!(wire, expected);
                let mut transcript = workspace.output
                    [plan.hash_prefix.0..plan.hash_prefix.0 + plan.hash_prefix.1]
                    .to_vec();
                transcript.extend_from_slice(&public);
                transcript.extend_from_slice(
                    &workspace.output[plan.hash_suffix.0..plan.hash_suffix.0 + plan.hash_suffix.1],
                );
                assert_eq!(transcript, auth);
                assert_eq!(&workspace.input[..HASH_BYTES], request.hash);
                assert_eq!(
                    &workspace.input[HASH_BYTES..MATERIAL_BYTES],
                    &[0x55; SEED_BYTES]
                );
                assert_eq!(
                    *platform.events.borrow(),
                    if blob {
                        vec!["certificate", "extensions", "blob", "wipe"]
                    } else {
                        vec!["certificate", "extensions"]
                    }
                );
                // Only capacities admitting the fixed authData/COSE copies are
                // internal builder inputs. Check each subsequent tail boundary.
                let fixed_end = plan.public_at + if extension { EXTENSION.len() } else { 0 };
                for capacity in fixed_end..=plan.output + 1 {
                    let mut limited = Workspace::new();
                    limited.capacity = capacity;
                    let mut platform = Platform::new();
                    let result =
                        reply::make::<Profile>(&mut platform, &request, &mut limited, AUTH_BYTES);
                    assert!(limited.output[capacity..].iter().all(|&v| v == 0xa5));
                    if capacity < plan.output {
                        assert!(result.is_err());
                        assert_eq!(&limited.input[..HASH_BYTES], &[0x33; HASH_BYTES]);
                        assert_eq!(limited.key, [0x55; KEY_BACKING_BYTES]);
                    } else {
                        assert!(result.is_ok());
                    }
                }
            }
        }
    }
}
#[test]
fn errors_stop_before_later_io_seed_replacement_or_plan_publication() {
    for algorithm in [alg::MLDSA44, alg::MLDSA65] {
        let mut request = Request::new(algorithm);
        request.user = true;
        request.blob = true;
        request.extension = true;
        for length in [0, CERTIFICATE_LIMIT + 1, usize::MAX] {
            let mut workspace = Workspace::new();
            let mut platform = Platform::new();
            platform.certificate_length = length;
            assert!(
                reply::make::<Profile>(&mut platform, &request, &mut workspace, AUTH_BYTES)
                    .is_err()
            );
            assert_eq!(*platform.events.borrow(), vec!["certificate"]);
            assert_eq!(workspace.input, [0x33; INPUT_BYTES]);
            assert_eq!(workspace.output, [0xa5; OUTPUT_BYTES]);
        }
        for fail in ["certificate", "extensions", "blob"] {
            let mut workspace = Workspace::new();
            let mut platform = Platform::new();
            platform.fail = Some(fail);
            assert!(
                reply::make::<Profile>(&mut platform, &request, &mut workspace, AUTH_BYTES)
                    .is_err()
            );
            assert_eq!(&workspace.input[..HASH_BYTES], &[0x33; HASH_BYTES]);
            assert_eq!(workspace.key, [0x55; KEY_BACKING_BYTES]);
            assert_eq!(platform.events.borrow().last(), Some(&fail));
        }
        let mut workspace = Workspace::new();
        let mut platform = Platform::new();
        platform.fail = Some("user");
        assert!(
            reply::assertion::<Profile>(&mut platform, &request, &mut workspace, AUTH_BYTES)
                .is_err()
        );
        assert_eq!(*platform.events.borrow(), vec!["user"]);
        assert_eq!(workspace.output, [0xa5; OUTPUT_BYTES]);
        assert_eq!(
            &workspace.input[AUTH_BYTES + HASH_BYTES..AUTH_BYTES + MATERIAL_BYTES],
            &[0x55; SEED_BYTES]
        );
        let mut workspace = Workspace::new();
        let mut platform = Platform::new();
        platform.fail = Some("blob");
        assert!(
            reply::assertion::<Profile>(&mut platform, &request, &mut workspace, AUTH_BYTES)
                .is_err()
        );
        assert_eq!(*platform.events.borrow(), vec!["user", "blob"]);
    }
    let mut request = Request::new(alg::P256);
    request.blob = true;
    for make in [false, true] {
        let mut workspace = Workspace::new();
        let mut platform = Platform::new();
        let result = if make {
            reply::make::<Profile>(&mut platform, &request, &mut workspace, AUTH_BYTES)
        } else {
            reply::assertion::<Profile>(&mut platform, &request, &mut workspace, AUTH_BYTES)
        };
        assert!(result.is_err());
        assert!(platform.events.borrow().is_empty());
        assert_eq!(workspace.input, [0x33; INPUT_BYTES]);
        assert_eq!(workspace.output, [0xa5; OUTPUT_BYTES]);
    }
}
