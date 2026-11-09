// SPDX-License-Identifier: Apache-2.0
//! Credential authorization and signing. All request bytes are owned before entry.
use super::wire::{auth_data, pin_protocol};
use super::{Session, Status, credential, credential_request::Parameters, pin, resident};
use crate::{
    ports::{KeyOperation, Platform, alg},
    runtime::workspace::Workspace,
};
use canokey_ctap::response::credential::{self as reply, Body, Envelope, Fields};
use canokey_ctap::{authorization, session::Boundary};

mod selection;
use canokey_ports::{Crypto as _, Device as _, Memory as _};
// Two 33-byte positive INTEGERs plus DER tags/lengths.
const MAX_ECDSA_SIGNATURE_BYTES: usize = 72;
use canokey_protocol::{cbor::Encoder, der::der_signature};

impl Session {
    #[inline(never)]
    pub(super) fn credential(
        &mut self,
        params: Option<&Parameters>,
        w: &mut Workspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<usize, Status> {
        let result = match params {
            Some(params) => self.credential_inner(params, w, p),
            None => self.next_assertion(w, p),
        };
        if result.is_err() || self.assertion.remaining == 0 {
            self.assertion.hmac.clear(p.memory);
        }
        p.memory.wipe(&mut w.key.bytes);
        if result.is_err() {
            p.memory.wipe(w.input);
            self.assertion.remaining = 0;
            p.memory.wipe(w.output);
        }
        result
    }
    #[inline(never)]
    fn credential_inner(
        &mut self,
        params: &Parameters,
        w: &mut Workspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<usize, Status> {
        if params.make && params.algorithm.is_none() {
            return Err(Status::UnsupportedAlgorithm);
        }
        let mut policy = [0; pin::RECORD_BYTES];
        pin::load(p, &mut policy)?;
        let pin_set = policy[pin::PIN_LENGTH] != 0;
        let always_uv = policy[pin::FLAGS] & pin::ALWAYS_UV != 0;

        let mut rp = [0; 32];
        let hash_result = p.crypto.sha256(&params.rp[..params.rp_len], &mut rp);
        let min_pin_length = (params.make
            && params.min_pin_length
            && policy[pin::RP_HASHES
                ..pin::RP_HASHES
                    + usize::from(policy[pin::FLAGS] >> pin::RP_HASH_COUNT_SHIFT) * 32]
                .chunks_exact(32)
                .any(|allowed| allowed == rp))
        .then_some(policy[pin::MIN_PIN_LENGTH]);
        p.memory.wipe(&mut policy);
        hash_result.map_err(|_| Status::Other)?;
        let uv = authorization::authorize(
            &authorization::Request {
                make: params.make,
                up: params.up,
                uv: params.uv,
                resident: params.resident,
                auth_length: params.auth_len,
                secret: params.hmac.is_some(),
                large_blob_key: params.large_blob_key,
            },
            authorization::Profile {
                secret_order: authorization::SecretOrder::AfterEmptyAuthentication,
                // The streamed schema rejects rk on GetAssertion before entry.
                reject_assertion_resident: false,
            },
            &mut CredentialAuthorization {
                session: self,
                parameters: params,
                workspace: w,
                platform: p,
                rp: &rp,
                pin_set,
                always_uv,
            },
        )
        .map_err(authorization_error)?
        .is_some();
        canokey_ctap::selection::execute(
            params.make,
            params.up,
            selection::Operation {
                session: self,
                params,
                workspace: w,
                platform: p,
                rp: &rp,
                uv,
                min_pin_length,
                selected: None,
                user_slot: None,
                count: 0,
            },
        )
    }
    fn next_assertion(
        &mut self,
        w: &mut Workspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<usize, Status> {
        if self.assertion.remaining == 0
            || !self
                .assertion
                .continuation
                .accepts(&(), p.device.now(), Boundary::AfterLimit)
        {
            return Err(Status::NotAllowed);
        }
        let (index, id) = resident::discover(
            &mut self.assertion.next,
            &self.assertion.rp,
            self.assertion.uv,
            w.input,
            p,
        )?
        .ok_or(Status::NoCredentials)?;
        self.assertion.remaining -= 1;
        self.sign_assertion(&id, Some(index), 0, true, w, p)
    }
    // Both initial and continued assertions use this exact key-open/sign path.
    #[inline(never)]
    fn sign_assertion(
        &mut self,
        id: &credential::Id,
        user_slot: Option<u8>,
        count: u8,
        details: bool,
        w: &mut Workspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<usize, Status> {
        let algorithm = credential::open(id, self.sm2, &self.assertion.rp, w.key, p)?;
        self.assertion.continuation.refresh((), p.device.now());
        respond(
            &Signing {
                id,
                rp: &self.assertion.rp,
                client_hash: &self.assertion.client_hash,
                algorithm,
                sm2: self.sm2,
                make: false,
                up: self.assertion.up,
                uv: self.assertion.uv,
                user_slot,
                count,
                details,
                protection: None,
                min_pin_length: None,
                hmac_secret: false,
                hmac: &self.assertion.hmac,
                cred_blob: None,
                get_cred_blob: self.assertion.get_cred_blob,
                third_party_payment: self.assertion.third_party_payment,
            },
            w,
            p,
            &mut self.auth_response,
        )
    }
    fn credential_presence(
        &mut self,
        w: &mut Workspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<(), Status> {
        self.selection(w, p).map(|_| ()).map_err(|error| {
            if error == Status::UserActionTimeout {
                Status::OperationDenied
            } else {
                error
            }
        })
    }
}

// The adapter lends the active session/workspace only for the synchronous
// presence probe or existing token check. Policy and RP were validated above.
struct CredentialAuthorization<'a, 'p, 'w, B: crate::ports::Backends> {
    session: &'a mut Session,
    parameters: &'a Parameters,
    workspace: &'a mut Workspace<'w>,
    platform: &'a mut Platform<'p, B>,
    rp: &'a [u8; 32],
    pin_set: bool,
    always_uv: bool,
}
impl<B: crate::ports::Backends> authorization::Backend for CredentialAuthorization<'_, '_, '_, B> {
    type Error = Status;
    type Authorization = ();
    fn policy(&mut self) -> Result<authorization::Policy, Status> {
        Ok(authorization::Policy {
            pin_set: self.pin_set,
            always_uv: self.always_uv,
        })
    }
    fn presence(&mut self) -> Result<(), Status> {
        self.session
            .credential_presence(self.workspace, self.platform)
    }
    fn verify(&mut self) -> Result<(), Status> {
        let params = self.parameters;
        self.session.authorize(
            params.protocol,
            &params.auth[..params.auth_len.unwrap()],
            &params.client_hash,
            if params.make {
                pin_protocol::PERMISSION_MAKE
            } else {
                pin_protocol::PERMISSION_ASSERT
            },
            Some(self.rp),
            self.platform,
        )
    }
}
fn authorization_error(error: authorization::Error<Status>) -> Status {
    match error {
        authorization::Error::Backend(status) => status,
        authorization::Error::Rule(rule) => match rule {
            authorization::RuleError::PinInvalid => Status::PinInvalid,
            authorization::RuleError::PinNotSet => Status::PinNotSet,
            authorization::RuleError::UnsupportedOption => Status::UnsupportedOption,
            authorization::RuleError::InvalidOption => Status::InvalidOption,
            authorization::RuleError::PuatRequired => Status::PuatRequired,
        },
    }
}

struct Signing<'a> {
    id: &'a credential::Id,
    rp: &'a [u8; 32],
    client_hash: &'a [u8; 32],
    algorithm: u8,
    sm2: super::settings::Sm2,
    make: bool,
    up: bool,
    uv: bool,
    user_slot: Option<u8>,
    count: u8,
    details: bool,
    protection: Option<u8>,
    min_pin_length: Option<u8>,
    hmac_secret: bool,
    hmac: &'a super::hmac_secret::Prepared,
    cred_blob: Option<bool>,
    get_cred_blob: bool,
    third_party_payment: bool,
}
fn respond(
    request: &Signing<'_>,
    w: &mut Workspace,
    p: &mut Platform<'_, impl crate::ports::Backends>,
    response: &mut Option<super::Response>,
) -> Result<usize, Status> {
    let counter = credential::counter(p)?;
    auth_data::header(
        w.input,
        request.rp,
        &counter,
        request.up,
        request.uv,
        request.make,
    );
    let mut auth_len = auth_data::HEADER_BYTES;
    if request.make {
        if crate::ports::mldsa::parameters(request.algorithm).is_some() {
            return respond_mldsa_make(request, w, p, response, auth_len);
        }
        let n = p
            .crypto
            .key_operation(
                KeyOperation::Public,
                request.algorithm,
                &mut w.key,
                &[],
                w.output,
            )
            .unwrap_or_default();
        if n != credential::public_length(request.algorithm) {
            return Err(Status::Other);
        }
        attested_header(&mut w.input[..], request.id);
        auth_len = auth_data::CREDENTIAL_OFFSET + credential::ID_BYTES;
        let tail = &mut w.input[auth_len..];
        let mut e = Encoder::new(tail);
        super::encoding::public_key(&mut e, request.algorithm, request.sm2, &w.output[..n])
            .map_err(|_| Status::Other)?;
        // The encoder retains a suffix of the fixed input workspace.
        auth_len = crate::runtime::workspace::INPUT_BYTES.wrapping_sub(e.writer().len());
    }
    auth_len = append_extensions(request, w, p, auth_len)?;
    if !request.make && crate::ports::mldsa::parameters(request.algorithm).is_some() {
        return respond_mldsa_assertion(request, w, p, response, auth_len);
    }
    let mut self_attest = false;
    let cert_len = if request.make {
        let certificate = canokey_ctap::ports::Attestation::certificate_length(
            &mut super::adapter::Attestation(p.storage),
        );
        let mut attestation_key = [0; 32];
        let key = super::attestation::key(&mut attestation_key, p);
        let result = (|| {
            let cert_len = match (key, certificate) {
                (Ok(()), Ok(n)) if n != 0 && n <= super::provision::CERT_LIMIT => n,
                (
                    Ok(()) | Err(crate::ports::StorageError::Missing),
                    Err(crate::ports::StorageError::Missing),
                )
                | (Err(crate::ports::StorageError::Missing), Ok(_)) => {
                    self_attest = true;
                    0
                }
                _ => {
                    // I/O failure or malformed key material is not an unprovisioned
                    // device. Clear even partially supplied private bytes on error.
                    return Err(Status::Other);
                }
            };
            if !self_attest {
                p.memory.wipe(&mut w.key.bytes);
                w.key.bytes[..32].copy_from_slice(&attestation_key);
            }
            Ok(cert_len)
        })();
        p.memory.wipe(&mut attestation_key);
        result?
    } else {
        0
    };
    let sign_algorithm = if request.make && !self_attest {
        alg::P256
    } else {
        request.algorithm
    };
    // append_extensions returns a cursor within INPUT_BYTES (544), so the
    // 32-byte client hash cannot overflow usize. Slice checks still bound it.
    let message_end = auth_len.wrapping_add(32);
    w.input[auth_len..message_end].copy_from_slice(request.client_hash);
    let mut digest = [0; 32];
    let message = if sign_algorithm == alg::P256 {
        p.crypto
            .sha256(&w.input[..message_end], &mut digest)
            .unwrap_or_default();
        &digest[..]
    } else if sign_algorithm == alg::SM2 {
        let n = p
            .crypto
            .key_operation(
                KeyOperation::Sm2MessageDigest,
                alg::SM2,
                &mut w.key,
                &w.input[..message_end],
                w.output,
            )
            .unwrap_or_default();
        if n != 32 {
            return Err(Status::Other);
        }
        digest.copy_from_slice(&w.output[..32]);
        &digest[..]
    } else {
        &w.input[..message_end]
    };
    let n = p
        .crypto
        .key_operation(
            KeyOperation::EcSign,
            sign_algorithm,
            &mut w.key,
            message,
            w.output,
        )
        .unwrap_or_default();
    if n != 64 {
        return Err(Status::Other);
    }
    let n = if sign_algorithm == alg::P256 {
        der_signature(w.output, n).unwrap_or_default()
    } else {
        n
    };
    let mut signature = [0; MAX_ECDSA_SIGNATURE_BYTES];
    signature[..n].copy_from_slice(&w.output[..n]);
    p.memory.wipe(&mut w.key.bytes);
    let has_blob_key = request.id[1] & resident::LARGE_BLOB_KEY != 0;
    let mut blob_key = [0; 32];
    let user = load_user(request.user_slot, &mut w.key.bytes, p)?;
    if has_blob_key {
        credential::large_blob_key(request.id, request.rp, &mut blob_key, p)?;
    }
    w.output[0] = 0;
    let mut e = Encoder::new(&mut w.output[1..]);
    let envelope = Envelope {
        make: request.make,
        id: request.id,
        user: user.is_some(),
        count: request.count,
        blob_key: has_blob_key.then_some(&blob_key[..]),
    };
    let mut prefix = 0;
    let mut certificate = None;
    let encoded = (|| {
        prefix = crate::runtime::workspace::OUTPUT_BYTES
            - reply::start(&mut e, &envelope, Body::External(auth_len))?;
        certificate = reply::statement(
            &mut e,
            request.make,
            self_attest.then(|| credential::cose_algorithm(request.algorithm, request.sm2)),
            &signature[..n],
            (cert_len != 0).then_some(Body::External(cert_len)),
        )?
        .map(|remaining| {
            (
                crate::runtime::workspace::OUTPUT_BYTES - remaining,
                cert_len,
            )
        });
        reply::tail(&mut e, &envelope, |e| {
            super::encoding::user(e, user.as_ref().unwrap(), request.uv && request.details)
        })
        .map_err(|_| canokey_protocol::cbor::EncodeError)
    })();
    p.memory.wipe(&mut blob_key);
    encoded.map_err(|_| Status::Other)?;
    // Each term is bounded by its workspace or the validated CERT_LIMIT.
    let total = (crate::runtime::workspace::OUTPUT_BYTES - e.writer().len())
        .wrapping_add(auth_len)
        .wrapping_add(cert_len);
    *response = Some(super::Response::Authentication {
        registration: false,
        prefix,
        auth: auth_len,
        certificate,
        total,
    });
    Ok(total)
}

/// Attested credential data header after rpIdHash/flags/counter: AAGUID,
/// credential ID length and ID. `auth` starts at the authenticator data.
// These two helpers stay out of line to share code across classic and ML-DSA.
#[inline(never)]
fn attested_header(auth: &mut [u8], id: &[u8]) {
    auth_data::attested(auth, &super::provision::AAGUID, id);
}

/// Load and decode the selected resident record into `out`, if any.
/// The returned entry borrows `out`; no credential or key is copied by value.
#[inline(never)]
fn load_user<'a>(
    slot: Option<u8>,
    out: &'a mut [u8],
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<Option<resident::Entry<'a>>, Status> {
    let Some(index) = slot else {
        return Ok(None);
    };
    let n = resident::load(index, out, p)?.ok_or(Status::NoCredentials)?;
    resident::decode(&out[..n]).map(Some)
}

fn append_extensions(
    request: &Signing<'_>,
    w: &mut Workspace,
    p: &mut Platform<'_, impl crate::ports::Backends>,
    mut auth_len: usize,
) -> Result<usize, Status> {
    let fields = canokey_ctap::response::extensions::Fields {
        make: request.make,
        protection: request.protection,
        min_pin_length: request.min_pin_length,
        cred_blob: request.cred_blob,
        get_cred_blob: request.get_cred_blob,
        hmac_secret: request.hmac_secret,
        hmac: request.hmac.active(),
        third_party_payment: request.third_party_payment,
    };
    if fields.count() != 0 {
        w.input[auth_data::FLAGS_OFFSET] |= auth_data::ED;
        let mut blob = [0; 32];
        let mut blob_len = 0;
        if request.get_cred_blob {
            if let Some(entry) = load_user(request.user_slot, w.output, p)? {
                blob_len = entry.blob.len();
                blob[..blob_len].copy_from_slice(entry.blob);
            }
        }
        let mut hmac_output = [0; 80];
        let hmac_len = if request.hmac.active() {
            request
                .hmac
                .output(request.id, request.rp, request.uv, &mut hmac_output, p)?
        } else {
            0
        };
        let mut e = Encoder::new(&mut w.input[auth_len..]);
        fields
            .encode(&mut e, &blob[..blob_len], &hmac_output[..hmac_len], || {
                request.id[1] & credential::THIRD_PARTY_PAYMENT != 0
            })
            .map_err(|_| Status::Other)?;
        // The encoder only consumes this suffix; its remainder cannot exceed
        // INPUT_BYTES, and subtracting it gives the absolute cursor directly.
        auth_len = crate::runtime::workspace::INPUT_BYTES.wrapping_sub(e.writer().len());
    }
    Ok(auth_len)
}

fn respond_mldsa_assertion(
    request: &Signing<'_>,
    w: &mut Workspace,
    p: &mut Platform<'_, impl crate::ports::Backends>,
    response: &mut Option<super::Response>,
    auth_len: usize,
) -> Result<usize, Status> {
    let params = crate::ports::mldsa::parameters(request.algorithm).ok_or(Status::Other)?;
    let has_blob_key = request.id[1] & resident::LARGE_BLOB_KEY != 0;
    w.input[auth_len..auth_len + 32].copy_from_slice(request.client_hash);
    w.input[auth_len + 32..auth_len + 64].copy_from_slice(&w.key.bytes[..32]);
    let user = load_user(request.user_slot, &mut w.key.bytes, p)?;
    w.output[0] = 0;
    let mut e = Encoder::new(&mut w.output[1..]);
    reply::start_fields(
        &mut e,
        Fields {
            make: false,
            user: user.is_some(),
            count: request.count,
            blob_key: has_blob_key,
        },
        request.id,
        Body::External(auth_len),
    )
    .map_err(|_| Status::Other)?;
    e.finish().map_err(|_| Status::Other)?;
    let prefix = crate::runtime::workspace::OUTPUT_BYTES - e.writer().len();
    let mut tail = Encoder::new(&mut w.output[prefix..]);
    let signature_at = crate::runtime::workspace::OUTPUT_BYTES
        - reply::signature_header(&mut tail, params.signature_bytes);
    reply::tail_fields(&mut tail, user.is_some(), request.count, |e| {
        super::encoding::user(e, user.as_ref().unwrap(), request.uv && request.details)
    })
    .map_err(|_| Status::Other)?;
    if has_blob_key {
        let mut key = [0; 32];
        credential::large_blob_key(request.id, request.rp, &mut key, p)?;
        reply::blob_key(&mut tail, false, &key);
        p.memory.wipe(&mut key);
    }
    tail.finish().map_err(|_| Status::Other)?;
    let output = crate::runtime::workspace::OUTPUT_BYTES - tail.writer().len();
    *response = Some(super::Response::Pending(super::pq::Pending {
        algorithm: request.algorithm,
        mode: super::pq::Mode::Assert,
        prefix,
        auth: auth_len,
        public_at: 0,
        // The generated signature follows the key-3 byte-string header.  `prefix`
        // points at the start of that header, so inserting at it would place the
        // signature before its own CBOR length prefix.
        signature_at,
        certificate: None,
        output,
        hash_prefix: (prefix, auth_len),
        hash_suffix: (prefix, auth_len),
    }));
    Ok(output + auth_len + params.signature_bytes)
}

fn respond_mldsa_make(
    request: &Signing<'_>,
    w: &mut Workspace,
    p: &mut Platform<'_, impl crate::ports::Backends>,
    response: &mut Option<super::Response>,
    auth_prefix: usize,
) -> Result<usize, Status> {
    let params = crate::ports::mldsa::parameters(request.algorithm).ok_or(Status::Other)?;
    let cert_len = super::attestation::certificate(p)?;
    // Extensions are encoded once for classic and streamed keys. The large
    // public key is spliced between the COSE header and these extension bytes.
    let auth_end = append_extensions(request, w, p, auth_prefix)?;
    let extension_len = auth_end - auth_prefix;
    let mut cose = [0u8; 32];
    let mut ce = Encoder::new(&mut cose[..]);
    super::encoding::mldsa_public_header(&mut ce, request.algorithm).map_err(|_| Status::Other)?;
    let cose_prefix_len = 32 - ce.writer().len();
    let auth_prefix_len = auth_data::CREDENTIAL_OFFSET + credential::ID_BYTES + cose_prefix_len;
    let has_blob_key = request.id[1] & resident::LARGE_BLOB_KEY != 0;
    w.output[0] = 0;
    let mut e = Encoder::new(&mut w.output[1..]);
    reply::start_fields(
        &mut e,
        Fields {
            make: true,
            user: false,
            count: 0,
            blob_key: has_blob_key,
        },
        request.id,
        Body::External(auth_prefix_len + params.public_bytes + extension_len),
    )
    .map_err(|_| Status::Other)?;
    e.finish().map_err(|_| Status::Other)?;
    let auth_start = crate::runtime::workspace::OUTPUT_BYTES - e.writer().len();
    w.output[auth_start..auth_start + auth_prefix].copy_from_slice(&w.input[..auth_prefix]);
    attested_header(&mut w.output[auth_start..], request.id);
    let cose_at = auth_start + auth_data::CREDENTIAL_OFFSET + credential::ID_BYTES;
    let public_at = cose_at + cose_prefix_len;
    w.output[cose_at..public_at].copy_from_slice(&cose[..cose_prefix_len]);
    w.output[public_at..public_at + extension_len].copy_from_slice(&w.input[auth_prefix..auth_end]);
    let mut tail = Encoder::new(&mut w.output[public_at + extension_len..]);
    reply::statement_prefix(&mut tail, true, None).map_err(|_| Status::Other)?;
    tail.finish().map_err(|_| Status::Other)?;
    // Stream::attest inserts the encoded DER signature here, exactly once.
    let signature_at = crate::runtime::workspace::OUTPUT_BYTES - tail.writer().len();
    reply::certificate_body(&mut tail, Body::External(cert_len));
    tail.finish().map_err(|_| Status::Other)?;
    let cert_at = crate::runtime::workspace::OUTPUT_BYTES - tail.writer().len();
    if has_blob_key {
        let mut key = [0; 32];
        credential::large_blob_key(request.id, request.rp, &mut key, p)?;
        reply::blob_key(&mut tail, true, &key);
        p.memory.wipe(&mut key);
    }
    tail.finish().map_err(|_| Status::Other)?;
    let output = crate::runtime::workspace::OUTPUT_BYTES - tail.writer().len();
    w.input[..32].copy_from_slice(request.client_hash);
    w.input[32..64].copy_from_slice(&w.key.bytes[..32]);
    *response = Some(super::Response::Pending(super::pq::Pending {
        algorithm: request.algorithm,
        mode: super::pq::Mode::Make,
        prefix: auth_start,
        auth: 0,
        public_at,
        signature_at,
        certificate: Some((cert_at, cert_len)),
        output,
        hash_prefix: (auth_start, auth_prefix_len),
        hash_suffix: (public_at, extension_len),
    }));
    Ok(output + params.public_bytes + cert_len)
}
