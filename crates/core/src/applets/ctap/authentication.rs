// SPDX-License-Identifier: Apache-2.0
//! Credential authorization and signing. All request bytes are owned before entry.
use super::wire::{assertion_response, auth_data, make_response, pin_protocol};
use super::{credential, credential_request::Parameters, pin, resident, Session, Status};
use crate::{
    ports::{alg, KeyOperation, Platform},
    runtime::workspace::Workspace,
};
use canokey_ctap::{authorization, session::Boundary};
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
        let mut selected = None;
        let mut user_slot = None;
        for id in params.ids() {
            if !credential::permitted_id(id) {
                continue;
            }
            if id[1] & resident::RESIDENT != 0 {
                let Some((index, _)) = resident::find(id, &rp, w.input, p)? else {
                    continue;
                };
                user_slot = Some(index);
            } else {
                user_slot = None;
            }
            match credential::open(id, self.sm2, &rp, w.key, p) {
                Ok(_) if id[1] & credential::CRED_PROTECT_MASK != 3 || uv => {
                    selected = Some(*id);
                    break;
                }
                Ok(_) | Err(Status::NoCredentials) => (),
                Err(error) => return Err(error),
            }
        }
        let mut count = 0u8;
        if !params.make && !params.list_present {
            let mut next = crate::ports::Record::CTAP_CREDENTIALS;
            while let Some((index, id)) = resident::discover(&mut next, &rp, uv, w.input, p)? {
                count += 1;
                if selected.is_none() {
                    selected = Some(id);
                    user_slot = Some(index);
                }
            }
        }
        p.memory.wipe(&mut w.key.bytes);
        if params.make && selected.is_some() {
            return match self.credential_presence(w, p) {
                Err(Status::Cancelled) => Err(Status::Cancelled),
                _ => Err(Status::CredentialExcluded),
            };
        }
        if !params.make && selected.is_none() {
            return Err(Status::NoCredentials);
        }
        if params.up {
            self.credential_presence(w, p)?;
            // Presence consumes permissions except LBW. Silent assertions
            // retain authorization for subsequent interactive assertions.
            self.permissions = canokey_ctap::client_pin::token::after_presence(
                u16::from(self.permissions),
                u16::from(pin::PERMISSION_LARGE_BLOB_WRITE),
            ) as u8;
            if self.permissions == 0 {
                self.clear_token(p.memory);
            }
        }
        if let Some(hmac) = &params.hmac {
            self.prepare_hmac(hmac, w, p)?;
        }
        if !params.make {
            self.assertion.rp = rp;
            self.assertion.client_hash = params.client_hash;
            self.assertion.next = user_slot.unwrap_or(0);
            self.assertion.remaining = count.saturating_sub(1);
            self.assertion.uv = uv;
            self.assertion.up = params.up;
            self.assertion.get_cred_blob = params.get_cred_blob;
            self.assertion.third_party_payment = params.third_party_payment;
            return self.sign_assertion(
                &selected.ok_or(Status::NoCredentials)?,
                user_slot,
                count,
                count > 1,
                w,
                p,
            );
        }
        let algorithm = params.algorithm.ok_or(Status::UnsupportedAlgorithm)?;
        let id = credential::create(
            algorithm,
            params.protection
                | if params.third_party_payment {
                    credential::THIRD_PARTY_PAYMENT
                } else {
                    0
                }
                | if params.large_blob_key {
                    resident::LARGE_BLOB_KEY
                } else {
                    0
                }
                | if params.resident {
                    resident::RESIDENT
                } else {
                    0
                },
            self.sm2,
            &rp,
            w.key,
            p,
        )?;
        if params.resident {
            // Preserve the ECC private/public view (or PQ seed) needed by respond.
            // The unused RSA tail holds the other three resident members.
            const COPY_OFFSET: usize =
                crate::ports::key_layout::ECC_PUBLIC + crate::ports::key_layout::ECC_PUBLIC_BYTES;
            const {
                assert!(crate::ports::key_layout::SIZE - COPY_OFFSET >= resident::COPY_BYTES);
            }
            resident::store(
                params,
                &id,
                &rp,
                w.output,
                (&mut w.key.bytes[COPY_OFFSET..COPY_OFFSET + resident::COPY_BYTES])
                    .try_into()
                    .unwrap(),
                p,
            )?;
        }
        respond(
            &Signing {
                id: &id,
                rp: &rp,
                client_hash: &params.client_hash,
                algorithm,
                sm2: self.sm2,
                make: true,
                up: params.up,
                uv,
                user_slot: None,
                count: 0,
                details: false,
                min_pin_length,
                hmac_secret: params.hmac_secret,
                hmac: &self.assertion.hmac,
                cred_blob: params.cred_blob_len.map(|n| params.resident && n <= 32),
                get_cred_blob: params.get_cred_blob,
                third_party_payment: params.third_party_payment,
                protection: params.protection_requested.then_some(params.protection),
            },
            w,
            p,
            &mut self.auth_response,
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
    w.input[..32].copy_from_slice(request.rp);
    w.input[auth_data::FLAGS_OFFSET] = if request.up { auth_data::UP } else { 0 }
        | if request.uv { auth_data::UV } else { 0 }
        | if request.make { auth_data::AT } else { 0 };
    w.input[auth_data::COUNTER_OFFSET..auth_data::HEADER_BYTES].copy_from_slice(&counter);
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
    let mut prefix = 0;
    let mut certificate = None;
    let encoded = (|| {
        e.map(
            3 + u64::from(user.is_some()) + u64::from(request.count > 1) + u64::from(has_blob_key),
        );
        if request.make {
            e.encoded(&super::encoding::MAKE_HEADER[1..]);
        } else {
            e.u8(assertion_response::CREDENTIAL);
            super::encoding::descriptor(&mut e, request.id)?;
            e.u8(assertion_response::AUTH_DATA);
        }
        e.bytes_len(auth_len as u64);
        prefix = crate::runtime::workspace::OUTPUT_BYTES - e.writer().len();
        e.u8(if request.make {
            make_response::ATTESTATION
        } else {
            assertion_response::SIGNATURE
        });
        if request.make {
            if self_attest {
                e.encoded(super::encoding::SELF_ATTESTATION)
                    .i32(credential::cose_algorithm(request.algorithm, request.sm2))
                    .str("sig");
            } else {
                e.encoded(super::encoding::ATTESTATION);
            }
        }
        e.bytes(&signature[..n]);
        if request.make && !self_attest {
            e.encoded(super::encoding::CERTIFICATE)
                .bytes_len(cert_len as u64);
            certificate = Some((
                crate::runtime::workspace::OUTPUT_BYTES - e.writer().len(),
                cert_len,
            ));
        }
        if let Some(user) = &user {
            e.u8(assertion_response::USER);
            super::encoding::user(&mut e, user, request.uv && request.details)?;
        }
        if request.count > 1 {
            e.u8(assertion_response::COUNT).u8(request.count);
        }
        if has_blob_key {
            e.u8(if request.make {
                make_response::LARGE_BLOB_KEY
            } else {
                assertion_response::LARGE_BLOB_KEY
            })
            .bytes(&blob_key);
        }
        e.finish()
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
    auth[auth_data::HEADER_BYTES..auth_data::CREDENTIAL_LENGTH_OFFSET]
        .copy_from_slice(&super::provision::AAGUID);
    auth[auth_data::CREDENTIAL_LENGTH_OFFSET..auth_data::CREDENTIAL_OFFSET]
        .copy_from_slice(&(credential::ID_BYTES as u16).to_be_bytes());
    auth[auth_data::CREDENTIAL_OFFSET..auth_data::CREDENTIAL_OFFSET + credential::ID_BYTES]
        .copy_from_slice(id);
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
    let extensions = u64::from(request.protection.is_some())
        + u64::from(request.min_pin_length.is_some())
        + u64::from(request.cred_blob.is_some() || request.get_cred_blob)
        + u64::from(request.hmac_secret)
        + u64::from(request.hmac.active())
        + u64::from(!request.make && request.third_party_payment);
    if extensions != 0 {
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
        {
            e.map(extensions);
            if let Some(accepted) = request.cred_blob {
                e.str("credBlob").bool(accepted);
            } else if request.get_cred_blob {
                e.str("credBlob").bytes(&blob[..blob_len]);
            }
            if let Some(protection) = request.protection {
                e.str("credProtect").u8(protection);
            }
            if request.hmac_secret {
                e.str("hmac-secret").bool(true);
            }
            if !request.make && hmac_len != 0 {
                e.str("hmac-secret").bytes(&hmac_output[..hmac_len]);
            }
            if let Some(minimum) = request.min_pin_length {
                e.str("minPinLength").u8(minimum);
            }
            if request.make && hmac_len != 0 {
                e.str("hmac-secret-mc").bytes(&hmac_output[..hmac_len]);
            }
            if !request.make && request.third_party_payment {
                e.str("thirdPartyPayment")
                    .bool(request.id[1] & credential::THIRD_PARTY_PAYMENT != 0);
            }
        }
        e.finish().map_err(|_| Status::Other)?;
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
    e.map(3 + u64::from(user.is_some()) + u64::from(request.count > 1) + u64::from(has_blob_key));
    e.u8(assertion_response::CREDENTIAL);
    super::encoding::descriptor(&mut e, request.id).map_err(|_| Status::Other)?;
    e.u8(assertion_response::AUTH_DATA)
        .bytes_len(auth_len as u64)
        .finish()
        .map_err(|_| Status::Other)?;
    let prefix = crate::runtime::workspace::OUTPUT_BYTES - e.writer().len();
    let mut tail = Encoder::new(&mut w.output[prefix..]);
    tail.u8(assertion_response::SIGNATURE)
        .bytes_len(params.signature_bytes as u64);
    let signature_at = crate::runtime::workspace::OUTPUT_BYTES - tail.writer().len();
    if let Some(user) = &user {
        tail.u8(assertion_response::USER);
        super::encoding::user(&mut tail, user, request.uv && request.details)
            .map_err(|_| Status::Other)?;
    }
    if request.count > 1 {
        tail.u8(assertion_response::COUNT).u8(request.count);
    }
    if has_blob_key {
        let mut key = [0; 32];
        credential::large_blob_key(request.id, request.rp, &mut key, p)?;
        tail.u8(assertion_response::LARGE_BLOB_KEY).bytes(&key);
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
    e.map(3 + u64::from(has_blob_key))
        .encoded(&super::encoding::MAKE_HEADER[1..])
        .bytes_len((auth_prefix_len + params.public_bytes + extension_len) as u64);
    e.finish().map_err(|_| Status::Other)?;
    let auth_start = crate::runtime::workspace::OUTPUT_BYTES - e.writer().len();
    w.output[auth_start..auth_start + auth_prefix].copy_from_slice(&w.input[..auth_prefix]);
    attested_header(&mut w.output[auth_start..], request.id);
    let cose_at = auth_start + auth_data::CREDENTIAL_OFFSET + credential::ID_BYTES;
    let public_at = cose_at + cose_prefix_len;
    w.output[cose_at..public_at].copy_from_slice(&cose[..cose_prefix_len]);
    w.output[public_at..public_at + extension_len].copy_from_slice(&w.input[auth_prefix..auth_end]);
    let mut tail = Encoder::new(&mut w.output[public_at + extension_len..]);
    tail.u8(make_response::ATTESTATION)
        .encoded(super::encoding::ATTESTATION);
    tail.finish().map_err(|_| Status::Other)?;
    // Stream::attest inserts the encoded DER signature here, exactly once.
    let signature_at = crate::runtime::workspace::OUTPUT_BYTES - tail.writer().len();
    tail.encoded(super::encoding::CERTIFICATE)
        .bytes_len(cert_len as u64);
    tail.finish().map_err(|_| Status::Other)?;
    let cert_at = crate::runtime::workspace::OUTPUT_BYTES - tail.writer().len();
    if has_blob_key {
        let mut key = [0; 32];
        credential::large_blob_key(request.id, request.rp, &mut key, p)?;
        tail.u8(make_response::LARGE_BLOB_KEY).bytes(&key);
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
