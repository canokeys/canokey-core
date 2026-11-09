// SPDX-License-Identifier: Apache-2.0
//! Credential authorization and signing. All request bytes are owned before entry.
use super::wire::{auth_data, pin_protocol};
use super::{Session, Status, credential, credential_request::Parameters, pin, resident};
use crate::{
    ports::{KeyOperation, Platform, alg},
    runtime::workspace::Workspace,
};
use canokey_ctap::response::credential::{self as reply, Body, Envelope};
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
    let built = construct_auth_data(request, &counter, w, p)?;
    let auth_len = match built {
        auth_data::Constructed::Complete(length) => length,
        auth_data::Constructed::ExternalPublic => {
            return respond_mldsa_make(request, w, p, response, auth_data::HEADER_BYTES);
        }
    };
    if !request.make && crate::ports::mldsa::parameters(request.algorithm).is_some() {
        return respond_mldsa_assertion(request, w, p, response, auth_len);
    }
    canokey_ctap::attestation::execute(
        request.make,
        canokey_ctap::attestation::Unprovisioned::SignCredential,
        ClassicResponse {
            request,
            workspace: w,
            platform: p,
            response,
            auth_len,
        },
    )
    .map(|output| output.unwrap())
}

// Only existing loans cross the shared material/sign/response stages. The
// outlined key-read capability and temporary key erasure precede signing.
struct ClassicResponse<'a, 'r, 'w, 'p, B: crate::ports::Backends> {
    request: &'a Signing<'r>,
    workspace: &'a mut Workspace<'w>,
    platform: &'a mut Platform<'p, B>,
    response: &'a mut Option<super::Response>,
    auth_len: usize,
}
impl<B: crate::ports::Backends> canokey_ctap::attestation::Backend
    for ClassicResponse<'_, '_, '_, '_, B>
{
    type Error = Status;
    type Signature = usize;
    type Output = usize;
    #[inline(always)]
    fn select(&mut self) -> Result<usize, Status> {
        let w = &mut *self.workspace;
        let p = &mut *self.platform;
        let mut attestation_key = [0x00; canokey_ctap::provision::PRIVATE_KEY_BYTES];
        let selected = canokey_ctap::provision::select(
            &mut super::attestation::Material(p),
            &mut attestation_key,
            super::provision::CERT_LIMIT,
            canokey_ctap::provision::Selection::MissingEither,
        );
        let result = (|| {
            let cert_len = selected.map_err(|_| Status::Other)?;
            if cert_len != 0 {
                p.memory.wipe(&mut w.key.bytes);
                w.key.bytes[..canokey_ctap::provision::PRIVATE_KEY_BYTES]
                    .copy_from_slice(&attestation_key);
            }
            Ok(cert_len)
        })();
        p.memory.wipe(&mut attestation_key);
        result
    }
    #[inline(always)]
    fn sign(&mut self, statement: canokey_ctap::attestation::Statement) -> Result<usize, Status> {
        let request = self.request;
        let w = &mut *self.workspace;
        let p = &mut *self.platform;
        let auth_len = self.auth_len;
        let sign_algorithm = if statement.provisioned() {
            alg::P256
        } else {
            request.algorithm
        };
        // append_extensions returns a cursor within INPUT_BYTES (544), so the
        // 32-byte client hash cannot overflow usize. Slice checks still bound it.
        let message_end = auth_len.wrapping_add(canokey_ctap::signing::DIGEST_BYTES);
        w.input[auth_len..message_end].copy_from_slice(request.client_hash);
        let algorithm = match sign_algorithm {
            alg::P256 => canokey_ctap::signing::Algorithm::Es256,
            alg::SM2 => canokey_ctap::signing::Algorithm::Sm2,
            _ => canokey_ctap::signing::Algorithm::Ed25519,
        };
        canokey_ctap::signing::sign(
            algorithm,
            ClassicSigning {
                algorithm: sign_algorithm,
                message_end,
                workspace: w,
                platform: p,
            },
        )
    }
    #[inline(always)]
    fn respond(
        self,
        statement: canokey_ctap::attestation::Statement,
        n: usize,
    ) -> Result<usize, Status> {
        let Self {
            request,
            workspace: w,
            platform: p,
            response,
            auth_len,
        } = self;
        let cert_len = statement.certificate_length();
        let self_attest = matches!(
            statement,
            canokey_ctap::attestation::Statement::SelfAttestation
        );
        let mut signature = [0x00; MAX_ECDSA_SIGNATURE_BYTES];
        signature[..n].copy_from_slice(&w.output[..n]);
        p.memory.wipe(&mut w.key.bytes);
        let has_blob_key = request.id[1] & resident::LARGE_BLOB_KEY != 0x00;
        let mut blob_key = [0x00; canokey_ctap::signing::DIGEST_BYTES];
        let user = load_user(request.user_slot, &mut w.key.bytes, p)?;
        if has_blob_key {
            credential::large_blob_key(request.id, request.rp, &mut blob_key, p)?;
        }
        w.output[0] = 0x00;
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
                self_attest
                    .then(|| credential::classic_cose_algorithm(request.algorithm, request.sm2)),
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
}

// The shared engine borrows the already concatenated workspace transcript.
// Preserve primitive failure mapping and SM2's exact digest-length check.
struct ClassicSigning<'a, 'w, 'p, B: crate::ports::Backends> {
    algorithm: u8,
    message_end: usize,
    workspace: &'a mut Workspace<'w>,
    platform: &'a mut Platform<'p, B>,
}
impl<B: crate::ports::Backends> canokey_ctap::signing::Primitive for ClassicSigning<'_, '_, '_, B> {
    type Error = Status;
    type Signature = usize;
    #[inline(always)]
    fn digest(
        &mut self,
        algorithm: canokey_ctap::signing::Algorithm,
        output: &mut [u8; 32],
    ) -> Result<(), Status> {
        let w = &mut self.workspace;
        if algorithm == canokey_ctap::signing::Algorithm::Es256 {
            self.platform
                .crypto
                .sha256(&w.input[..self.message_end], output)
                .unwrap_or_default();
        } else {
            let length = self
                .platform
                .crypto
                .key_operation(
                    KeyOperation::Sm2MessageDigest,
                    alg::SM2,
                    &mut w.key,
                    &w.input[..self.message_end],
                    w.output,
                )
                .unwrap_or_default();
            if length != canokey_ctap::signing::DIGEST_BYTES {
                return Err(Status::Other);
            }
            output.copy_from_slice(&w.output[..canokey_ctap::signing::DIGEST_BYTES]);
        }
        Ok(())
    }
    #[inline(always)]
    fn sign(&mut self, digest: Option<&[u8; 32]>) -> Result<usize, Status> {
        let w = &mut self.workspace;
        let message = match digest {
            Some(digest) => &digest[..],
            None => &w.input[..self.message_end],
        };
        Ok(self
            .platform
            .crypto
            .key_operation(
                KeyOperation::EcSign,
                self.algorithm,
                &mut w.key,
                message,
                w.output,
            )
            .unwrap_or_default())
    }
    #[inline(always)]
    fn length(&self, signature: &usize) -> usize {
        *signature
    }
    #[inline(always)]
    fn invalid_signature() -> Status {
        Status::Other
    }
}
impl<B: crate::ports::Backends> canokey_ctap::signing::Backend for ClassicSigning<'_, '_, '_, B> {
    #[inline(always)]
    fn der(&mut self, signature: usize) -> Result<usize, Status> {
        Ok(der_signature(self.workspace.output, signature).unwrap_or_default())
    }
    #[inline(always)]
    fn raw(&mut self, signature: usize) -> Result<usize, Status> {
        Ok(signature)
    }
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

#[inline(always)]
fn extension_fields(request: &Signing<'_>) -> canokey_ctap::response::extensions::Fields {
    canokey_ctap::response::extensions::Fields {
        make: request.make,
        protection: request.protection,
        min_pin_length: request.min_pin_length,
        cred_blob: request.cred_blob,
        get_cred_blob: request.get_cred_blob,
        hmac_secret: request.hmac_secret,
        hmac: request.hmac.active(),
        third_party_payment: request.third_party_payment,
    }
}

#[inline(always)]
fn construct_auth_data(
    request: &Signing<'_>,
    counter: &[u8; 4],
    w: &mut Workspace,
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<auth_data::Constructed, Status> {
    auth_data::construct(
        auth_data::Construction {
            rp: request.rp,
            counter,
            up: request.up,
            uv: request.uv,
            make: request.make,
        },
        AuthData {
            request,
            workspace: w,
            platform: p,
        },
    )
}

struct AuthData<'a, 'r, 'p, 'w, B: crate::ports::Backends> {
    request: &'a Signing<'r>,
    workspace: &'a mut Workspace<'w>,
    platform: &'a mut Platform<'p, B>,
}
impl<B: crate::ports::Backends> auth_data::Constructor for AuthData<'_, '_, '_, '_, B> {
    type Error = Status;
    type Public = usize;
    type Extensions = canokey_ctap::response::extensions::Fields;
    #[inline(always)]
    fn data(&mut self) -> &mut [u8] {
        self.workspace.input
    }
    #[inline(always)]
    fn prepare_public(&mut self) -> Result<usize, Status> {
        let length = self
            .platform
            .crypto
            .key_operation(
                KeyOperation::Public,
                self.request.algorithm,
                self.workspace.key,
                &[],
                self.workspace.output,
            )
            .unwrap_or_default();
        if length != credential::classic_public_length(self.request.algorithm) {
            return Err(Status::Other);
        }
        Ok(length)
    }
    #[inline(always)]
    fn attested(&mut self) -> usize {
        // Share the existing out-of-line helper with PQ framing.
        attested_header(self.workspace.input, self.request.id);
        auth_data::CREDENTIAL_OFFSET + credential::ID_BYTES
    }
    #[inline(always)]
    fn public(&mut self, cursor: usize, length: usize) -> Result<usize, Status> {
        let capacity = crate::runtime::workspace::INPUT_BYTES;
        let mut e = Encoder::new(&mut self.workspace.input[cursor..]);
        super::encoding::public_key(
            &mut e,
            self.request.algorithm,
            self.request.sm2,
            &self.workspace.output[..length],
        )
        .map_err(|_| Status::Other)?;
        Ok(capacity.wrapping_sub(e.writer().len()))
    }
    #[inline(always)]
    fn external_public(&self) -> bool {
        crate::ports::mldsa::parameters(self.request.algorithm).is_some()
    }
    #[inline(always)]
    fn prepare_extensions(&self) -> Option<Self::Extensions> {
        let fields = extension_fields(self.request);
        (fields.count() != 0).then_some(fields)
    }
    #[inline(always)]
    fn extensions(&mut self, cursor: usize, fields: Self::Extensions) -> Result<usize, Status> {
        append_extensions(self.request, self.workspace, self.platform, cursor, fields)
    }
    #[inline(always)]
    fn append_extensions(self, cursor: usize) -> Result<usize, Status> {
        auth_data::extend::<Self>(self.platform, self.request, self.workspace, cursor)
    }
}

impl<'r, 'p, 'w, B: crate::ports::Backends> auth_data::ExtensionConstructor
    for AuthData<'_, 'r, 'p, 'w, B>
{
    type Request = Signing<'r>;
    type Workspace = Workspace<'w>;
    type Platform = Platform<'p, B>;
    type Prepared = canokey_ctap::response::extensions::Fields;
    type Error = Status;
    #[inline(always)]
    fn prepare(request: &Signing<'r>) -> Self::Prepared {
        extension_fields(request)
    }
    #[inline(always)]
    fn present(fields: &Self::Prepared) -> bool {
        fields.count() != 0
    }
    #[inline(always)]
    fn data(workspace: &mut Self::Workspace) -> &mut [u8] {
        workspace.input
    }
    #[inline(always)]
    fn encode(
        request: &Signing<'r>,
        workspace: &mut Self::Workspace,
        platform: &mut Self::Platform,
        cursor: usize,
        fields: Self::Prepared,
    ) -> Result<usize, Status> {
        append_extensions(request, workspace, platform, cursor, fields)
    }
}

#[inline(always)]
fn append_extensions(
    request: &Signing<'_>,
    w: &mut Workspace,
    p: &mut Platform<'_, impl crate::ports::Backends>,
    mut auth_len: usize,
    fields: canokey_ctap::response::extensions::Fields,
) -> Result<usize, Status> {
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
    let capacity = crate::runtime::workspace::INPUT_BYTES;
    let mut e = Encoder::new(&mut w.input[auth_len..]);
    fields
        .encode(&mut e, &blob[..blob_len], &hmac_output[..hmac_len], || {
            request.id[1] & credential::THIRD_PARTY_PAYMENT != 0
        })
        .map_err(|_| Status::Other)?;
    // The encoder only consumes this suffix; its remainder cannot exceed
    // INPUT_BYTES, and subtracting it gives the absolute cursor directly.
    auth_len = capacity.wrapping_sub(e.writer().len());
    Ok(auth_len)
}

struct PqConstruction<'r, 'p, 'w, B: crate::ports::Backends>(
    core::marker::PhantomData<(&'r (), Platform<'p, B>, Workspace<'w>)>,
);
impl<'r, 'p, 'w, B: crate::ports::Backends> canokey_ctap::streaming::reply::Construction
    for PqConstruction<'r, 'p, 'w, B>
{
    type Request = Signing<'r>;
    type Workspace = Workspace<'w>;
    type Platform = Platform<'p, B>;
    type Error = Status;
    #[inline(always)]
    fn invalid() -> Status {
        Status::Other
    }
    #[inline(always)]
    fn fields<'a>(
        request: &'a Signing<'r>,
    ) -> canokey_ctap::streaming::reply::CredentialFields<'a> {
        canokey_ctap::streaming::reply::CredentialFields {
            id: request.id,
            client_hash: request.client_hash,
            algorithm: request.algorithm,
            count: request.count,
            details: request.uv && request.details,
            blob_key: request.id[1] & resident::LARGE_BLOB_KEY != 0,
        }
    }
    #[inline(always)]
    fn buffers<'a>(
        workspace: &'a mut Workspace<'w>,
    ) -> canokey_ctap::streaming::reply::Buffers<'a> {
        canokey_ctap::streaming::reply::Buffers {
            key: &mut workspace.key.bytes,
            input: workspace.input,
            output: workspace.output,
        }
    }
    #[inline(always)]
    fn certificate(platform: &mut Platform<'p, B>) -> Result<usize, Status> {
        super::attestation::certificate(platform)
    }
    #[inline(always)]
    fn extensions(
        platform: &mut Platform<'p, B>,
        request: &Signing<'r>,
        workspace: &mut Workspace<'w>,
        cursor: usize,
    ) -> Result<usize, Status> {
        auth_data::extend::<AuthData<'_, 'r, 'p, 'w, B>>(platform, request, workspace, cursor)
    }
    #[inline(always)]
    fn user<'a>(
        request: &Signing<'r>,
        key: &'a mut [u8],
        platform: &mut Platform<'p, B>,
    ) -> Result<Option<resident::Entry<'a>>, Status> {
        load_user(request.user_slot, key, platform)
    }
    #[inline(always)]
    fn blob_key(
        request: &Signing<'r>,
        output: &mut [u8; canokey_ctap::credential::KEY_BYTES],
        platform: &mut Platform<'p, B>,
    ) -> Result<(), Status> {
        credential::large_blob_key(request.id, request.rp, output, platform)
    }
    #[inline(always)]
    fn wipe(platform: &Platform<'p, B>, bytes: &mut [u8]) {
        platform.memory.wipe(bytes);
    }
    #[inline(always)]
    fn attested(output: &mut [u8], id: &credential::Id) {
        attested_header(output, id);
    }
}

fn respond_mldsa_assertion(
    request: &Signing<'_>,
    w: &mut Workspace,
    p: &mut Platform<'_, impl crate::ports::Backends>,
    response: &mut Option<super::Response>,
    auth_len: usize,
) -> Result<usize, Status> {
    let (plan, length) = canokey_ctap::streaming::reply::assertion::<PqConstruction<'_, '_, '_, _>>(
        p, request, w, auth_len,
    )?;
    *response = Some(super::Response::Pending(plan));
    Ok(length)
}

fn respond_mldsa_make(
    request: &Signing<'_>,
    w: &mut Workspace,
    p: &mut Platform<'_, impl crate::ports::Backends>,
    response: &mut Option<super::Response>,
    auth_prefix: usize,
) -> Result<usize, Status> {
    let (plan, length) = canokey_ctap::streaming::reply::make::<PqConstruction<'_, '_, '_, _>>(
        p,
        request,
        w,
        auth_prefix,
    )?;
    *response = Some(super::Response::Pending(plan));
    Ok(length)
}
