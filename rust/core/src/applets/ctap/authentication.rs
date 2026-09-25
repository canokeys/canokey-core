// SPDX-License-Identifier: Apache-2.0
//! Credential authorization and signing. All request bytes are owned before entry.
use super::{Session, Status, credential, credential_request::Parameters, pin, resident};
use crate::{
    ports::{KeyOperation, Platform, alg},
    runtime::workspace::Workspace,
};
use canokey_protocol::{cbor::Encoder, der::der_signature};

impl Session {
    #[inline(never)]
    pub(super) fn credential(
        &mut self,
        params: &Parameters,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<usize, Status> {
        let result = self.credential_inner(params, w, p);
        if result.is_err() || self.assertion.remaining == 0 {
            self.assertion.hmac.clear(p.memory);
        }
        p.memory.wipe(&mut w.key.bytes);
        if result.is_err() {
            p.memory.wipe(&mut w.input);
            self.assertion.remaining = 0;
            p.memory.wipe(&mut w.output);
        }
        result
    }
    fn credential_inner(
        &mut self,
        params: &Parameters,
        w: &mut Workspace,
        p: &mut Platform<'_>,
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
            && policy[pin::RP_HASHES..pin::RP_HASHES + usize::from(policy[pin::FLAGS] >> 3) * 32]
                .chunks_exact(32)
                .any(|allowed| allowed == rp))
        .then_some(policy[pin::MIN_PIN_LENGTH]);
        p.memory.wipe(&mut policy);
        hash_result.map_err(|_| Status::Other)?;
        if params.auth_len == Some(0) {
            self.credential_presence(w, p)?;
            return Err(if pin_set {
                Status::PinInvalid
            } else {
                Status::PinNotSet
            });
        }
        if !params.make && !params.up && params.hmac.is_some() {
            return Err(Status::UnsupportedOption);
        }
        if params.make && params.large_blob_key && !params.resident {
            return Err(Status::InvalidOption);
        }
        if (params.make && !params.up) || (params.uv && params.auth_len.is_none()) {
            return Err(Status::InvalidOption);
        }
        let uv = if let Some(n) = params.auth_len {
            if !pin_set {
                return Err(Status::PinNotSet);
            }
            self.authorize(
                params.protocol,
                &params.auth[..n],
                &params.client_hash,
                if params.make { 1 } else { 2 },
                Some(&rp),
                p,
            )?;
            true
        } else {
            if always_uv || (pin_set && params.make && params.resident) {
                return Err(Status::PuatRequired);
            }
            false
        };
        let mut selected = None;
        let mut user_slot = None;
        for id in &params.list[..params.list_len] {
            if id[1] & resident::RESIDENT != 0 {
                let Some((index, _)) = resident::find(id, &rp, &mut w.input, p)? else {
                    continue;
                };
                user_slot = Some(index);
            } else {
                user_slot = None;
            }
            match credential::open(id, self.sm2, &rp, w, p) {
                Ok(_) if id[1] & 3 != 3 || uv => {
                    selected = Some(*id);
                    break;
                }
                Ok(_) | Err(Status::NoCredentials) => (),
                Err(error) => return Err(error),
            }
        }
        let mut count = 0;
        if !params.make && !params.list_present {
            for index in 0..crate::ports::Record::CTAP_CREDENTIALS {
                if let Some(n) = resident::load(index, &mut w.input, p)? {
                    let entry = resident::Entry::decode(&w.input[..n])?;
                    if entry.rp_hash == &rp && (uv || entry.id[1] & 3 == 1) {
                        count += 1;
                        if selected.is_none() {
                            selected = Some(*entry.id);
                            user_slot = Some(index);
                        }
                    }
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
        }
        // A credential operation consumes all token permissions except LBW.
        // Future operations must obtain fresh verification/presence as in C.
        self.permissions &= pin::PERMISSION_LARGE_BLOB_WRITE;
        if self.permissions == 0 {
            self.clear_token(p.memory);
        }
        if let Some(hmac) = &params.hmac {
            self.prepare_hmac(hmac, w, p)?;
        }
        let (id, algorithm) = if params.make {
            let algorithm = params.algorithm.ok_or(Status::UnsupportedAlgorithm)?;
            (
                credential::create(
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
                    w,
                    p,
                )?,
                algorithm,
            )
        } else {
            let id = selected.ok_or(Status::NoCredentials)?;
            let algorithm = credential::open(&id, self.sm2, &rp, w, p)?;
            (id, algorithm)
        };
        if params.make && params.resident {
            resident::store(params, &id, &rp, &mut w.output, p)?;
        }
        if !params.make && count > 1 {
            self.assertion = resident::Assertion {
                rp,
                client_hash: params.client_hash,
                next: user_slot.unwrap() + 1,
                remaining: count - 1,
                uv,
                up: params.up,
                started: p.device.now(),
                get_cred_blob: params.get_cred_blob,
                third_party_payment: params.third_party_payment,
                hmac: core::mem::replace(
                    &mut self.assertion.hmac,
                    super::hmac_secret::Prepared::new(),
                ),
            };
        }
        respond(
            &Signing {
                id: &id,
                rp: &rp,
                client_hash: &params.client_hash,
                algorithm,
                sm2: self.sm2,
                make: params.make,
                up: params.up,
                uv,
                user_slot: if params.make { None } else { user_slot },
                count,
                details: count > 1,
                min_pin_length,
                hmac_secret: params.make && params.hmac_secret,
                hmac: &self.assertion.hmac,
                cred_blob: params.cred_blob_len.map(|n| params.resident && n <= 32),
                get_cred_blob: params.get_cred_blob,
                third_party_payment: params.third_party_payment,
                protection: (params.make && params.protection_requested)
                    .then_some(params.protection),
            },
            w,
            p,
            &mut self.auth_response,
        )
    }
    pub(super) fn next_assertion(
        &mut self,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<usize, Status> {
        let result = (|| {
            if self.assertion.remaining == 0
                || p.device.now().wrapping_sub(self.assertion.started) > 30_000
            {
                return Err(Status::NotAllowed);
            }
            for index in self.assertion.next..crate::ports::Record::CTAP_CREDENTIALS {
                if let Some(n) = resident::load(index, &mut w.input, p)? {
                    let entry = resident::Entry::decode(&w.input[..n])?;
                    if entry.rp_hash != &self.assertion.rp
                        || (!self.assertion.uv && entry.id[1] & 3 != 1)
                    {
                        continue;
                    }
                    let id = *entry.id;
                    let algorithm = credential::open(&id, self.sm2, &self.assertion.rp, w, p)?;
                    self.assertion.next = index + 1;
                    self.assertion.remaining -= 1;
                    self.assertion.started = p.device.now();
                    return respond(
                        &Signing {
                            id: &id,
                            rp: &self.assertion.rp,
                            client_hash: &self.assertion.client_hash,
                            algorithm,
                            sm2: self.sm2,
                            make: false,
                            up: self.assertion.up,
                            uv: self.assertion.uv,
                            user_slot: Some(index),
                            count: 0,
                            details: true,
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
                    );
                }
            }
            Err(Status::NoCredentials)
        })();
        if result.is_err() || self.assertion.remaining == 0 {
            self.assertion.hmac.clear(p.memory);
        }
        p.memory.wipe(&mut w.key.bytes);
        if result.is_err() {
            p.memory.wipe(&mut w.input);
            self.assertion.remaining = 0;
            p.memory.wipe(&mut w.output);
        }
        result
    }
    fn credential_presence(
        &mut self,
        w: &mut Workspace,
        p: &mut Platform<'_>,
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
    p: &mut Platform<'_>,
    response: &mut Option<super::Response>,
) -> Result<usize, Status> {
    let counter = credential::counter(p)?;
    w.input[..32].copy_from_slice(request.rp);
    w.input[32] =
        u8::from(request.up) | if request.uv { 4 } else { 0 } | if request.make { 0x40 } else { 0 };
    w.input[33..37].copy_from_slice(&counter);
    let mut auth_len = 37;
    if request.make {
        if request.algorithm == alg::MLDSA65 {
            return respond_mldsa_make(request, w, p, response, auth_len);
        }
        let n = p
            .crypto
            .key_operation(
                KeyOperation::Public,
                request.algorithm,
                &mut w.key,
                &[],
                &mut w.output,
            )
            .unwrap_or_default();
        if n != credential::public_length(request.algorithm) {
            return Err(Status::Other);
        }
        w.input[37..53].copy_from_slice(&super::provision::AAGUID);
        w.input[53..55].copy_from_slice(&(credential::ID_BYTES as u16).to_be_bytes());
        w.input[55..55 + credential::ID_BYTES].copy_from_slice(request.id);
        auth_len = 55 + credential::ID_BYTES;
        let tail = &mut w.input[auth_len..];
        let capacity = tail.len();
        let mut e = Encoder::new(tail);
        super::encoding::public_key(&mut e, request.algorithm, request.sm2, &w.output[..n])
            .map_err(|_| Status::Other)?;
        auth_len += capacity - e.writer().len();
    }
    let extensions = u64::from(request.protection.is_some())
        + u64::from(request.min_pin_length.is_some())
        + u64::from(request.cred_blob.is_some() || request.get_cred_blob)
        + u64::from(request.hmac_secret)
        + u64::from(request.hmac.active())
        + u64::from(!request.make && request.third_party_payment);
    if extensions != 0 {
        w.input[32] |= 0x80;
        let mut blob = [0; 32];
        let mut blob_len = 0;
        if request.get_cred_blob {
            if let Some(index) = request.user_slot {
                let n = resident::load(index, &mut w.output, p)?.ok_or(Status::NoCredentials)?;
                let entry = resident::Entry::decode(&w.output[..n])?;
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
        let capacity = w.input.len() - auth_len;
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
        auth_len += capacity - e.writer().len();
    }
    if !request.make && request.algorithm == alg::MLDSA65 {
        return respond_mldsa_assertion(request, w, p, response, auth_len);
    }
    let mut self_attest = false;
    let cert_len = if request.make {
        let certificate = p.storage.size(crate::ports::Record::CtapCertificate);
        let mut attestation_key = [0; 32];
        let key_ok = matches!(
            p.storage.load(
                crate::ports::Record::CtapAttestationKey,
                &mut attestation_key
            ),
            Ok(32)
        );
        let cert_len = match (key_ok, certificate) {
            (true, Ok(n)) if (n as usize) <= super::provision::CERT_LIMIT => n as usize,
            (false, Err(crate::ports::StorageError::Missing))
            | (true, Err(crate::ports::StorageError::Missing))
            | (false, Ok(_)) => {
                self_attest = true;
                0
            }
            _ => return Err(Status::Other),
        };
        if !self_attest {
            p.memory.wipe(&mut w.key.bytes);
            w.key.bytes[..32].copy_from_slice(&attestation_key);
        }
        p.memory.wipe(&mut attestation_key);
        cert_len
    } else {
        0
    };
    let sign_algorithm = if request.make && !self_attest {
        alg::P256
    } else {
        request.algorithm
    };
    w.input[auth_len..auth_len + 32].copy_from_slice(request.client_hash);
    let mut digest = [0; 32];
    let message = if sign_algorithm == alg::P256 {
        p.crypto
            .sha256(&w.input[..auth_len + 32], &mut digest)
            .unwrap_or_default();
        &digest[..]
    } else if sign_algorithm == alg::SM2 {
        let n = p
            .crypto
            .key_operation(
                KeyOperation::Sm2MessageDigest,
                alg::SM2,
                &mut w.key,
                &w.input[..auth_len + 32],
                &mut w.output,
            )
            .unwrap_or_default();
        if n != 32 {
            return Err(Status::Other);
        }
        digest.copy_from_slice(&w.output[..32]);
        &digest[..]
    } else {
        &w.input[..auth_len + 32]
    };
    let n = p
        .crypto
        .key_operation(
            KeyOperation::EcSign,
            sign_algorithm,
            &mut w.key,
            message,
            &mut w.output,
        )
        .unwrap_or_default();
    if n != 64 {
        return Err(Status::Other);
    }
    let n = if sign_algorithm == alg::P256 {
        der_signature(&mut w.output, n).unwrap_or_default()
    } else {
        n
    };
    let mut signature = [0; 72];
    signature[..n].copy_from_slice(&w.output[..n]);
    p.memory.wipe(&mut w.key.bytes);
    let has_blob_key = request.id[1] & resident::LARGE_BLOB_KEY != 0;
    let mut blob_key = [0; 32];
    let user = if let Some(index) = request.user_slot {
        let n = resident::load(index, &mut w.key.bytes, p)?.ok_or(Status::NoCredentials)?;
        Some(resident::Entry::decode(&w.key.bytes[..n])?)
    } else {
        None
    };
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
        )
        .u8(1);
        if request.make {
            e.str("packed");
        } else {
            super::encoding::descriptor(&mut e, request.id)?;
        }
        e.u8(2).bytes_len(auth_len as u64);
        prefix = crate::runtime::workspace::OUTPUT_BYTES - e.writer().len();
        e.u8(3);
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
            e.u8(4);
            super::encoding::user(&mut e, user, request.uv && request.details)?;
        }
        if request.count > 1 {
            e.u8(5).u8(request.count);
        }
        if has_blob_key {
            e.u8(if request.make { 5 } else { 7 }).bytes(&blob_key);
        }
        e.finish()
    })();
    p.memory.wipe(&mut blob_key);
    encoded.map_err(|_| Status::Other)?;
    let total = crate::runtime::workspace::OUTPUT_BYTES - e.writer().len() + auth_len + cert_len;
    *response = Some(super::Response::Authentication {
        prefix,
        auth: auth_len,
        certificate,
        total,
    });
    Ok(total)
}

fn respond_mldsa_assertion(
    request: &Signing<'_>,
    w: &mut Workspace,
    p: &mut Platform<'_>,
    response: &mut Option<super::Response>,
    auth_len: usize,
) -> Result<usize, Status> {
    let has_blob_key = request.id[1] & resident::LARGE_BLOB_KEY != 0;
    let mut e = Encoder::new(&mut w.output[..]);
    e.map(2 + u64::from(request.count > 1) + u64::from(has_blob_key));
    e.u8(2)
        .bytes_len(auth_len as u64)
        .finish()
        .map_err(|_| Status::Other)?;
    let prefix = crate::runtime::workspace::OUTPUT_BYTES - e.writer().len();
    let mut tail = Encoder::new(&mut w.output[prefix..]);
    tail.u8(3).bytes_len(super::pq::SIGNATURE_BYTES as u64);
    let signature_at = crate::runtime::workspace::OUTPUT_BYTES - tail.writer().len();
    if request.count > 1 {
        tail.u8(5).u8(request.count);
    }
    if has_blob_key {
        let mut key = [0; 32];
        credential::large_blob_key(request.id, request.rp, &mut key, p)?;
        tail.u8(7).bytes(&key);
        p.memory.wipe(&mut key);
    }
    tail.finish().map_err(|_| Status::Other)?;
    let output = crate::runtime::workspace::OUTPUT_BYTES - tail.writer().len();
    w.input[auth_len..auth_len + 32].copy_from_slice(request.client_hash);
    w.input[auth_len + 32..auth_len + 64].copy_from_slice(&w.key.bytes[..32]);
    *response = Some(super::Response::Pending(super::pq::Pending {
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
    Ok(output + auth_len + super::pq::SIGNATURE_BYTES)
}

fn respond_mldsa_make(
    request: &Signing<'_>,
    w: &mut Workspace,
    p: &mut Platform<'_>,
    response: &mut Option<super::Response>,
    _auth_prefix_len: usize,
) -> Result<usize, Status> {
    let cert_len = p
        .storage
        .size(crate::ports::Record::CtapCertificate)
        .unwrap_or_default() as usize;
    if cert_len > super::provision::CERT_LIMIT {
        return Err(Status::Other);
    }
    w.input[..32].copy_from_slice(request.client_hash);
    w.input[32..64].copy_from_slice(&w.key.bytes[..32]);

    let mut cose = [0u8; 32];
    let mut ce = Encoder::new(&mut cose[..]);
    super::encoding::mldsa_public_header(&mut ce).map_err(|_| Status::Other)?;
    let cose_prefix_len = 32 - ce.writer().len();
    // authenticatorData = rpIdHash (32) || flags (1) || counter (4) ||
    // AAGUID (16) || credentialIdLength (2) || credentialId || COSE key.
    let auth_prefix_len = 55 + credential::ID_BYTES + cose_prefix_len;
    let auth_len = auth_prefix_len + 0;

    let mut e = Encoder::new(&mut w.output[..]);
    e.encoded(super::encoding::MAKE_HEADER)
        .bytes_len((auth_len + super::pq::PUBLIC_BYTES) as u64);
    e.finish().map_err(|_| Status::Other)?;
    let auth_start = crate::runtime::workspace::OUTPUT_BYTES - e.writer().len();
    let public_at = auth_start + auth_prefix_len;
    w.output[auth_start..auth_start + 32].copy_from_slice(request.rp);
    w.output[auth_start + 32] = 0x41;
    let counter = credential::counter(p)?;
    w.output[auth_start + 33..auth_start + 37].copy_from_slice(&counter);
    w.output[auth_start + 37..auth_start + 53].copy_from_slice(&super::provision::AAGUID);
    w.output[auth_start + 53..auth_start + 55]
        .copy_from_slice(&(credential::ID_BYTES as u16).to_be_bytes());
    w.output[auth_start + 55..auth_start + 55 + credential::ID_BYTES].copy_from_slice(request.id);
    w.output[public_at..public_at + cose_prefix_len].copy_from_slice(&cose[..cose_prefix_len]);

    let after_cose = public_at + cose_prefix_len;
    let mut tail = Encoder::new(&mut w.output[after_cose..]);
    tail.u8(3)
        .encoded(super::encoding::ATTESTATION)
        .bytes_len(72);
    tail.finish().map_err(|_| Status::Other)?;
    let signature_at = crate::runtime::workspace::OUTPUT_BYTES - tail.writer().len();
    tail.encoded(super::encoding::CERTIFICATE)
        .bytes_len(cert_len as u64);
    tail.finish().map_err(|_| Status::Other)?;
    let cert_at = crate::runtime::workspace::OUTPUT_BYTES - tail.writer().len();
    let output = cert_at;
    let total = output + super::pq::PUBLIC_BYTES + cert_len;
    *response = Some(super::Response::Pending(super::pq::Pending {
        mode: super::pq::Mode::Make,
        prefix: auth_start,
        auth: 0,
        public_at,
        signature_at,
        certificate: Some((cert_at, cert_len)),
        output,
        hash_prefix: (auth_start, auth_prefix_len),
        hash_suffix: (after_cose, 0),
    }));
    Ok(total)
}
