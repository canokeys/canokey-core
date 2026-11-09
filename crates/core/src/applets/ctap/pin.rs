// SPDX-License-Identifier: Apache-2.0
//! PIN protocol crypto and compact durable retries. Request PKE is already gone.
use super::wire::pin_protocol as wire;
use super::wire::pin_protocol::{MAX_PIN_BYTES, MAX_RETRIES, MIN_CODE_POINTS, PIN_HASH_BYTES};
use super::{
    Session, Status,
    client_pin::Parameters,
    crypto::{equal, mac, verify_mac},
};
use crate::{
    ports::{KeyMaterial, KeyOperation, Platform, Record, alg},
    runtime::workspace::Workspace,
};
use canokey_ctap::client_pin::{self as shared_pin, agreement, response, retry, token};
use canokey_ports::{Crypto as _, Device as _, Memory as _, Storage as _};

#[cfg(test)]
use canokey_ctap::client_pin::retry::POWER_CYCLE_ATTEMPTS as SESSION_ATTEMPTS;

mod operation;

pub(super) struct PinCrypto<'a, 'p, B: crate::ports::Backends>(pub(super) &'a mut Platform<'p, B>);
impl<B: crate::ports::Backends> shared_pin::Derivation for PinCrypto<'_, '_, B> {
    type Error = Status;
    fn sha256(&mut self, input: &[u8], out: &mut [u8; 32]) -> Result<(), Status> {
        self.0.crypto.sha256(input, out).map_err(|_| Status::Other)
    }
    fn hmac_sha256(
        &mut self,
        key: &[u8; 32],
        input: &[u8],
        out: &mut [u8; 32],
    ) -> Result<(), Status> {
        mac(key, input, out, self.0)
    }
    fn wipe(&mut self, bytes: &mut [u8]) {
        self.0.memory.wipe(bytes);
    }
}

impl<B: crate::ports::Backends> shared_pin::cipher::Cbc for PinCrypto<'_, '_, B> {
    type Error = Status;
    fn aes256_cbc(
        &mut self,
        direction: shared_pin::cipher::Direction,
        key: &[u8; 32],
        iv: &[u8; shared_pin::cipher::BLOCK_BYTES],
        bytes: &mut [u8],
    ) -> Result<(), Status> {
        self.0
            .crypto
            .aes256_cbc(
                matches!(direction, shared_pin::cipher::Direction::Encrypt),
                key,
                iv,
                bytes,
            )
            .map_err(|_| Status::Other)
    }
}
impl<B: crate::ports::Backends> shared_pin::cipher::Encryption for PinCrypto<'_, '_, B> {
    fn random_iv(&mut self, iv: &mut [u8; shared_pin::cipher::BLOCK_BYTES]) -> Result<(), Status> {
        self.0.crypto.random(iv).map_err(|_| Status::Other)
    }
}
pub(super) fn cipher_error(error: shared_pin::cipher::Error<Status>) -> Status {
    match error {
        shared_pin::cipher::Error::InvalidLength => Status::InvalidLength,
        shared_pin::cipher::Error::Primitive(error) => error,
    }
}
// Existing internal CBC callers have already admitted the protocol. Preserve
// their zero-IV fallback while keeping the shared framing API typed.
pub(super) fn cipher_protocol(protocol: u8) -> shared_pin::Protocol {
    if protocol == wire::V2 {
        shared_pin::Protocol::Two
    } else {
        shared_pin::Protocol::One
    }
}

// The owner reserves status plus the shared map/key/bstr prefix before AES.
const TOKEN_RESPONSE_HEADER_BYTES: usize = 1 + response::TOKEN_PREFIX_BYTES;

// PIN hash, retries, code-point count, minimum length, flags/RP count,
// followed by at most four RP hashes. One atomic record; no padding or prefix.
pub(super) const ALWAYS_UV: u8 = 1;
pub(super) const FORCE_CHANGE: u8 = 2;
pub(super) const LONG_RESET: u8 = 4;
pub(super) const RECORD_BYTES: usize = 20 + 4 * 32;
pub(super) const RETRIES: usize = 16;
pub(super) const PIN_LENGTH: usize = 17;
pub(super) const MIN_PIN_LENGTH: usize = 18;
pub(super) const FLAGS: usize = 19;
pub(super) const RETRY_MASK: u8 = 0x07;
pub(super) const RP_HASH_COUNT_SHIFT: u8 = 3;
pub(super) const RP_HASHES: usize = 20;
pub(super) const PERMISSION_LARGE_BLOB_WRITE: u8 = 0x10;
pub(super) const PERMISSION_CONFIG: u8 = 0x20;
/// Fill a caller-owned PIN record without returning a second array copy.
/// A failed read/validation wipes even partially supplied backend data.
pub(super) fn load(
    p: &mut Platform<'_, impl crate::ports::Backends>,
    record: &mut [u8; RECORD_BYTES],
) -> Result<(), Status> {
    record.fill(0);
    let result = crate::mechanisms::storage::load_or_else(
        p,
        Record::CtapPin,
        record,
        |record, n| {
            if n >= RP_HASHES
                && record[RETRIES] <= MAX_RETRIES
                && (record[PIN_LENGTH] == 0
                    || (record[PIN_LENGTH] >= MIN_CODE_POINTS
                        && record[PIN_LENGTH] <= MAX_PIN_BYTES))
                && (record[MIN_PIN_LENGTH] >= MIN_CODE_POINTS
                    && record[MIN_PIN_LENGTH] <= MAX_PIN_BYTES)
                && record[FLAGS] >> RP_HASH_COUNT_SHIFT <= 4
                && n == RP_HASHES + usize::from(record[FLAGS] >> RP_HASH_COUNT_SHIFT) * 32
            {
                Ok(())
            } else {
                Err(Status::Other)
            }
        },
        |record, _| {
            record[RETRIES] = MAX_RETRIES;
            record[MIN_PIN_LENGTH] = MIN_CODE_POINTS;
            Ok(())
        },
        |_| Status::Other,
    );
    if result.is_err() {
        p.memory.wipe(record);
    }
    result
}
/// Non-secret policy shared by callers that do not need the PIN hash/RP list.
/// Validate the complete record before publishing any flags, then erase it here.
pub(super) struct Policy {
    pub retries: u8,
    pub pin_length: u8,
    pub minimum: u8,
    pub flags: u8,
}
#[inline(never)]
pub(super) fn policy(p: &mut Platform<'_, impl crate::ports::Backends>) -> Result<Policy, Status> {
    let mut record = [0; RECORD_BYTES];
    load(p, &mut record)?;
    let policy = Policy {
        retries: record[RETRIES],
        pin_length: record[PIN_LENGTH],
        minimum: record[MIN_PIN_LENGTH],
        flags: record[FLAGS],
    };
    p.memory.wipe(&mut record);
    Ok(policy)
}
pub(super) fn save(
    record: &[u8; RECORD_BYTES],
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<(), Status> {
    let n = RP_HASHES + usize::from(record[FLAGS] >> RP_HASH_COUNT_SHIFT) * 32;
    p.storage
        .replace(Record::CtapPin, &record[..n])
        .map_err(|_| Status::Other)
}
pub(super) fn decrypt(
    protocol: u8,
    key: &[u8; 32],
    bytes: &mut [u8],
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<(), Status> {
    shared_pin::cipher::decrypt_in_place(cipher_protocol(protocol), key, bytes, &mut PinCrypto(p))
        .map(|_| ())
        .map_err(cipher_error)
}
struct KeyGeneration<'a, 'p, B: crate::ports::Backends> {
    pin: &'a mut shared_pin::Session<u8>,
    key: &'a mut KeyMaterial,
    input: &'a mut [u8],
    platform: &'a mut Platform<'p, B>,
}
impl<B: crate::ports::Backends> agreement::Generation for KeyGeneration<'_, '_, B> {
    type Error = Status;
    type Output = ();
    fn ready(&self) -> bool {
        self.pin.agreement_ready()
    }
    fn generate(&mut self) -> Result<bool, Status> {
        self.platform
            .crypto
            .key_operation(KeyOperation::Generate, alg::P256, self.key, &[], self.input)
            .map_err(|_| Status::Other)?;
        // The native generator performs scalar rejection before returning.
        Ok(true)
    }
    fn commit(&mut self) -> Result<(), Status> {
        self.pin.with_private_mut(|private| {
            private.copy_from_slice(&self.key.bytes[..32]);
        });
        self.pin.commit_agreement();
        Ok(())
    }
    fn restore(&mut self) -> Result<(), Status> {
        self.pin
            .with_private(|private| self.key.bytes[..32].copy_from_slice(private));
        Ok(())
    }
}
struct AgreementCrypto<'a, 'p, B: crate::ports::Backends> {
    key: &'a mut KeyMaterial,
    platform: &'a mut Platform<'p, B>,
}
impl<B: crate::ports::Backends> shared_pin::Derivation for AgreementCrypto<'_, '_, B> {
    type Error = Status;
    fn sha256(&mut self, input: &[u8], out: &mut [u8; 32]) -> Result<(), Status> {
        shared_pin::Derivation::sha256(&mut PinCrypto(self.platform), input, out)
    }
    fn hmac_sha256(
        &mut self,
        key: &[u8; 32],
        input: &[u8],
        out: &mut [u8; 32],
    ) -> Result<(), Status> {
        shared_pin::Derivation::hmac_sha256(&mut PinCrypto(self.platform), key, input, out)
    }
    fn wipe(&mut self, bytes: &mut [u8]) {
        self.platform.memory.wipe(bytes);
    }
}
impl<B: crate::ports::Backends> agreement::Exchange for AgreementCrypto<'_, '_, B> {
    fn agree(&mut self, peer: &[u8; 64], output: &mut [u8]) -> Result<(), Status> {
        let length = self
            .platform
            .crypto
            .key_operation(KeyOperation::Agree, alg::P256, self.key, peer, output)
            .map_err(|_| Status::InvalidParameter)?;
        if length != shared_pin::KEY_BYTES {
            return Err(Status::Other);
        }
        Ok(())
    }
}

// This loan spans durable charging, current-PIN comparison and successful
// refund. New-PIN policy and token publication require its successful return.
struct CurrentPin<'a, 'p, B: crate::ports::Backends> {
    session: &'a mut Session,
    parameters: &'a mut Parameters,
    record: &'a mut [u8; RECORD_BYTES],
    aes_key: &'a [u8; 32],
    platform: &'a mut Platform<'p, B>,
}
impl<B: crate::ports::Backends> canokey_ctap::session::PinAgreement for CurrentPin<'_, '_, B> {
    fn erase_agreement(&mut self) {
        self.session
            .pin
            .clear_agreement(|bytes| self.platform.memory.wipe(bytes));
    }
    fn permissions(&self) -> u16 {
        u16::from(self.session.pin.token.permissions)
    }
    fn retain_permissions(&mut self, permissions: u16) {
        self.session.pin.token.permissions = permissions as u8;
    }
}
impl<B: crate::ports::Backends> retry::Verification for CurrentPin<'_, '_, B> {
    type Error = Status;
    fn remaining(&self) -> u8 {
        self.record[RETRIES]
    }
    fn blocked(&self) -> Status {
        Status::PinBlocked
    }
    fn charge(&mut self, remaining: u8) -> Result<(), Status> {
        self.record[RETRIES] = remaining;
        self.platform
            .storage
            .replace_at(
                Record::CtapPin,
                RETRIES as u32,
                &self.record[RETRIES..RETRIES + 1],
            )
            .map_err(|_| Status::Other)
    }
    fn compare(&mut self) -> Result<bool, Status> {
        let hash_len = wire::auth_bytes(self.parameters.protocol);
        decrypt(
            self.parameters.protocol,
            self.aes_key,
            &mut self.parameters.pin_hash[..hash_len],
            self.platform,
        )?;
        Ok(equal(
            &self.record[..PIN_HASH_BYTES],
            &self.parameters.pin_hash[..PIN_HASH_BYTES],
        ))
    }
    fn rejected(&mut self) -> Status {
        let rejection = self.session.pin_attempts.rejected(self.record[RETRIES]);
        canokey_ctap::session::lose_pin_agreement(self);
        match rejection {
            retry::Rejection::Blocked => Status::PinBlocked,
            retry::Rejection::PowerCycleBlocked => Status::PinAuthBlocked,
            retry::Rejection::Invalid => Status::PinInvalid,
        }
    }
    fn accepted(&mut self) -> Result<(), Status> {
        self.session.pin_attempts.reset();
        self.record[RETRIES] = MAX_RETRIES;
        self.platform
            .storage
            .replace_at(
                Record::CtapPin,
                RETRIES as u32,
                &self.record[RETRIES..RETRIES + 1],
            )
            .map_err(|_| Status::Other)
    }
}

// Both agreement responses and exchanges restore the same private key into the
// existing workspace. Outline the complete setup once for Thumb-1 callers.
#[inline(never)]
fn establish_agreement(
    owner: &mut shared_pin::Session<u8>,
    w: &mut Workspace,
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<(), Status> {
    agreement::establish(&mut KeyGeneration {
        pin: owner,
        key: w.key,
        input: w.input,
        platform: p,
    })
}

pub(super) fn decapsulate(
    owner: &mut shared_pin::Session<u8>,
    protocol: u8,
    agreement: &[u8; 64],
    shared: &mut [u8; 64],
    w: &mut Workspace,
    p: &mut Platform<'_, impl crate::ports::Backends>,
) -> Result<(), Status> {
    // ECDH validates the peer point in the primitive backend. Generating
    // our private key does not require exporting a public response first.
    if !owner.agreement_ready() {
        w.clear(p.memory);
    }
    establish_agreement(owner, w, p)?;
    let (mac_key, aes_key) = shared.split_at_mut(shared_pin::KEY_BYTES);
    agreement::decapsulate(
        || shared_pin::Protocol::decode(u64::from(protocol)).ok_or(Status::InvalidParameter),
        agreement,
        w.input,
        mac_key.try_into().unwrap(),
        aes_key.try_into().unwrap(),
        &mut AgreementCrypto {
            key: w.key,
            platform: p,
        },
    )
}
/// Authorization commits usage only once the request has its final RP scope.
#[derive(Clone, Copy)]
pub(super) enum AuthorizationScope {
    SuppliedRp,
    Global,
    DeferredRp,
}
impl Session {
    // Callers own workspace cleanup; only public replies export COSE.
    #[inline(always)]
    pub(super) fn agreement_key(
        &mut self,
        w: &mut Workspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<(), Status> {
        establish_agreement(&mut self.pin, w, p)
    }
    #[inline(always)]
    pub(super) fn decapsulate(
        &mut self,
        protocol: u8,
        agreement: &[u8; 64],
        shared: &mut [u8; 64],
        w: &mut Workspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<(), Status> {
        decapsulate(&mut self.pin, protocol, agreement, shared, w, p)
    }
    pub(super) fn retries(
        &mut self,
        w: &mut Workspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<usize, Status> {
        let retries = policy(p)?.retries;
        w.output[0] = 0x00;
        let mut offset = 1;
        response::retries(retries, None, |fragment| {
            w.output[offset..offset + fragment.len()].copy_from_slice(fragment);
            offset += fragment.len();
            Ok::<(), core::convert::Infallible>(())
        })
        .unwrap();
        Ok(offset)
    }
    #[inline(never)]
    pub(super) fn client_pin(
        &mut self,
        cp: &mut Parameters,
        w: &mut Workspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<usize, Status> {
        let mut shared = [0; 64];
        let mut record = [0; RECORD_BYTES];
        let result = (|| {
            let command = shared_pin::request::Command::decode(u64::from(cp.subcommand))
                .ok_or(Status::InvalidSubcommand)?;
            let kind = shared_pin::operation::Kind::from_command(command)
                .ok_or(Status::InvalidSubcommand)?;
            shared_pin::operation::execute(
                kind,
                &mut operation::Operation {
                    session: self,
                    parameters: cp,
                    workspace: w,
                    platform: p,
                    shared: &mut shared,
                    record: &mut record,
                },
            )
        })();
        p.memory.wipe(&mut cp.new_pin);
        p.memory.wipe(&mut cp.pin_hash);
        p.memory.wipe(&mut cp.auth);
        p.memory.wipe(&mut shared);
        p.memory.wipe(&mut record);
        p.memory.wipe(&mut w.key.bytes);
        p.memory.wipe(w.input);
        if result.is_err() {
            p.memory.wipe(w.output);
        }
        result
    }
    /// Verify only after transport staging is released. Authorization binds a
    /// successful use to the requested permission and, where applicable, RP.
    pub(super) fn authorize(
        &mut self,
        protocol: u8,
        auth: &[u8],
        message: &[u8],
        permission: u8,
        rp: Option<&[u8; 32]>,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<(), Status> {
        self.authorize_scoped(
            protocol,
            auth,
            message,
            permission,
            rp,
            AuthorizationScope::SuppliedRp,
            p,
        )
        .map(|_| ())
    }
    pub(super) fn authorize_scoped(
        &mut self,
        protocol: u8,
        auth: &[u8],
        message: &[u8],
        permission: u8,
        rp: Option<&[u8; 32]>,
        scope: AuthorizationScope,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<token::VerifiedRequest, Status> {
        self.expire_token(p.device.now(), p.memory);
        if self.pin_attempts.blocked() {
            return Err(Status::PinAuthBlocked);
        }
        if !matches!(protocol, wire::V1 | wire::V2) || auth.len() != wire::auth_bytes(protocol) {
            return Err(Status::PinAuthInvalid);
        }
        let verified = self
            .pin
            .token
            .verify_request(
                u16::from(permission),
                rp,
                if matches!(scope, AuthorizationScope::Global) {
                    token::MissingRp::Deny
                } else {
                    token::MissingRp::Allow
                },
                |secret| verify_mac(secret, auth, message, p),
                equal,
            )
            .map_err(|error| match error {
                token::Error::Scope => Status::PinAuthInvalid,
                token::Error::Mac(status) => status,
            })?;
        if !matches!(scope, AuthorizationScope::DeferredRp) {
            self.pin.token.mark_used(p.device.now());
        }
        Ok(verified)
    }
    /// The shared management dispatcher has authenticated this request before
    /// record IO. Serialized execution forbids replacing its token between that
    /// admission and this final check; time may still advance during storage IO.
    #[inline(never)]
    pub(super) fn finish_management(
        &mut self,
        _verified: &token::VerifiedRequest,
        rp: &[u8; 32],
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<(), Status> {
        self.expire_token(p.device.now(), p.memory);
        if self.pin_attempts.blocked() {
            return Err(Status::PinAuthBlocked);
        }
        if !self.pin.token.allows(
            wire::PERMISSION_CREDENTIALS.into(),
            Some(rp),
            token::MissingRp::Deny,
            equal,
        ) {
            return Err(Status::PinAuthInvalid);
        }
        self.pin.token.mark_used(p.device.now());
        Ok(())
    }
    // Reuse the expiry/erasure paths across applet admission and reset entrypoints.
    #[inline(never)]
    pub(super) fn expire_token(&mut self, now: u32, memory: &(impl crate::ports::Memory + ?Sized)) {
        // Successful authorization refreshes the idle window only. Issuance
        // fixes the absolute lifetime; unauthenticated requests refresh neither.
        if self.pin.token.permissions != 0 && self.pin.token.remaining_ms(now).is_none() {
            self.clear_token(memory);
        }
    }
    pub(super) fn clear_token(&mut self, memory: &(impl crate::ports::Memory + ?Sized)) {
        self.pin.token.clear(|bytes| memory.wipe(bytes));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Wipe;
    impl crate::ports::Memory for Wipe {
        fn wipe(&self, bytes: &mut [u8]) {
            bytes.fill(0);
        }
    }
    #[test]
    fn token_expiry_checks_idle_and_absolute_limits_across_clock_wrap() {
        for start in [0, u32::MAX - 1000] {
            for (last_used, elapsed, expired) in [
                (0, 29_999, false),
                (0, 30_000, true),
                (590_000, 599_999, false),
                (590_000, 600_000, true),
            ] {
                let mut session = Session::new();
                session
                    .pin
                    .token
                    .with_secret_mut(|secret| secret.fill(0xa5));
                session.pin.token.permissions = PERMISSION_CONFIG;
                session.pin.token.bind_rp(Some([0x5a; 32]));
                session.pin.token.issued = start;
                session.pin.token.last_used = start.wrapping_add(last_used);
                session.pin_attempts.rejected(7);
                session.pin_attempts.rejected(6);
                session.expire_token(start.wrapping_add(elapsed), &Wipe);
                assert_eq!(session.pin.token.permissions == 0, expired);
                assert_eq!(
                    session.pin.token.with_secret(|secret| *secret) == [0; 32],
                    expired
                );
                assert_eq!(
                    session.pin.token.rp_id().copied().unwrap_or([0x00; 32]) == [0; 32],
                    expired
                );
                assert_eq!(session.pin.token.rp_id().is_some(), !expired);
                assert_eq!(session.pin_attempts.remaining(), 1);
            }
        }
    }
}

#[cfg(test)]
mod operation_tests;
