// SPDX-License-Identifier: Apache-2.0
//! PIN protocol crypto and compact durable retries. Request PKE is already gone.
use super::wire::pin_protocol as wire;
use super::wire::pin_protocol::{
    MAX_PIN_BYTES, MAX_RETRIES, MIN_CODE_POINTS, PIN_HASH_BYTES, SESSION_ATTEMPTS,
};
use super::{
    Session, Status,
    client_pin::Parameters,
    crypto::{equal, mac, verify_mac},
};
use crate::{
    ports::{KeyOperation, Platform, Record, StorageError, alg},
    runtime::workspace::Workspace,
};

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
pub(super) fn load(p: &mut Platform<'_>, record: &mut [u8; RECORD_BYTES]) -> Result<(), Status> {
    record.fill(0);
    match p.storage.load(Record::CtapPin, record) {
        Err(StorageError::Missing) => {
            record[RETRIES] = MAX_RETRIES;
            record[MIN_PIN_LENGTH] = MIN_CODE_POINTS;
        }
        Ok(n)
            if n >= RP_HASHES
                && record[RETRIES] <= MAX_RETRIES
                && (record[PIN_LENGTH] == 0
                    || (MIN_CODE_POINTS..=MAX_PIN_BYTES).contains(&record[PIN_LENGTH]))
                && (MIN_CODE_POINTS..=MAX_PIN_BYTES).contains(&record[MIN_PIN_LENGTH])
                && record[FLAGS] >> RP_HASH_COUNT_SHIFT <= 4
                && n == RP_HASHES + usize::from(record[FLAGS] >> RP_HASH_COUNT_SHIFT) * 32 =>
        {
            ()
        }
        _ => {
            p.memory.wipe(record);
            return Err(Status::Other);
        }
    }
    Ok(())
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
pub(super) fn policy(p: &mut Platform<'_>) -> Result<Policy, Status> {
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
pub(super) fn save(record: &[u8; RECORD_BYTES], p: &mut Platform<'_>) -> Result<(), Status> {
    let n = RP_HASHES + usize::from(record[FLAGS] >> RP_HASH_COUNT_SHIFT) * 32;
    p.storage
        .replace(Record::CtapPin, &record[..n])
        .map_err(|_| Status::Other)
}
pub(super) fn decrypt(
    protocol: u8,
    key: &[u8; 32],
    bytes: &mut [u8],
    p: &mut Platform<'_>,
) -> Result<(), Status> {
    if protocol == wire::V2 && bytes.len() < wire::AES_BLOCK_BYTES {
        return Err(Status::InvalidLength);
    }
    if bytes.len() % wire::AES_BLOCK_BYTES != 0 {
        return Err(Status::InvalidLength);
    }
    let mut iv = [0; wire::AES_BLOCK_BYTES];
    let n = if protocol == wire::V2 {
        iv.copy_from_slice(&bytes[..wire::AES_BLOCK_BYTES]);
        bytes.copy_within(wire::AES_BLOCK_BYTES.., 0);
        bytes.len() - wire::AES_BLOCK_BYTES
    } else {
        bytes.len()
    };
    p.crypto
        .aes256_cbc(false, key, &iv, &mut bytes[..n])
        .map_err(|_| Status::Other)
}
impl Session {
    // Both callers own workspace cleanup and Session::execute invalidates
    // authorization after a primitive failure. Only public replies export COSE.
    #[inline(never)]
    pub(super) fn agreement_key(
        &mut self,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<(), Status> {
        if !self.agreement_ready {
            p.crypto
                .key_operation(KeyOperation::Generate, alg::P256, &mut w.key, &[], w.input)
                .map_err(|_| Status::Other)?;
            self.agreement.copy_from_slice(&w.key.bytes[..32]);
            self.agreement_ready = true;
        } else {
            w.key.bytes[..32].copy_from_slice(&self.agreement);
        }
        Ok(())
    }
    pub(super) fn decapsulate(
        &mut self,
        protocol: u8,
        agreement: &[u8; 64],
        shared: &mut [u8; 64],
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<(), Status> {
        // ECDH validates the peer point in the primitive backend. Generating
        // our private key does not require exporting a public response first.
        if !self.agreement_ready {
            w.clear(p.memory);
        }
        self.agreement_key(w, p)?;
        let n = p
            .crypto
            .key_operation(
                KeyOperation::Agree,
                alg::P256,
                &mut w.key,
                agreement,
                w.input,
            )
            .map_err(|_| Status::InvalidParameter)?;
        if n != 32 {
            return Err(Status::Other);
        }
        if protocol == wire::V1 {
            p.crypto
                .sha256(&w.input[..32], (&mut shared[..32]).try_into().unwrap())
                .map_err(|_| Status::Other)?;
            shared.copy_within(..32, 32);
        } else {
            let mut prk = [0; 32];
            let derive = (|| {
                mac(&[0; 32], &w.input[..32], &mut prk, p)?;
                mac(
                    &prk,
                    // CTAP2 protocol2 HKDF-Expand info plus block counter 0x01.
                    b"CTAP2 HMAC key\x01",
                    (&mut shared[..32]).try_into().unwrap(),
                    p,
                )?;
                mac(
                    &prk,
                    // Separate HKDF info derives the AES key, block counter 0x01.
                    b"CTAP2 AES key\x01",
                    (&mut shared[32..]).try_into().unwrap(),
                    p,
                )
            })();
            p.memory.wipe(&mut prk);
            derive?;
        }
        Ok(())
    }
    pub(super) fn retries(
        &mut self,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<usize, Status> {
        w.output[..4].copy_from_slice(&[0, 0xa1, wire::RESPONSE_RETRIES, policy(p)?.retries]);
        Ok(4)
    }
    #[inline(never)]
    pub(super) fn client_pin(
        &mut self,
        cp: &mut Parameters,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<usize, Status> {
        let mut shared = [0; 64];
        let mut record = [0; RECORD_BYTES];
        let result = (|| {
            load(p, &mut record)?;
            let configured = record[PIN_LENGTH] != 0;
            if cp.subcommand == wire::SET_PIN {
                if configured {
                    return Err(Status::PinAuthInvalid);
                }
            } else {
                if !configured {
                    return Err(Status::PinNotSet);
                }
                if record[RETRIES] == 0 {
                    return Err(Status::PinBlocked);
                }
                if self.pin_attempts == 0 {
                    return Err(Status::PinAuthBlocked);
                }
            }
            self.decapsulate(cp.protocol, &cp.agreement, &mut shared, w, p)?;
            let new_len = wire::new_pin_bytes(cp.protocol);
            let hash_len = wire::auth_bytes(cp.protocol);
            if cp.subcommand == wire::SET_PIN || cp.subcommand == wire::CHANGE_PIN {
                w.input[..new_len].copy_from_slice(&cp.new_pin[..new_len]);
                let n = if cp.subcommand == wire::CHANGE_PIN {
                    w.input[new_len..new_len + hash_len].copy_from_slice(&cp.pin_hash[..hash_len]);
                    new_len + hash_len
                } else {
                    new_len
                };
                verify_mac(&shared[..32], &cp.auth[..hash_len], &w.input[..n], p)?;
            }
            let aes_key: &[u8; 32] = shared[32..].try_into().unwrap();
            if cp.subcommand != wire::SET_PIN {
                // Charge before decrypt/compare. Failed writes never authorize.
                record[RETRIES] -= 1;
                p.storage
                    .replace_at(
                        Record::CtapPin,
                        RETRIES as u32,
                        &record[RETRIES..RETRIES + 1],
                    )
                    .map_err(|_| Status::Other)?;
                decrypt(cp.protocol, aes_key, &mut cp.pin_hash[..hash_len], p)?;
                if !equal(&record[..PIN_HASH_BYTES], &cp.pin_hash[..PIN_HASH_BYTES]) {
                    self.pin_attempts -= 1;
                    self.agreement_ready = false;
                    p.memory.wipe(&mut self.agreement);
                    return Err(if record[RETRIES] == 0 {
                        Status::PinBlocked
                    } else if self.pin_attempts == 0 {
                        Status::PinAuthBlocked
                    } else {
                        Status::PinInvalid
                    });
                }
                self.pin_attempts = SESSION_ATTEMPTS;
                // Correct current PIN restores retries even if the new PIN
                // subsequently fails policy validation.
                record[RETRIES] = MAX_RETRIES;
                p.storage
                    .replace_at(
                        Record::CtapPin,
                        RETRIES as u32,
                        &record[RETRIES..RETRIES + 1],
                    )
                    .map_err(|_| Status::Other)?;
            }
            if cp.subcommand == wire::GET_TOKEN || cp.subcommand == wire::GET_TOKEN_PERMISSIONS {
                if record[FLAGS] & FORCE_CHANGE != 0 {
                    return Err(if cp.subcommand == wire::GET_TOKEN {
                        Status::PinInvalid
                    } else {
                        Status::PinPolicy
                    });
                }
                self.clear_token(p.memory);
                p.crypto
                    .random(&mut self.token)
                    .map_err(|_| Status::Other)?;
                w.input[..32].copy_from_slice(&self.token);
                let mut iv = [0; wire::AES_BLOCK_BYTES];
                if cp.protocol == wire::V2 {
                    p.crypto.random(&mut iv).map_err(|_| Status::Other)?;
                }
                p.crypto
                    .aes256_cbc(true, aes_key, &iv, &mut w.input[..32])
                    .map_err(|_| Status::Other)?;
                let n = wire::token_bytes(cp.protocol) as u8;
                w.output[..5].copy_from_slice(&[0, 0xa1, wire::RESPONSE_TOKEN, 0x58, n]);
                let offset = if cp.protocol == wire::V2 {
                    w.output[5..21].copy_from_slice(&iv);
                    21
                } else {
                    5
                };
                w.output[offset..offset + 32].copy_from_slice(&w.input[..32]);
                self.token_started = p.device.now();
                self.token_used = self.token_started;
                if cp.subcommand == wire::GET_TOKEN_PERMISSIONS && cp.rp_len != 0 {
                    p.crypto
                        .sha256(&cp.rp[..cp.rp_len], &mut self.rp_binding)
                        .map_err(|_| Status::Other)?;
                    self.rp_bound = true;
                }
                self.permissions = if cp.subcommand == wire::GET_TOKEN {
                    wire::PERMISSION_RP
                } else {
                    cp.permissions
                };
                return Ok(offset + 32);
            }
            decrypt(cp.protocol, aes_key, &mut cp.new_pin[..new_len], p)?;
            let n = cp.new_pin[..wire::PADDED_PIN_BYTES]
                .iter()
                .rposition(|b| *b != 0)
                .map_or(0, |i| i + 1);
            if n == 0 || n > usize::from(MAX_PIN_BYTES) {
                return Err(Status::PinPolicy);
            }
            let pin = core::str::from_utf8(&cp.new_pin[..n]).map_err(|_| Status::PinPolicy)?;
            let count = pin.chars().count();
            if count < usize::from(record[MIN_PIN_LENGTH]) || pin.contains('\0') {
                return Err(Status::PinPolicy);
            }
            let mut digest = [0; 32];
            let hash = p
                .crypto
                .sha256(pin.as_bytes(), &mut digest)
                .map_err(|_| Status::Other);
            record[..PIN_HASH_BYTES].copy_from_slice(&digest[..PIN_HASH_BYTES]);
            p.memory.wipe(&mut digest);
            hash?;
            record[RETRIES] = MAX_RETRIES;
            record[PIN_LENGTH] = count as u8;
            record[FLAGS] &= !FORCE_CHANGE;
            save(&record, p)?;
            self.clear_token(p.memory);
            w.output[0] = 0;
            Ok(1)
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
        p: &mut Platform<'_>,
    ) -> Result<(), Status> {
        self.expire_token(p.device.now(), p.memory);
        if self.pin_attempts == 0 {
            return Err(Status::PinAuthBlocked);
        }
        if !matches!(protocol, wire::V1 | wire::V2)
            || auth.len() != wire::auth_bytes(protocol)
            || self.permissions & permission != permission
            || rp.is_some_and(|rp| self.rp_bound && !equal(rp, &self.rp_binding))
        {
            return Err(Status::PinAuthInvalid);
        }
        verify_mac(&self.token, auth, message, p)?;
        self.token_used = p.device.now();
        Ok(())
    }
    pub(super) fn expire_token(&mut self, now: u32, memory: &crate::ports::MemoryPort<'_>) {
        // Match C: 30 seconds without successful authentication, at most ten
        // minutes from issuance. Unauthenticated requests never refresh either.
        if self.permissions != 0
            && (now.wrapping_sub(self.token_used) >= 30_000
                || now.wrapping_sub(self.token_started) >= 600_000)
        {
            self.clear_token(memory);
        }
    }
    pub(super) fn clear_token(&mut self, memory: &crate::ports::MemoryPort<'_>) {
        memory.wipe(&mut self.token);
        self.permissions = 0;
        memory.wipe(&mut self.rp_binding);
        self.rp_bound = false;
        self.token_started = 0;
        self.token_used = 0;
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
                session.token.fill(0xa5);
                session.permissions = PERMISSION_CONFIG;
                session.rp_binding.fill(0x5a);
                session.rp_bound = true;
                session.token_started = start;
                session.token_used = start.wrapping_add(last_used);
                session.pin_attempts = 1;
                session.expire_token(start.wrapping_add(elapsed), &Wipe);
                assert_eq!(session.permissions == 0, expired);
                assert_eq!(session.token == [0; 32], expired);
                assert_eq!(session.rp_binding == [0; 32], expired);
                assert_eq!(session.rp_bound, !expired);
                assert_eq!(session.pin_attempts, 1);
            }
        }
    }
}

#[cfg(test)]
mod operation_tests;
