// SPDX-License-Identifier: Apache-2.0
//! OpenPGP session/key policy, independent of APDU and TLV encoding.
use super::domain::{grant, key_role, touch_policy};
use super::repository::key_meta;
use super::{
    domain::{Algorithm, Error},
    repository::{self as repo, io},
};
use crate::ports::alg;
use crate::{
    Platform,
    ports::{KeyOperation, Record},
    runtime::workspace::Workspace,
};
fn pw1_policy(p: &mut Platform<'_>) -> Result<[u8; 2], Error> {
    let mut policy = [0; 2];
    p.storage
        .read_at(
            Record::PgpState,
            repo::state_layout::PW1_REUSE as u32,
            &mut policy,
        )
        .map_err(io)?;
    Ok(policy)
}
pub struct Session {
    // Independent authorization bits: signature PW1, other PW1, and PW3.
    // A successful VERIFY adds one bit; failure revokes all uses of that PIN.
    pub(super) grants: u8,
    last_touch: u32,
    touch_valid: bool,
    pub(super) presence: crate::runtime::presence::Request,
}
impl Session {
    pub const fn new() -> Self {
        Self {
            grants: 0,
            last_touch: 0,
            touch_valid: false,
            presence: crate::runtime::presence::Request::new(),
        }
    }
    pub fn clear_touch(&mut self) {
        self.touch_valid = false;
    }
    pub fn admin(&self) -> Result<(), Error> {
        if self.grants & grant::ADMIN == 0 {
            Err(Error::Unauthorized)
        } else {
            Ok(())
        }
    }
    // Protocol adapters call this once per public-key operation; keeping the
    // policy and primitive sequence here avoids a second wire-level copy.
    #[inline(always)]
    pub fn public_key(
        &mut self,
        role: usize,
        generate: bool,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<(Algorithm, usize), Error> {
        let a = if generate {
            self.admin()?;
            let a = Algorithm(repo::meta(p, role)?[key_meta::ALGORITHM]);
            p.crypto
                .key_operation(KeyOperation::Generate, a.0, &mut w.key, &[], &mut w.output)
                .map_err(|_| Error::Crypto)?;
            repo::save_key(p, role, 1, &w.key.bytes)?;
            a
        } else {
            repo::load_key(p, role, &mut w.key.bytes)?
        };
        let n = p
            .crypto
            .key_operation(KeyOperation::Public, a.0, &mut w.key, &[], &mut w.output)
            .map_err(|_| Error::Crypto)?;
        Ok((a, n))
    }
    pub fn prepare(
        &mut self,
        r: usize,
        key: &mut [u8; crate::ports::key_layout::SIZE],
        p: &mut Platform<'_>,
    ) -> Result<Algorithm, Error> {
        let bit = if r == key_role::SIGNATURE {
            grant::SIGNATURE
        } else {
            grant::OTHER
        };
        if self.grants & bit == 0 {
            return Err(Error::Unauthorized);
        }
        let a = repo::load_key(p, r, key)?;
        let policy = pw1_policy(p)?;
        // Single-use PW1 authorization is consumed before touch/crypto, so a
        // later failure cannot accidentally leave a reusable signature grant.
        if r == key_role::SIGNATURE && policy[0] == 0 {
            self.grants &= !grant::SIGNATURE;
        }
        Ok(a)
    }
    // The adapter has already validated the APDU shape; this boundary owns
    // authorization consumption, touch policy and the native operation.
    #[inline(always)]
    pub fn execute(
        &mut self,
        r: usize,
        a: Algorithm,
        input: core::ops::Range<usize>,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<usize, Error> {
        if input.end > w.input.len() {
            return Err(Error::Length);
        }
        // Prepare and execute are separate protocol phases; re-read the
        // durable policy here before applying touch and reuse decisions.
        let policy = pw1_policy(p)?;
        let op = if r != key_role::DECIPHER {
            if a.rsa() {
                KeyOperation::RsaPkcs1Sign
            } else {
                KeyOperation::EcSign
            }
        } else if a.rsa() {
            KeyOperation::RsaPkcs1Decipher
        } else {
            KeyOperation::Agree
        };
        let used = input.len();
        let mut m = repo::meta(p, r)?;
        if m[key_meta::TOUCH_POLICY] != touch_policy::DISABLED {
            let now = p.device.now();
            if !(self.touch_valid
                && policy[1] != 0
                && now.wrapping_sub(self.last_touch) < u32::from(policy[1]) * 1000)
            {
                if !self.presence.wait(p.device) {
                    return Err(Error::Presence);
                }
                self.last_touch = p.device.now();
                self.touch_valid = true;
            }
        }
        // A native Weierstrass digest is a scalar-width integer.
        // Normalize in session input; it is no longer needed as wire data.
        let input = if r != key_role::DECIPHER
            && matches!(a.0, alg::P256 | alg::SECP256K1 | alg::P384 | alg::P521)
        {
            let width = a.private_component_bytes();
            if width == 0 || used > width {
                return Err(Error::Length);
            }
            w.input.copy_within(input.clone(), width - used);
            w.input[..width - used].fill(0);
            &w.input[..width]
        } else {
            &w.input[input]
        };
        let n = p
            .crypto
            .key_operation(op, a.0, &mut w.key, input, &mut w.output)
            .map_err(|_| Error::Crypto)?;
        // Publish the signature counter before returning the signature. A
        // persistence error fails the operation rather than exposing an
        // unaccounted signature; the three-byte counter saturates at FFFFFF.
        if r == key_role::SIGNATURE {
            let count = u32::from_be_bytes([
                0,
                m[key_meta::SIGNATURE_COUNTER],
                m[key_meta::SIGNATURE_COUNTER + 1],
                m[key_meta::SIGNATURE_COUNTER + 2],
            ])
            .saturating_add(1)
            .min(0xffffff);
            m[key_meta::SIGNATURE_COUNTER..key_meta::END]
                .copy_from_slice(&count.to_be_bytes()[1..]);
            repo::put_meta(p, r, &m)?;
        }
        Ok(n)
    }
}

impl Session {
    pub fn verify_pin(&mut self, bit: u8, value: &[u8], p: &mut Platform<'_>) -> Result<(), Error> {
        let id = if bit == grant::ADMIN {
            Record::PgpPw3
        } else {
            Record::PgpPw1
        };
        self.grants &= !bit;
        if let Err(error) = super::pin::verify(id, value, p) {
            self.grants &= if bit == grant::ADMIN {
                !grant::ADMIN
            } else {
                !grant::PW1
            };
            return Err(error);
        }
        self.grants |= bit;
        Ok(())
    }
    pub fn change_pin(
        &mut self,
        id: Record,
        value: &[u8],
        p: &mut Platform<'_>,
    ) -> Result<(), Error> {
        self.grants &= if matches!(id, Record::PgpPw1) {
            !grant::PW1
        } else {
            !grant::ADMIN
        };
        let n = super::pin::info(id, p)?.length_bytes;
        if value.len() < n {
            return Err(Error::Length);
        }
        super::pin::verify(id, &value[..n], p)?;
        super::pin::change(id, &value[n..], p)
    }
    pub fn reset_pw1(
        &mut self,
        use_admin: bool,
        value: &[u8],
        p: &mut Platform<'_>,
    ) -> Result<(), Error> {
        self.grants &= !grant::PW1;
        let n = if use_admin {
            self.admin()?;
            0
        } else {
            let n = super::pin::info(Record::PgpRc, p)?.length_bytes;
            if value.len() < n {
                return Err(Error::Length);
            }
            super::pin::verify(Record::PgpRc, &value[..n], p)?;
            n
        };
        super::pin::change(Record::PgpPw1, &value[n..], p)
    }
}
