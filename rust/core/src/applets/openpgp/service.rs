// SPDX-License-Identifier: Apache-2.0
//! OpenPGP session/key policy, independent of APDU and TLV encoding.
use super::{
    domain::{Algorithm, Error},
    repository::{self as repo, io},
};
use crate::{
    Platform,
    ports::{KeyOperation, Record},
    runtime::workspace::Workspace,
};
pub struct Session {
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
        if self.grants & 4 == 0 {
            Err(Error::Unauthorized)
        } else {
            Ok(())
        }
    }
    // One wire caller: fuse this boundary without duplicating policy code.
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
            let a = Algorithm(repo::meta(p, role)?[1]);
            p.crypto
                .key_operation(KeyOperation::Generate, a.0, &mut w.key, &[], &mut w.output)
                .map_err(|_| Error::Storage)?;
            repo::save_key(p, role, 1, &w.key.bytes)?;
            a
        } else {
            repo::load_key(p, role, &mut w.key.bytes)?
        };
        let n = p
            .crypto
            .key_operation(KeyOperation::Public, a.0, &mut w.key, &[], &mut w.output)
            .map_err(|_| Error::Storage)?;
        Ok((a, n))
    }
    pub fn prepare(
        &mut self,
        r: usize,
        key: &mut [u8; 1284],
        p: &mut Platform<'_>,
    ) -> Result<Algorithm, Error> {
        let bit = if r == 0 { 1 } else { 2 };
        if self.grants & bit == 0 {
            return Err(Error::Unauthorized);
        }
        let a = repo::load_key(p, r, key)?;
        let mut policy = [0; 2];
        p.storage
            .read_at(Record::PgpState, 2, &mut policy)
            .map_err(io)?;
        if r == 0 && policy[0] == 0 {
            self.grants &= !1;
        }
        Ok(a)
    }
    // One wire caller: fuse this boundary without duplicating policy code.
    #[inline(always)]
    pub fn execute(
        &mut self,
        r: usize,
        a: Algorithm,
        input: core::ops::Range<usize>,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<usize, Error> {
        let mut policy = [0; 2];
        p.storage
            .read_at(Record::PgpState, 2, &mut policy)
            .map_err(io)?;
        let op = if r != 1 {
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
        if m[3] != 0 {
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
        let input = if r != 1 && matches!(a.0, 0 | 1 | 2 | 8) {
            let width = a.scalar();
            w.input.copy_within(..used, width - used);
            w.input[..width - used].fill(0);
            &w.input[..width]
        } else {
            &w.input[input]
        };
        let n = p
            .crypto
            .key_operation(op, a.0, &mut w.key, input, &mut w.output)
            .map_err(|_| Error::Storage)?;
        if r == 0 {
            let count = u32::from_be_bytes([0, m[28], m[29], m[30]])
                .saturating_add(1)
                .min(0xffffff);
            m[28..31].copy_from_slice(&count.to_be_bytes()[1..]);
            repo::put_meta(p, r, &m)?;
        }
        Ok(n)
    }
}

impl Session {
    pub fn verify_pin(&mut self, bit: u8, value: &[u8], p: &mut Platform<'_>) -> Result<(), Error> {
        let id = if bit == 4 {
            Record::PgpPw3
        } else {
            Record::PgpPw1
        };
        self.grants &= !bit;
        if let Err(error) = super::pin::verify(id, value, p) {
            self.grants &= if bit == 4 { !4 } else { !3 };
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
        self.grants &= if matches!(id, Record::PgpPw1) { !3 } else { !4 };
        let n = super::pin::info(id, p)?.0;
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
        self.grants &= !3;
        let n = if use_admin {
            self.admin()?;
            0
        } else {
            let n = super::pin::info(Record::PgpRc, p)?.0;
            if value.len() < n {
                return Err(Error::Length);
            }
            super::pin::verify(Record::PgpRc, &value[..n], p)?;
            n
        };
        super::pin::change(Record::PgpPw1, &value[n..], p)
    }
}
