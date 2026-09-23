// SPDX-License-Identifier: Apache-2.0
//! Management-key challenge/response authentication.
use super::*;

impl Piv {
    pub(super) fn management_auth(
        &mut self,
        h: Header,
        f: &[Option<&[u8]>; 6],
        out: &mut [u8],
        p: &mut Platform<'_>,
    ) -> Result<u32, Sw> {
        if !matches!(h.p1, 0 | 8) {
            return Err(Sw::WRONG_P1P2);
        }
        let mut mgmt = repo::management(p)?;
        let r = (|| {
            self.touch(mgmt[1], p)?;
            let key: &[u8; 24] = mgmt[2..].try_into().unwrap();
            if f[0] == Some(&[][..]) || f[1] == Some(&[][..]) {
                self.admin = false;
                self.auth_clear(p);
                p.crypto
                    .random(&mut self.challenge)
                    .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
                let mutual = f[0].is_some();
                self.auth_mode = if mutual {
                    AuthMode::Mutual
                } else {
                    AuthMode::External
                };
                out[..4].copy_from_slice(&[0x7c, 18, if mutual { 0x80 } else { 0x81 }, 16]);
                if mutual {
                    p.crypto
                        .aes192(key, &self.challenge, (&mut out[4..20]).try_into().unwrap())
                        .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
                } else {
                    out[4..20].copy_from_slice(&self.challenge);
                    let mut expected = [0; 16];
                    p.crypto
                        .aes192(key, &self.challenge, &mut expected)
                        .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
                    self.challenge = expected;
                    p.memory.wipe(&mut expected);
                }
                self.memory(20);
                return Ok(20);
            }
            if let Some(response) = f[2] {
                if self.auth_mode != AuthMode::External || !codec::equal(response, &self.challenge)
                {
                    return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
                }
                self.auth_clear(p);
                self.admin = true;
                return Ok(0);
            }
            if let (Some(witness), Some(challenge)) = (f[0], f[1]) {
                if self.auth_mode != AuthMode::Mutual
                    || !codec::equal(witness, &self.challenge)
                    || challenge.len() != 16
                {
                    return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
                }
                out[..4].copy_from_slice(&[0x7c, 18, 0x82, 16]);
                p.crypto
                    .aes192(
                        key,
                        challenge.try_into().unwrap(),
                        (&mut out[4..20]).try_into().unwrap(),
                    )
                    .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
                self.auth_clear(p);
                self.admin = true;
                self.memory(20);
                return Ok(20);
            }
            Err(Sw::WRONG_DATA)
        })();
        p.memory.wipe(&mut mgmt);
        if r.is_err() {
            self.admin = false;
            self.auth_clear(p)
        }
        r
    }
}
