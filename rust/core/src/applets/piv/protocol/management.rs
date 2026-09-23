// SPDX-License-Identifier: Apache-2.0
//! Management-key challenge/response authentication.
use super::*;

impl Piv {
    pub(super) fn management_auth(
        &mut self,
        h: Header,
        f: &[Option<&[u8]>; ga_field::COUNT],
        out: &mut [u8],
        p: &mut Platform<'_>,
    ) -> Result<u32, Sw> {
        if !matches!(h.p1, wire_alg::DEFAULT | wire_alg::AES192) {
            return Err(Sw::WRONG_P1P2);
        }
        let mut mgmt = repo::management(p)?;
        let r = (|| {
            self.touch(mgmt[repo::MANAGEMENT_TOUCH], p)?;
            let key: &[u8; 24] = mgmt[repo::MANAGEMENT_KEY..].try_into().unwrap();
            if f[ga_field::WITNESS] == Some(&[][..]) || f[ga_field::CHALLENGE] == Some(&[][..]) {
                self.admin = false;
                self.auth_clear(p);
                p.crypto
                    .random(&mut self.challenge)
                    .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
                // External authentication sends plaintext and expects AES(K, R).
                // Mutual authentication sends AES(K, R) and expects plaintext R,
                // then encrypts the host challenge to prove possession of K.
                let mutual = f[ga_field::WITNESS].is_some();
                self.auth_mode = if mutual {
                    AuthMode::Mutual
                } else {
                    AuthMode::External
                };
                out[..4].copy_from_slice(&[
                    ga_tag::TEMPLATE,
                    18,
                    if mutual {
                        ga_tag::WITNESS
                    } else {
                        ga_tag::CHALLENGE
                    },
                    16,
                ]);
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
                    // In External mode this field now holds the expected
                    // ciphertext, not the random plaintext sent to the host.
                    self.challenge = expected;
                    p.memory.wipe(&mut expected);
                }
                self.memory(20);
                return Ok(20);
            }
            if let Some(response) = f[ga_field::RESPONSE] {
                if self.auth_mode != AuthMode::External || !codec::equal(response, &self.challenge)
                {
                    return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
                }
                self.auth_clear(p);
                self.admin = true;
                return Ok(0);
            }
            if let (Some(witness), Some(challenge)) = (f[ga_field::WITNESS], f[ga_field::CHALLENGE])
            {
                if self.auth_mode != AuthMode::Mutual
                    || !codec::equal(witness, &self.challenge)
                    || challenge.len() != 16
                {
                    return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
                }
                out[..4].copy_from_slice(&[ga_tag::TEMPLATE, 18, ga_tag::RESPONSE, 16]);
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
        // Any failed step revokes both authorization and the pending exchange.
        if r.is_err() {
            self.admin = false;
            self.auth_clear(p)
        }
        r
    }
}
