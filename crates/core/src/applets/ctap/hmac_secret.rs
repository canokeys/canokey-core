// SPDX-License-Identifier: Apache-2.0
//! Owned hmac-secret inputs and per-enumeration secrets; no Flash state.
//! Output uses shared IV-before-MAC encryption and erases failed output.
use super::wire::pin_protocol as wire;
use super::{
    Session, Status, credential,
    crypto::{mac, verify_mac},
    pin,
};
use crate::{ports::Platform, runtime::workspace::Workspace};
pub use canokey_ctap::request::hmac_secret::Parameters;
use canokey_ports::Memory as _;
#[cfg(test)]
pub(super) type Parser = canokey_ctap::request::hmac_secret::Parser<Status>;
const MAX_ENCRYPTED_SALT_BYTES: usize = canokey_ctap::extensions::hmac_secret::MAX_OUTPUT_BYTES;

const PREPARED_SALT_BYTES: usize = MAX_ENCRYPTED_SALT_BYTES;
pub(super) struct Prepared {
    // Both regions share one erasure lifetime: salts, then AES key.
    secrets: [u8; PREPARED_SALT_BYTES + 32],
    length: usize,
    protocol: u8,
}
impl Prepared {
    pub const fn new() -> Self {
        Self {
            secrets: [0; PREPARED_SALT_BYTES + 32],
            length: 0,
            protocol: wire::V1,
        }
    }
    pub fn clear(&mut self, memory: &(impl crate::ports::Memory + ?Sized)) {
        memory.wipe(&mut self.secrets);
        self.length = 0;
    }
    pub fn active(&self) -> bool {
        self.length != 0
    }
    pub fn output(
        &self,
        id: &credential::Id,
        rp: &[u8; 32],
        uv: bool,
        out: &mut [u8; MAX_ENCRYPTED_SALT_BYTES],
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<usize, Status> {
        let mut random = [0x00; 32];
        let result = (|| {
            credential::extension_key(
                if uv {
                    canokey_ctap::credential::ExtensionDomain::HmacSecretWithUv
                } else {
                    canokey_ctap::credential::ExtensionDomain::HmacSecretWithoutUv
                },
                id,
                rp,
                &mut random,
                p,
            )?;
            canokey_ctap::extensions::hmac_secret::output(
                pin::cipher_protocol(self.protocol),
                self.secrets[PREPARED_SALT_BYTES..].try_into().unwrap(),
                &random,
                &self.secrets[..self.length],
                out,
                &mut pin::PinCrypto(p),
            )
            .map_err(pin::cipher_error)
        })();
        p.memory.wipe(&mut random);
        if result.is_err() {
            p.memory.wipe(out);
        }
        result
    }
}
impl<B: crate::ports::Backends> canokey_ctap::extensions::hmac_secret::Output
    for pin::PinCrypto<'_, '_, B>
{
    #[inline(always)]
    fn mac(
        &mut self,
        key: &[u8; 32],
        salt: &[u8; 32],
        output: &mut [u8; 32],
    ) -> Result<(), Status> {
        mac(key, salt, output, self.0)
    }
}
impl Session {
    pub(super) fn prepare_hmac(
        &mut self,
        params: &Parameters,
        w: &mut Workspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<(), Status> {
        let mut shared = [0; 64];
        let result = (|| {
            self.decapsulate(params.protocol, &params.agreement, &mut shared, w, p)?;
            verify_mac(
                &shared[..32],
                &params.auth[..params.auth_len],
                &params.salt[..params.salt_len],
                p,
            )?;
            let prepared = &mut self.assertion.hmac;
            let (salts, aes_key) = prepared.secrets.split_at_mut(PREPARED_SALT_BYTES);
            aes_key.copy_from_slice(&shared[32..]);
            salts[..params.salt_len].copy_from_slice(&params.salt[..params.salt_len]);
            pin::decrypt(
                params.protocol,
                (&*aes_key).try_into().unwrap(),
                &mut salts[..params.salt_len],
                p,
            )?;
            prepared.protocol = params.protocol;
            prepared.length = params.salt_len
                - if params.protocol == wire::V2 {
                    wire::AES_BLOCK_BYTES
                } else {
                    0
                };
            Ok(())
        })();
        p.memory.wipe(&mut shared);
        if result.is_err() {
            self.assertion.hmac.clear(p.memory);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Erase;
    impl crate::ports::Memory for Erase {
        fn wipe(&self, bytes: &mut [u8]) {
            bytes.fill(0);
        }
    }

    #[test]
    fn clear_erases_key_and_unused_salt_capacity_for_both_protocols() {
        for protocol in [1, 2] {
            for length in [32, 64] {
                let mut prepared = Prepared::new();
                prepared.protocol = protocol;
                prepared.length = length;
                prepared.secrets[..PREPARED_SALT_BYTES].fill(0xa5);
                prepared.secrets[PREPARED_SALT_BYTES..].fill(0x5a);
                prepared.clear(&Erase);
                assert!(!prepared.active());
                assert!(prepared.secrets.iter().all(|&byte| byte == 0));
                assert_eq!(prepared.protocol, protocol);
                prepared.clear(&Erase);
                assert!(prepared.secrets.iter().all(|&byte| byte == 0));
            }
        }
    }
}
