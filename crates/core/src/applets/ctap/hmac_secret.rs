// SPDX-License-Identifier: Apache-2.0
//! Owned hmac-secret inputs and per-enumeration secrets; no Flash state.
//! Output uses shared IV-before-MAC encryption and erases failed output.
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

pub(super) struct Prepared(canokey_ctap::extensions::hmac_secret::Prepared);
impl Prepared {
    pub const fn new() -> Self {
        Self(canokey_ctap::extensions::hmac_secret::Prepared::new())
    }
    pub fn clear(&mut self, memory: &(impl crate::ports::Memory + ?Sized)) {
        self.0.clear(|bytes| memory.wipe(bytes));
    }
    pub fn active(&self) -> bool {
        self.0.active()
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
            self.0
                .output(&random, out, &mut pin::PinCrypto(p))
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
struct Preparation<'a, 'w, 'p, B: crate::ports::Backends> {
    pin: &'a mut canokey_ctap::client_pin::Session<u8>,
    workspace: &'a mut Workspace<'w>,
    platform: &'a mut Platform<'p, B>,
}
impl<B: crate::ports::Backends> canokey_ctap::extensions::hmac_secret::Input
    for Preparation<'_, '_, '_, B>
{
    type Error = Status;
    const INVALID_LENGTH: Status = Status::InvalidLength;
    fn decrypt(&mut self, protocol: canokey_ctap::client_pin::Protocol,
        key: &[u8; 32], encoded: &mut [u8]) -> Result<(), Status>
    {
        pin::decrypt(protocol as u8, key, encoded, self.platform)
    }
    fn agree(
        &mut self,
        protocol: canokey_ctap::client_pin::Protocol,
        peer: &[u8; 64],
        shared: &mut [u8; 64],
    ) -> Result<(), Status> {
        pin::decapsulate(
            self.pin,
            protocol as u8,
            peer,
            shared,
            self.workspace,
            self.platform,
        )
    }
    fn authenticate(
        &mut self,
        _: canokey_ctap::client_pin::Protocol,
        key: &[u8; 32],
        ciphertext: &[u8],
        auth: &[u8],
    ) -> Result<(), Status> {
        verify_mac(key, auth, ciphertext, self.platform)
    }
    fn wipe(&mut self, bytes: &mut [u8]) {
        self.platform.memory.wipe(bytes);
    }
}
impl Session {
    pub(super) fn prepare_hmac(
        &mut self,
        params: &Parameters,
        w: &mut Workspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<(), Status> {
        self.assertion
            .hmac
            .0
            .prepare(
                pin::cipher_protocol(params.protocol),
                &params.agreement,
                &params.salt[..params.salt_len],
                &params.auth[..params.auth_len],
                &mut Preparation {
                    pin: &mut self.pin,
                    workspace: w,
                    platform: p,
                },
            )
    }
}
