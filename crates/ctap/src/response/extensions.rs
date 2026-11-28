// SPDX-License-Identifier: Apache-2.0
//! Authenticator-data extension maps over already prepared public outputs.
//! Product capabilities retain record reads, hmac-secret crypto and key erasure.
use super::encoding::{EncodeError, Encoder};
use crate::extensions::{Extension, name};

#[derive(Clone, Copy, Default)]
pub struct Fields {
    pub make: bool,
    pub protection: Option<u8>,
    pub min_pin_length: Option<u8>,
    pub cred_blob: Option<bool>,
    pub get_cred_blob: bool,
    pub hmac_secret: bool,
    pub hmac: bool,
    pub third_party_payment: bool,
}
impl Fields {
    /// Called before IO to decide ED and preserve the product preparation order.
    /// The hmac capability supplies a nonempty encrypted output when active.
    #[inline(always)]
    pub fn count(&self) -> u64 {
        u64::from(self.protection.is_some())
            + u64::from(self.min_pin_length.is_some())
            + u64::from(self.cred_blob.is_some() || self.get_cred_blob)
            + u64::from(self.hmac_secret)
            + u64::from(self.hmac)
            + u64::from(!self.make && self.third_party_payment)
    }
    /// CTAP extension names are in deterministic CBOR text-key order. Blob and
    /// encrypted hmac slices borrow existing caller buffers only for this call.
    /// The scalar capability inspection runs only at the third-party field; it
    /// must not perform IO, crypto or retain any response/workspace borrow.
    /// The registration hmac-secret acknowledgement precedes hmac-secret-mc;
    /// assertion hmac-secret contains encrypted salts instead of a boolean.
    #[inline(always)]
    pub fn encode(
        &self,
        e: &mut Encoder<&mut [u8]>,
        blob: &[u8],
        hmac: &[u8],
        third_party_accepted: impl FnOnce() -> bool,
    ) -> Result<(), EncodeError> {
        e.map(self.count());
        if let Some(accepted) = self.cred_blob {
            e.encoded(name(Extension::CredBlob)).bool(accepted);
        } else if self.get_cred_blob {
            e.encoded(name(Extension::CredBlob)).bytes(blob);
        }
        if let Some(protection) = self.protection {
            e.encoded(name(Extension::CredProtect)).u8(protection);
        }
        if self.hmac_secret {
            e.encoded(name(Extension::HmacSecret)).bool(true);
        }
        if !self.make && !hmac.is_empty() {
            e.encoded(name(Extension::HmacSecret)).bytes(hmac);
        }
        if let Some(minimum) = self.min_pin_length {
            e.encoded(name(Extension::MinPinLength)).u8(minimum);
        }
        if self.make && !hmac.is_empty() {
            e.encoded(name(Extension::HmacSecretMc)).bytes(hmac);
        }
        if !self.make && self.third_party_payment {
            e.encoded(name(Extension::ThirdPartyPayment))
                .bool(third_party_accepted());
        }
        e.finish()
    }
}
