// SPDX-License-Identifier: Apache-2.0
//! CanoKey product storage ABI; these limits are not shared CTAP constraints.
/// CanoKey persisted record IDs, including its product-specific CTAP capacity.
/// Other products choose their own paths and resident-credential bounds.
/// The native backend preserves legacy NDEF filenames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Record(u8);
#[allow(non_upper_case_globals)]
impl Record {
    pub const Pass: Self = Self(0x00);
    pub const AdminPin: Self = Self(0x01);
    pub const OathMetadata: Self = Self(0x02);
    pub const OathRecords: Self = Self(0x03);
    pub const PgpState: Self = Self(0x04);
    pub const PgpPw1: Self = Self(0x05);
    pub const PgpPw3: Self = Self(0x06);
    pub const PgpRc: Self = Self(0x07);
    pub const PgpSig: Self = Self(0x08);
    pub const PgpDec: Self = Self(0x09);
    pub const PgpAut: Self = Self(0x0a);
    pub const PgpCertSig: Self = Self(0x0b);
    pub const PgpCertDec: Self = Self(0x0c);
    pub const PgpCertAut: Self = Self(0x0d);
    pub const PivState: Self = Self(0x0e);
    pub const PivManagement: Self = Self(0x0f);
    pub const PivConfig: Self = Self(0x10);
    pub const PivKey0: Self = Self(0x11);
    pub const PivKey1: Self = Self(0x12);
    pub const PivKey2: Self = Self(0x13);
    pub const PivKey3: Self = Self(0x14);
    pub const PivKey4: Self = Self(0x15);
    pub const PivKey5: Self = Self(0x16);
    pub const PivKey6: Self = Self(0x17);
    pub const PivKey7: Self = Self(0x18);
    pub const PivKey8: Self = Self(0x19);
    pub const PivKey9: Self = Self(0x1a);
    pub const PivKey10: Self = Self(0x1b);
    pub const PivKey11: Self = Self(0x1c);
    pub const PivKey12: Self = Self(0x1d);
    pub const PivKey13: Self = Self(0x1e);
    pub const PivKey14: Self = Self(0x1f);
    pub const PivKey15: Self = Self(0x20);
    pub const PivKey16: Self = Self(0x21);
    pub const PivKey17: Self = Self(0x22);
    pub const PivKey18: Self = Self(0x23);
    pub const PivKey19: Self = Self(0x24);
    pub const PivKey20: Self = Self(0x25);
    pub const PivKey21: Self = Self(0x26);
    pub const PivKey22: Self = Self(0x27);
    pub const PivKey23: Self = Self(0x28);
    pub const PivKey24: Self = Self(0x29);
    pub const PivObject0: Self = Self(0x2a);
    pub const PivObject1: Self = Self(0x2b);
    pub const PivObject2: Self = Self(0x2c);
    pub const PivObject3: Self = Self(0x2d);
    pub const PivObject4: Self = Self(0x2e);
    pub const PivObject5: Self = Self(0x2f);
    pub const PivObject6: Self = Self(0x30);
    pub const PivObject7: Self = Self(0x31);
    pub const PivObject8: Self = Self(0x32);
    pub const PivObject9: Self = Self(0x33);
    pub const PivObject10: Self = Self(0x34);
    pub const PivObject11: Self = Self(0x35);
    pub const PivObject12: Self = Self(0x36);
    pub const PivObject13: Self = Self(0x37);
    pub const PivObject14: Self = Self(0x38);
    pub const PivObject15: Self = Self(0x39);
    pub const PivObject16: Self = Self(0x3a);
    pub const PivObject17: Self = Self(0x3b);
    pub const PivObject18: Self = Self(0x3c);
    pub const PivObject19: Self = Self(0x3d);
    pub const PivObject20: Self = Self(0x3e);
    pub const PivObject21: Self = Self(0x3f);
    pub const PivObject22: Self = Self(0x40);
    pub const PivObject23: Self = Self(0x41);
    pub const PivObject24: Self = Self(0x42);
    pub const PivObject25: Self = Self(0x43);
    pub const PivObject26: Self = Self(0x44);
    pub const PivObject27: Self = Self(0x45);
    pub const PivObject28: Self = Self(0x46);
    pub const PivObject29: Self = Self(0x47);
    pub const PivObject30: Self = Self(0x48);
    pub const PivObject31: Self = Self(0x49);
    pub const PivObject32: Self = Self(0x4a);
    pub const PivObject33: Self = Self(0x4b);
    pub const PivProvision: Self = Self(0x4c);
    pub const CtapPin: Self = Self(0x4d);
    pub const CtapMaster: Self = Self(0x4e);
    pub const CtapCounter: Self = Self(0x4f);
    pub const CtapLargeBlob: Self = Self(0xb4);
    pub const CtapSm2: Self = Self(0xb5);
    pub const CtapAttestationKey: Self = Self(0xb6);
    pub const CtapCertificate: Self = Self(0xb7);
    pub const NdefCapability: Self = Self(0xb8);
    pub const NdefMessage: Self = Self(0xb9);
    pub const COUNT: usize = Self::NdefMessage.id() as usize + 1;
    /// Validate a raw ID in the backend namespace 0..=185, including reserved
    /// holes and CTAP group IDs. This does not imply an assigned or existing record.
    pub const fn from_id(id: u8) -> Option<Self> {
        if id <= Self::NdefMessage.0 {
            Some(Self(id))
        } else {
            None
        }
    }
    pub const fn id(self) -> u8 {
        self.0
    }
    // Group namespace starts immediately after CtapCounter (0x4f).
    pub const CTAP_GROUP_BASE: u8 = 0x50;
    pub const CTAP_CREDENTIALS: u8 = 100;
    pub const CTAP_GROUP_MEMBERS: u8 = 4;
    pub const CTAP_GROUPS: u8 = Self::CTAP_CREDENTIALS / Self::CTAP_GROUP_MEMBERS;
    pub const fn ctap_group(index: u8) -> Option<Self> {
        if index < Self::CTAP_GROUPS {
            Some(Self(Self::CTAP_GROUP_BASE + index))
        } else {
            None
        }
    }
}
