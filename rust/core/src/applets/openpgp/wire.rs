// SPDX-License-Identifier: Apache-2.0
//! OpenPGP Card 3.4 command and data-object assignments.
//! INS is the APDU instruction byte; a tag identifies a BER-TLV data object (DO).
//! SIG/DEC/AUT mean signature/decipher/authentication key roles. These values
//! belong to the card protocol, not the native crypto algorithm-ID namespace.
pub(super) mod ins {
    pub const INS_VERIFY: u8 = 0x20;
    pub const INS_CHANGE_REFERENCE_DATA: u8 = 0x24;
    pub const INS_RESET_RETRY_COUNTER: u8 = 0x2c;
    pub const INS_SELECT_DATA: u8 = 0xa5;
    pub const INS_GET_DATA: u8 = 0xca;
    pub const INS_GET_NEXT_DATA: u8 = 0xcc;
    pub const INS_PUT_DATA: u8 = 0xda;
    pub const INS_IMPORT_KEY: u8 = 0xdb;
    pub const INS_GENERATE_KEY: u8 = 0x47;
    pub const INS_INTERNAL_AUTHENTICATE: u8 = 0x88;
    pub const INS_PERFORM_SECURITY_OPERATION: u8 = 0x2a;
    pub const INS_GET_CHALLENGE: u8 = 0x84;
    pub const INS_TERMINATE: u8 = 0xe6;
    pub const INS_ACTIVATE: u8 = 0x44;
    // CanoKey extension (not OpenPGP Card 3.4): see docs/openpgp.md.
    pub const INS_SET_RETRIES: u8 = 0xf2;
}
pub(super) mod tag {
    pub const AID: u16 = 0x004f;
    pub const NAME: u16 = 0x005b;
    pub const LOGIN: u16 = 0x005e;
    pub const LANGUAGE: u16 = 0x5f2d;
    pub const SEX: u16 = 0x5f35;
    pub const URL: u16 = 0x5f50;
    pub const HISTORICAL_BYTES: u16 = 0x5f52;
    pub const CARDHOLDER: u16 = 0x0065;
    pub const APPLICATION: u16 = 0x006e;
    // Container DO 73 groups applet-specific capabilities, key and PIN metadata.
    pub const DISCRETIONARY: u16 = 0x0073;
    pub const GENERAL_FEATURES: u16 = 0x7f74;
    pub const EXTENDED_CAPABILITIES: u16 = 0x00c0;
    pub const ALGORITHM_SIG: u16 = 0x00c1;
    pub const ALGORITHM_DEC: u16 = 0x00c2;
    pub const ALGORITHM_AUT: u16 = 0x00c3;
    pub const PW_STATUS: u16 = 0x00c4;
    pub const FINGERPRINTS: u16 = 0x00c5;
    pub const CA_FINGERPRINTS: u16 = 0x00c6;
    pub const FINGERPRINT_SIG: u16 = 0x00c7;
    pub const FINGERPRINT_AUT: u16 = 0x00c9;
    pub const CA_FINGERPRINT_1: u16 = 0x00ca;
    pub const CA_FINGERPRINT_3: u16 = 0x00cc;
    pub const CREATION_TIMES: u16 = 0x00cd;
    pub const CREATED_SIG: u16 = 0x00ce;
    pub const CREATED_AUT: u16 = 0x00d0;
    pub const RESET_CODE: u16 = 0x00d3;
    // User Interaction Flag (UIF): touch policy plus the supported input method.
    pub const UIF_SIG: u16 = 0x00d6;
    pub const UIF_DEC: u16 = 0x00d7;
    pub const UIF_AUT: u16 = 0x00d8;
    pub const KEY_INFORMATION: u16 = 0x00de;
    pub const SECURITY_SUPPORT: u16 = 0x007a;
    pub const SIGNATURE_COUNTER: u16 = 0x0093;
    pub const TOUCH_CACHE: u16 = 0x0102;
    pub const ALGORITHM_INFORMATION: u16 = 0x00fa;
    pub const CERTIFICATE: u16 = 0x7f21;
}
// Key control references and password references are separate protocol fields.
// PW1 is the user PIN: 81 authorizes signing, 82 authorizes other operations.
// PW3 is the administrator PIN. The reset code (RC) is a separate credential.
pub(super) mod reference {
    pub const SIGNATURE: u8 = 0xb6;
    pub const DECIPHER: u8 = 0xb8;
    pub const AUTHENTICATION: u8 = 0xa4;
    pub const PW1_SIGNATURE: u8 = 0x81;
    pub const PW1_OTHER: u8 = 0x82;
    pub const PW3: u8 = 0x83;
}
pub(super) mod key_tag {
    pub const IMPORT: u8 = 0x4d;
    pub const COMPONENT_LENGTHS: [u8; 2] = [0x7f, 0x48];
    pub const COMPONENT_VALUES: [u8; 2] = [0x5f, 0x48];
    pub const RSA_COMPONENTS: [u8; 6] = [0x91, 0x92, 0x93, 0x94, 0x95, 0x96];
    pub const PRIVATE: u8 = 0x92;
    pub const PUBLIC: u8 = 0x99;
    pub const KEY_REFERENCE: [u8; 3] = [0x84, 0x01, 0x01];
    pub const PUBLIC_TEMPLATE: u16 = 0x7f49;
    pub const MODULUS: u16 = 0x81;
    pub const EXPONENT: u8 = 0x82;
    pub const POINT: u16 = 0x86;
    pub const AGREEMENT_TEMPLATE: u16 = 0xa6;
    pub const PSO_SIGNATURE: u16 = 0x9e9a;
    pub const PSO_DECIPHER: u16 = 0x8086;
}

/// Byte limits for an entire logical command, including all chained APDUs.
/// These bound accepted input, not per-frame buffers or RAM allocations.
pub(super) mod limits {
    // RSA-4096 import carries e plus five 256-byte CRT components, with room
    // for the 4D envelope and 7F48/5F48 descriptors. Components stream into
    // the key workspace; the complete 1400-byte request is never buffered.
    pub const KEY_IMPORT_BYTES: u16 = 1400;
    // Cardholder certificate limit, also advertised in Extended Capabilities
    // (DO C0). Certificate PUT DATA streams directly into a storage transaction.
    pub const CERTIFICATE_BYTES: u16 = 1152;
    // Largest ordinary input: one RSA-4096 ciphertext (512 bytes) preceded by
    // the decipher command's one-byte padding indicator.
    pub const ORDINARY_COMMAND_BYTES: u16 = 513;
}
