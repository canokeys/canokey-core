// SPDX-License-Identifier: Apache-2.0
//! PIV card wire assignments (NIST SP 800-73 plus CanoKey extensions).
//! INS is the APDU instruction byte. TLV means tag/length/value; GA means
//! GENERAL AUTHENTICATE. wire_alg identifies algorithms on the card interface,
//! while ports::alg identifies primitives in the C/Rust crypto ABI.
pub(super) mod ins {
    pub const INS_ATTEST: u8 = 0xf9;
    pub const INS_PUT_DATA: u8 = 0xdb;
    pub const INS_IMPORT_KEY: u8 = 0xfe;
    pub const INS_GENERAL_AUTHENTICATE: u8 = 0x87;
    pub const INS_NAME: u8 = 0xf5;
    pub const INS_VERIFY: u8 = 0x20;
    pub const INS_CHANGE_REFERENCE_DATA: u8 = 0x24;
    pub const INS_RESET_RETRY_COUNTER: u8 = 0x2c;
    pub const INS_GET_CHALLENGE: u8 = 0x84;
    pub const INS_GET_VERSION: u8 = 0xfd;
    pub const INS_GET_SERIAL: u8 = 0xf8;
    pub const INS_GET_DATA: u8 = 0xcb;
    pub const INS_GENERATE_KEY: u8 = 0x47;
    pub const INS_GET_METADATA: u8 = 0xf7;
    pub const INS_MOVE_KEY: u8 = 0xf6;
    pub const INS_SET_MANAGEMENT_KEY: u8 = 0xff;
    pub const INS_SET_RETRIES: u8 = 0xfa;
    pub const INS_RESET: u8 = 0xfb;
    pub const INS_CONFIG: u8 = 0xee;
}
pub(super) mod ga_tag {
    pub const TEMPLATE: u8 = 0x7c;
    pub const WITNESS: u8 = 0x80;
    pub const CHALLENGE: u8 = 0x81;
    pub const RESPONSE: u8 = 0x82;
    pub const EXPONENTIATION: u8 = 0x85;
    pub const PEER_STATIC: u8 = 0x86;
    pub const PEER_EPHEMERAL: u8 = 0x87;
    pub const PEER_ID: u8 = 0x88;
    pub const OUTPUT_LENGTH: u8 = 0x89;
}
// Dense indexes used by the GA parser, derived from wire tags. They are not
// byte offsets into a received APDU; each entry records a parsed field range.
pub(super) mod ga_field {
    use super::ga_tag;
    pub const WITNESS: usize = 0;
    pub const CHALLENGE: usize = (ga_tag::CHALLENGE - ga_tag::WITNESS) as usize;
    pub const RESPONSE: usize = (ga_tag::RESPONSE - ga_tag::WITNESS) as usize;
    pub const EXPONENTIATION: usize = (ga_tag::EXPONENTIATION - ga_tag::WITNESS) as usize;
    pub const COUNT: usize = EXPONENTIATION + 1;
}
pub(super) mod key_tag {
    pub const GENERATION_TEMPLATE: u8 = 0xac;
    pub const ALGORITHM: u8 = 0x80;
    pub const PIN_POLICY: u8 = 0xaa;
    pub const TOUCH_POLICY: u8 = 0xab;
    pub const PUBLIC_TEMPLATE: [u8; 2] = [0x7f, 0x49];
    pub const MODULUS: u8 = 0x81;
    pub const EXPONENT: u8 = 0x82;
    pub const PUBLIC_POINT: u8 = 0x86;
    pub const IMPORT_RSA_P: u8 = 1;
    pub const IMPORT_EC: u8 = 6;
    pub const IMPORT_ED25519: u8 = 7;
    pub const IMPORT_X25519: u8 = 8;
    pub const IMPORT_MLDSA: u8 = 9;
    pub const IMPORT_MLKEM: u8 = 10;
}
// Credential references: PIN is the user secret, PUK is the PIN unblocking
// key, and MANAGEMENT selects AES management-key authentication.
pub(super) mod reference {
    pub const PIN: u8 = 0x80;
    pub const PUK: u8 = 0x81;
    pub const MANAGEMENT: u8 = 0x9b;
}
pub(super) mod wire_alg {
    pub const DEFAULT: u8 = 0x00;
    pub const RSA2048: u8 = 0x07;
    pub const AES192: u8 = 0x0a;
    pub const P256: u8 = 0x11;
    pub const P384: u8 = 0x14;
    pub const ED25519_STREAM: u8 = 0xff;
}
pub(super) mod policy {
    pub const DEFAULT: u8 = 0;
    pub const PIN_NEVER: u8 = 1;
    pub const PIN_ONCE: u8 = 2;
    pub const PIN_ALWAYS: u8 = 3;
    pub const TOUCH_NEVER: u8 = 1;
    pub const TOUCH_ALWAYS: u8 = 2;
    pub const TOUCH_CACHED: u8 = 3;
    pub const TOUCH_CACHE_MS: u32 = 15_000;
}
pub(super) mod slot {
    pub const AUTHENTICATION: u8 = 0x9a;
    pub const SIGNATURE: u8 = 0x9c;
    pub const KEY_MANAGEMENT: u8 = 0x9d;
    pub const CARD_AUTHENTICATION: u8 = 0x9e;
    pub const ATTESTATION: u8 = 0xf9;
}
pub(super) mod object_tag {
    pub const CERT_AUTHENTICATION: u32 = 0x5fc105;
    pub const CERT_SIGNATURE: u32 = 0x5fc10a;
    pub const CERT_KEY_MANAGEMENT: u32 = 0x5fc10b;
    pub const CERT_CARD_AUTHENTICATION: u32 = 0x5fc101;
    pub const CERT_RETIRED_FIRST: u32 = 0x5fc10d;
    pub const CERT_RETIRED_LAST: u32 = 0x5fc120;
    pub const CERT_ATTESTATION: u32 = 0x5fff01;
    pub const CHUID: u32 = 0x5fc102;
    pub const FINGERPRINTS: u32 = 0x5fc103;
    pub const SECURITY: u32 = 0x5fc106;
    pub const CAPABILITY: u32 = 0x5fc107;
    pub const FACIAL_IMAGE: u32 = 0x5fc108;
    pub const PRINTED_INFORMATION: u32 = 0x5fc109;
    pub const KEY_HISTORY: u32 = 0x5fc10c;
    pub const IRIS_IMAGES: u32 = 0x5fc121;
    pub const ADMIN: u32 = 0x5fff00;
}
pub(super) mod object_tlv {
    pub const TAG_LIST: u8 = 0x5c;
    pub const DATA: u8 = 0x53;
    pub const CERTIFICATE: u8 = 0x70;
    pub const DISCOVERY: u32 = 0x7e;
    pub const MAX_TAG_BYTES: usize = 3;
    pub const SELECT_P1: u8 = 0x3f;
    pub const SELECT_P2: u8 = 0xff;
}
// GET METADATA response tags (F7): algorithm, PIN/touch policy, key origin,
// public key, factory-default indicator, and retry limit/remaining count.
pub(super) mod metadata_tag {
    pub const ALGORITHM: u8 = 1;
    pub const POLICY: u8 = 2;
    pub const ORIGIN: u8 = 3;
    pub const PUBLIC_KEY: u8 = 4;
    pub const DEFAULT: u8 = 5;
    pub const RETRIES: u8 = 6;
}

/// Accepted logical-command byte counts, accumulated across short APDU chains.
/// Streaming limits do not reserve equivalently sized RAM buffers.
pub(super) mod limits {
    // Stored certificate TLV quota, shared by PUT routing and object storage.
    pub const CERTIFICATE_OBJECT_BYTES: usize = 6568;
    // PUT adds a 5C selector: tag, length, and up to three object-ID bytes.
    pub const PUT_DATA_BYTES: u32 = (CERTIFICATE_OBJECT_BYTES + 5) as u32;
    // Five RSA-4096 CRT components plus import TLVs and optional policies.
    pub const KEY_IMPORT_BYTES: u32 = 1400;
    // GA uses the decoder's two-byte BER length ceiling. Long message values
    // are fed directly to crypto; the per-algorithm handlers impose extra limits.
    pub const GENERAL_AUTHENTICATE_BYTES: u32 = u16::MAX as u32;
}
