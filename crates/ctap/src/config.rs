// SPDX-License-Identifier: Apache-2.0
//! CTAP command bytes and request capacities derived from product policy.
use crate::ports::RequestLimits;
use core::marker::PhantomData;

/// Conservative wire-byte budget per stored public-key algorithm. A minimal
/// valid CBOR map {"alg": 0, "type": "public-key"} occupies 22 bytes (CTAP 2.3
/// §6.1, WebAuthn PublicKeyCredentialParameters). Using 20 preserves existing
/// capacities and leaves room beyond every complete descriptor that can fit.
pub const ALGORITHM_WIRE_BUDGET_BYTES: usize = 20;

/// One product policy supplies GetInfo, command-plus-CBOR transport admission,
/// and both borrowed and owned parsers. Concrete aliases can use these constants
/// as const generics without generic const expressions or runtime storage.
pub struct RequestConfig<L: RequestLimits>(PhantomData<L>);
impl<L: RequestLimits> RequestConfig<L> {
    pub const MAX_MESSAGE_BYTES: usize = {
        assert!(L::CTAP_REQUEST_MAX_BYTES > 1);
        assert!(L::CTAP_REQUEST_MAX_BYTES <= u16::MAX as usize);
        L::CTAP_REQUEST_MAX_BYTES
    };
    pub const MAX_MESSAGE_SIZE: u16 = Self::MAX_MESSAGE_BYTES as u16;
    /// The command byte is admitted by the transport, outside the CBOR parser.
    pub const CBOR_BYTES: u16 = (Self::MAX_MESSAGE_BYTES - 1) as u16;
    pub const ALGORITHM_CAPACITY: usize = Self::MAX_MESSAGE_BYTES / ALGORITHM_WIRE_BUDGET_BYTES;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    MakeCredential = 0x01,
    GetAssertion = 0x02,
    GetInfo = 0x04,
    ClientPin = 0x06,
    Reset = 0x07,
    GetNextAssertion = 0x08,
    CredentialManagement = 0x0a,
    Selection = 0x0b,
    LargeBlobs = 0x0c,
    Config = 0x0d,
    LegacyCredentialManagement = 0x41,
}

#[cfg(test)]
mod capacity_tests {
    use super::*;
    struct Limits<const BYTES: usize>;
    impl<const BYTES: usize> RequestLimits for Limits<BYTES> {
        const CTAP_REQUEST_MAX_BYTES: usize = BYTES;
        const NATIVE_MSG_MAX_BYTES: usize = BYTES;
    }
    #[test]
    fn product_profiles_share_message_parser_and_algorithm_derivations() {
        fn check<const BYTES: usize>(algorithms: usize) {
            assert_eq!(
                RequestConfig::<Limits<BYTES>>::MAX_MESSAGE_SIZE as usize,
                BYTES
            );
            assert_eq!(
                RequestConfig::<Limits<BYTES>>::CBOR_BYTES as usize + 1,
                BYTES
            );
            assert_eq!(
                RequestConfig::<Limits<BYTES>>::ALGORITHM_CAPACITY,
                algorithms
            );
            // Even the smallest valid complete descriptor cannot overflow the
            // owned algorithm array before the message byte budget is reached.
            assert!(algorithms >= BYTES / 22);
        }
        check::<1296>(64);
        check::<2048>(102);
    }
}
