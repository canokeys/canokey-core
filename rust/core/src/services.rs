// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
/// IDs belong exclusively to the new /rust namespace, never legacy C files.
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Record {
    Pass = 0,
    AdminPin = 1,
    OathMetadata = 2,
    OathRecords = 3,
}
#[derive(Clone, Copy, Debug)]
pub enum StorageError {
    Missing,
    Unavailable,
    Uncertain,
}
pub trait Storage {
    #[cfg(feature = "oath")]
    fn size(&mut self, record: Record) -> Result<u32, StorageError>;
    #[cfg(feature = "oath")]
    fn read_at(
        &mut self,
        record: Record,
        offset: u32,
        output: &mut [u8],
    ) -> Result<(), StorageError>;
    #[cfg(feature = "oath")]
    fn replace_at(&mut self, record: Record, offset: u32, input: &[u8])
    -> Result<(), StorageError>;
    #[cfg(feature = "oath")]
    fn has_space(&mut self, bytes: u32, reserve: u32) -> Result<bool, StorageError>;
    fn load(&mut self, record: Record, output: &mut [u8]) -> Result<usize, StorageError>;
    /// Atomic replacement. Any failed mutation invalidates cached state.
    fn replace(&mut self, record: Record, input: &[u8]) -> Result<(), StorageError>;
}
pub trait Secrets {
    #[cfg(feature = "oath")]
    fn mac(
        &mut self,
        algorithm: u8,
        key: &[u8],
        input: &[u8],
        output: &mut [u8; 64],
    ) -> Result<(), StorageError>;
    #[cfg(feature = "oath")]
    fn random(&mut self, output: &mut [u8]) -> Result<(), StorageError>;
    #[cfg(feature = "oath")]
    fn serial(&mut self, output: &mut [u8; 4]);
    #[cfg(feature = "pass")]
    fn now(&mut self) -> u32;
    #[cfg(feature = "pass")]
    fn touched(&mut self) -> bool;
    /// Transport-only progress; false means reset/disconnect/cancel.
    #[cfg(feature = "pass")]
    fn progress(&mut self) -> bool;

    #[cfg(feature = "pass")]
    fn led(&mut self, on: bool);

    fn wipe(&mut self, bytes: &mut [u8]);
    fn hmac_sha1(&mut self, key: &[u8; 20], input: &[u8], output: &mut [u8; 20]);
}
pub trait Platform: Storage + Secrets {}
impl<T: Storage + Secrets> Platform for T {}
