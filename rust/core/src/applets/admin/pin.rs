// SPDX-License-Identifier: Apache-2.0
//! ADMIN policy over the shared credential mechanism. Grants belong to the applet.
pub(crate) use crate::mechanisms::pin::Error;
use crate::{
    Platform,
    mechanisms::pin::{Charge, RecordPin},
    ports::Record,
};
const PIN: RecordPin = RecordPin {
    id: Record::AdminPin,
    stored_min: 6,
    fixed_limit: Some(3),
};
pub fn change(pin: &[u8], p: &mut Platform<'_>) -> Result<(), Error> {
    PIN.change(pin, 6, p)
}
pub fn install(p: &mut Platform<'_>) -> Result<(), Error> {
    PIN.install(b"123456", 3, p)
}
pub fn retries(p: &mut Platform<'_>) -> Result<u8, Error> {
    PIN.info(p).map(|(_, n, _)| n)
}
pub fn verify(pin: &[u8], p: &mut Platform<'_>) -> Result<(), Error> {
    // Preserve ADMIN's length error even when storage is unavailable or blocked.
    if !(6..=64).contains(&pin.len()) {
        return Err(Error::Length);
    }
    PIN.verify(pin, 6, Charge::OnMismatch, p)
}
/// Registry calls only after locked-PIN and strong-presence checks, with PIN last.
pub fn factory_reset(p: &mut Platform<'_>) -> Result<(), Error> {
    PIN.create(b"123456", 3, p)
}
