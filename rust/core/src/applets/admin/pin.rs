// SPDX-License-Identifier: Apache-2.0
//! ADMIN policy over the shared credential mechanism. Grants belong to the applet.
pub(crate) use crate::mechanisms::pin::Error;
use crate::{
    Platform,
    mechanisms::pin::{Charge, RecordPin},
    ports::Record,
};
pub const MIN_LENGTH: usize = 6;
pub const MAX_LENGTH: usize = 64;
const RETRIES: u8 = 3;
const DEFAULT_PIN: &[u8] = b"123456";
const PIN: RecordPin = RecordPin {
    id: Record::AdminPin,
    stored_min: MIN_LENGTH as u8,
    fixed_limit: Some(RETRIES),
};
pub fn change(pin: &[u8], p: &mut Platform<'_>) -> Result<(), Error> {
    PIN.change(pin, MIN_LENGTH, p)
}
pub fn install(p: &mut Platform<'_>) -> Result<(), Error> {
    PIN.install(DEFAULT_PIN, RETRIES, p)
}
pub fn retries(p: &mut Platform<'_>) -> Result<u8, Error> {
    PIN.info(p).map(|info| info.retries_remaining)
}
pub fn verify(pin: &[u8], p: &mut Platform<'_>) -> Result<(), Error> {
    // Preserve ADMIN's length error even when storage is unavailable or blocked.
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&pin.len()) {
        return Err(Error::Length);
    }
    PIN.verify(pin, MIN_LENGTH, Charge::OnMismatch, p)
}
/// Registry calls only after locked-PIN and strong-presence checks, with PIN last.
pub fn factory_reset(p: &mut Platform<'_>) -> Result<(), Error> {
    let result = crate::runtime::config::reset_admin(p.storage);
    crate::runtime::config::notify(p);
    result.map_err(|_| Error::Persistence)?;
    PIN.create(DEFAULT_PIN, RETRIES, p)
}
