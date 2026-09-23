// SPDX-License-Identifier: Apache-2.0
//! C-compatible PIN mechanism: PIN bytes, length and durable retry counters.
//! No KDF, hashing, enrollment protocol, APDU or session grant ownership.
#![forbid(unsafe_code)]
use crate::ports::{Platform, Record, StorageError};
const LENGTH: usize = 68;
const RETRIES: u8 = 3;
#[derive(Clone, Copy)]
pub enum Error {
    Persistence,
    Length,
    Blocked,
    Retries(u8),
}
fn load(p: &mut Platform<'_>, record: &mut [u8; LENGTH]) -> Result<(), Error> {
    if p.storage
        .load(Record::AdminPin, record)
        .map_err(|_| Error::Persistence)?
        != LENGTH
        || record[0] != 1
        || !(6..=64).contains(&record[1])
        || record[2] > RETRIES
        || record[3] != RETRIES
    {
        return Err(Error::Persistence);
    }
    Ok(())
}
fn save(p: &mut Platform<'_>, record: &[u8; LENGTH]) -> Result<(), Error> {
    p.storage
        .replace(Record::AdminPin, record)
        .map_err(|_| Error::Persistence)
}
fn create(pin: &[u8], p: &mut Platform<'_>) -> Result<(), Error> {
    let mut record = [0; LENGTH];
    record[..4].copy_from_slice(&[1, pin.len() as u8, RETRIES, RETRIES]);
    record[4..4 + pin.len()].copy_from_slice(pin);
    let result = save(p, &record);
    p.memory.wipe(&mut record);
    result
}
pub fn change(pin: &[u8], p: &mut Platform<'_>) -> Result<(), Error> {
    if !(6..=64).contains(&pin.len()) {
        return Err(Error::Length);
    }
    let mut record = [0; LENGTH];
    let result = load(p, &mut record);
    p.memory.wipe(&mut record);
    result?;
    create(pin, p)
}
pub fn install(p: &mut Platform<'_>) -> Result<(), Error> {
    let mut record = [0; LENGTH];
    let result = match p.storage.load(Record::AdminPin, &mut record) {
        Err(StorageError::Missing) => create(b"123456", p),
        Ok(_) => load(p, &mut record),
        Err(_) => Err(Error::Persistence),
    };
    p.memory.wipe(&mut record);
    result
}
pub fn retries(p: &mut Platform<'_>) -> Result<u8, Error> {
    let mut record = [0; LENGTH];
    let result = load(p, &mut record).map(|_| record[2]);
    p.memory.wipe(&mut record);
    result
}
pub fn verify(pin: &[u8], p: &mut Platform<'_>) -> Result<(), Error> {
    if !(6..=64).contains(&pin.len()) {
        return Err(Error::Length);
    }
    let mut record = [0; LENGTH];
    let result = (|| {
        load(p, &mut record)?;
        if record[2] == 0 {
            return Err(Error::Blocked);
        }
        // Evaluate both length and all supplied bytes without an early exit.
        let difference = pin
            .iter()
            .zip(&record[4..])
            .fold(record[1] ^ pin.len() as u8, |v, (a, b)| v | (a ^ b));
        if difference != 0 {
            record[2] -= 1;
            save(p, &record)?;
            return Err(if record[2] == 0 {
                Error::Blocked
            } else {
                Error::Retries(record[2])
            });
        }
        // Match C: a successful check writes only if retries need restoring.
        if record[2] != record[3] {
            record[2] = record[3];
            save(p, &record)?;
        }
        Ok(())
    })();
    p.memory.wipe(&mut record);
    result
}

/// Registry calls only after locked-PIN and strong-presence checks, with PIN last.
pub fn factory_reset(p: &mut Platform<'_>) -> Result<(), Error> {
    create(b"123456", p)
}
