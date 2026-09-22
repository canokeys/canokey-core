// SPDX-License-Identifier: Apache-2.0
//! C-compatible PIN mechanism: PIN bytes, length and durable retry counters.
//! No KDF, hashing, enrollment protocol, APDU or session grant ownership.
#![forbid(unsafe_code)]
use crate::services::{Platform, Record, StorageError};
const LENGTH: usize = 68;
const RETRIES: u8 = 3;
#[derive(Clone, Copy)]
pub enum Error {
    Persistence,
    Length,
    Blocked,
    Retries(u8),
}
fn load(p: &mut dyn Platform, record: &mut [u8; LENGTH]) -> Result<(), Error> {
    if p.load(Record::AdminPin, record)
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
fn save(p: &mut dyn Platform, record: &[u8; LENGTH]) -> Result<(), Error> {
    p.replace(Record::AdminPin, record)
        .map_err(|_| Error::Persistence)
}
fn create(pin: &[u8], p: &mut dyn Platform) -> Result<(), Error> {
    let mut record = [0; LENGTH];
    record[..4].copy_from_slice(&[1, pin.len() as u8, RETRIES, RETRIES]);
    record[4..4 + pin.len()].copy_from_slice(pin);
    let result = save(p, &record);
    p.wipe(&mut record);
    result
}
pub fn change(pin: &[u8], p: &mut dyn Platform) -> Result<(), Error> {
    if !(6..=64).contains(&pin.len()) {
        return Err(Error::Length);
    }
    let mut record = [0; LENGTH];
    let result = load(p, &mut record);
    p.wipe(&mut record);
    result?;
    create(pin, p)
}
pub fn install(p: &mut dyn Platform) -> Result<(), Error> {
    let mut record = [0; LENGTH];
    let result = match p.load(Record::AdminPin, &mut record) {
        Err(StorageError::Missing) => create(b"123456", p),
        Ok(_) => load(p, &mut record),
        Err(_) => Err(Error::Persistence),
    };
    p.wipe(&mut record);
    result
}
pub fn retries(p: &mut dyn Platform) -> Result<u8, Error> {
    let mut record = [0; LENGTH];
    let result = load(p, &mut record).map(|_| record[2]);
    p.wipe(&mut record);
    result
}
pub fn verify(pin: &[u8], p: &mut dyn Platform) -> Result<(), Error> {
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
    p.wipe(&mut record);
    result
}

/// Registry calls only after locked-PIN and strong-presence checks, with PIN last.
pub fn factory_reset(p: &mut dyn Platform) -> Result<(), Error> {
    create(b"123456", p)
}
