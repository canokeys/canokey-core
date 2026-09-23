// SPDX-License-Identifier: Apache-2.0
//! Separate PW1/PW3/reset-code records. No session grants in persistence.
use super::domain::Error;
use super::repository::io;
use crate::{Platform, ports::Record};
fn load(id: Record, p: &mut Platform<'_>, b: &mut [u8; 68]) -> Result<(), Error> {
    if p.storage.load(id, b).map_err(io)? != 68
        || b[0] != 1
        || b[1] > 64
        || b[2] > b[3]
        || b[3] == 0
    {
        return Err(Error::Storage);
    }
    Ok(())
}
pub fn create(id: Record, pin: &[u8], limit: u8, p: &mut Platform<'_>) -> Result<(), Error> {
    let mut b = [0; 68];
    b[..4].copy_from_slice(&[
        1,
        pin.len() as u8,
        if pin.is_empty() { 0 } else { limit },
        limit,
    ]);
    b[4..4 + pin.len()].copy_from_slice(pin);
    let r = p.storage.replace(id, &b).map_err(io);
    p.memory.wipe(&mut b);
    r
}
pub fn info(id: Record, p: &mut Platform<'_>) -> Result<(usize, u8, u8), Error> {
    let mut b = [0; 68];
    let r = load(id, p, &mut b).map(|_| (b[1] as usize, b[2], b[3]));
    p.memory.wipe(&mut b);
    r
}
pub fn verify(id: Record, pin: &[u8], p: &mut Platform<'_>) -> Result<(), Error> {
    let mut b = [0; 68];
    let r = (|| {
        load(id, p, &mut b)?;
        if b[2] == 0 {
            return Err(Error::Blocked);
        }
        let min = if matches!(id, Record::PgpPw1) { 6 } else { 8 };
        if !(min..=64).contains(&pin.len()) {
            return Err(Error::Length);
        }
        // Charge durably before comparing, including interruption during comparison.
        b[2] -= 1;
        p.storage.replace(id, &b).map_err(io)?;
        let diff = pin
            .iter()
            .zip(&b[4..])
            .fold(b[1] ^ pin.len() as u8, |v, (a, b)| v | (a ^ b));
        if diff != 0 {
            return Err(if b[2] == 0 {
                Error::Blocked
            } else {
                Error::Unauthorized
            });
        }
        b[2] = b[3];
        p.storage.replace(id, &b).map_err(io)
    })();
    p.memory.wipe(&mut b);
    r
}
pub fn change(id: Record, value: &[u8], p: &mut Platform<'_>) -> Result<(), Error> {
    let min = if matches!(id, Record::PgpPw1) { 6 } else { 8 };
    if !(min..=64).contains(&value.len()) {
        return Err(Error::Length);
    }
    let (_, _, limit) = info(id, p)?;
    create(id, value, limit, p)
}
pub fn retry_limit(id: Record, limit: u8, p: &mut Platform<'_>) -> Result<(), Error> {
    let mut b = [0; 68];
    let r = (|| {
        load(id, p, &mut b)?;
        b[3] = limit;
        b[2] = if b[1] == 0 { 0 } else { limit };
        p.storage.replace(id, &b).map_err(io)
    })();
    p.memory.wipe(&mut b);
    r
}
