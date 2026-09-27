// SPDX-License-Identifier: Apache-2.0
//! OpenPGP role/length/error policy over shared credential records. No session grants.
use super::domain::Error;
use crate::{
    Platform,
    mechanisms::pin::{self as pin_mechanism, Charge, PinInfo, RecordPin},
    ports::Record,
};
fn credential(id: Record) -> RecordPin {
    RecordPin {
        id,
        stored_min: 0,
        fixed_limit: None,
    }
}
fn min(id: Record) -> usize {
    if matches!(id, Record::PgpPw1) { 6 } else { 8 }
}
fn error(e: pin_mechanism::Error) -> Error {
    match e {
        pin_mechanism::Error::Persistence => Error::Storage,
        pin_mechanism::Error::Length => Error::Length,
        pin_mechanism::Error::Blocked => Error::Blocked,
        pin_mechanism::Error::Retries(_) => Error::Unauthorized,
    }
}
pub fn create(id: Record, pin: &[u8], limit: u8, p: &mut Platform<'_>) -> Result<(), Error> {
    credential(id).create(pin, limit, p).map_err(error)
}
pub fn info(id: Record, p: &mut Platform<'_>) -> Result<PinInfo, Error> {
    credential(id).info(p).map_err(error)
}
pub fn verify(id: Record, pin: &[u8], p: &mut Platform<'_>) -> Result<(), Error> {
    credential(id)
        .verify(pin, min(id), Charge::BeforeCompare, p)
        .map_err(error)
}
pub fn change(id: Record, value: &[u8], p: &mut Platform<'_>) -> Result<(), Error> {
    credential(id).change(value, min(id), p).map_err(error)
}
pub fn retry_limit(id: Record, limit: u8, p: &mut Platform<'_>) -> Result<(), Error> {
    credential(id).retry_limit(limit, p).map_err(error)
}
