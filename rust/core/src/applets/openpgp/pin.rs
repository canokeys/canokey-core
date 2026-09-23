// SPDX-License-Identifier: Apache-2.0
//! OpenPGP role/length/error policy over shared credential records. No session grants.
use super::domain::Error;
use crate::{
    Platform,
    mechanisms::pin::{self, Charge, RecordPin},
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
fn error(e: pin::Error) -> Error {
    match e {
        pin::Error::Persistence => Error::Storage,
        pin::Error::Length => Error::Length,
        pin::Error::Blocked => Error::Blocked,
        pin::Error::Retries(_) => Error::Unauthorized,
    }
}
pub fn create(id: Record, pin: &[u8], limit: u8, p: &mut Platform<'_>) -> Result<(), Error> {
    credential(id).create(pin, limit, p).map_err(error)
}
pub fn info(id: Record, p: &mut Platform<'_>) -> Result<(usize, u8, u8), Error> {
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
