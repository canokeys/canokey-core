// SPDX-License-Identifier: Apache-2.0
//! Borrowed envelope framing; parameter semantics use the shared event parser.
use super::{Error, Fields};
use crate::request::{Error as _, credential::borrowed::Reader, stream::Key};

pub struct Envelope<'a> {
    pub subcommand: u8,
    pub parameters: &'a [u8],
    pub protocol: Option<u64>,
    pub auth: Option<&'a [u8]>,
}
impl<'a> Envelope<'a> {
    /// Header/framing errors precede deferred parameter semantics. Keep the exact
    /// encoded parameter map borrowed for MAC verification, without re-encoding.
    pub fn decode<R: Reader<'a>>(bytes: &'a [u8]) -> Result<Self, R::Error> {
        let mut reader = R::new(bytes);
        let (mut subcommand, mut parameters, mut protocol, mut auth) = (None, &[][..], None, None);
        let mut previous = None;
        for _ in 0..reader.map()? {
            match Key::<R::Error>::borrowed_ordered(&mut reader, &mut previous)? {
                Some(key) if key == super::SUBCOMMAND as i8 => {
                    subcommand = Some(super::subcommand::<R::Error>(reader.uint()?)?);
                }
                Some(key) if key == super::PARAMETERS as i8 => {
                    let start = reader.remaining();
                    // Require a map at its header before consuming its body.
                    // Parameter key/type/order errors are deferred until the
                    // complete envelope has passed, as in the owned consumer.
                    for _ in 0..reader.map()? {
                        reader.item()?;
                        reader.item()?;
                    }
                    parameters = &start[..start.len() - reader.remaining().len()];
                }
                Some(key) if key == super::PIN_PROTOCOL as i8 => {
                    let (negative, value) = reader.integer()?;
                    if negative {
                        return Err(R::Error::INVALID_PARAMETER);
                    }
                    super::protocol::<R::Error>(value)?;
                    protocol = Some(value);
                }
                Some(key) if key == super::PIN_AUTH as i8 => {
                    auth = Some(reader.bytes_checked(super::auth_length::<R::Error>)?);
                }
                _ => reader.skip_unknown()?,
            }
        }
        if !reader.done() {
            return Err(R::Error::INVALID_CBOR);
        }
        Ok(Self {
            subcommand: subcommand.ok_or(R::Error::MISSING_PARAMETER)?,
            parameters,
            protocol,
            auth,
        })
    }
}

pub fn fields<'a, R: Reader<'a>, const METADATA_ONLY: bool>(
    bytes: &'a [u8],
) -> Result<Fields<'a>, R::Error>
where
    R::Error: Error,
{
    super::stream::fields::<R::Error, METADATA_ONLY>(bytes)
}
