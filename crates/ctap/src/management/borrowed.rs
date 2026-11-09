// SPDX-License-Identifier: Apache-2.0
//! Borrowed fields over a product reader; authentication retains the raw map.
use super::{Error, Fields, USER_ID_MAX, User, VENDOR_METADATA_ONLY};
use crate::request::Error as _;
use crate::request::credential::borrowed::Reader;

pub struct Envelope<'a> {
    pub subcommand: u8,
    pub parameters: &'a [u8],
    pub protocol: Option<u64>,
    pub auth: Option<&'a [u8]>,
}
impl<'a> Envelope<'a> {
    /// Header admission precedes parameter semantics, matching the streaming
    /// parser. The exact parameter bytes remain borrowed for authentication.
    pub fn decode<R: Reader<'a>>(bytes: &'a [u8]) -> Result<Self, R::Error> {
        R::validate(bytes)?;
        let mut reader = R::new(bytes);
        let (mut subcommand, mut parameters, mut protocol, mut auth) = (None, &[][..], None, None);
        for _ in 0..reader.map()? {
            match reader.uint()? {
                super::SUBCOMMAND => {
                    subcommand = Some(super::subcommand::<R::Error>(reader.uint()?)?);
                }
                super::PARAMETERS => {
                    parameters = reader.item()?;
                    R::new(parameters).map()?;
                }
                super::PIN_PROTOCOL => {
                    let raw = reader.item()?;
                    // CBOR negative integers are invalid protocol values;
                    // other major types retain UnexpectedType.
                    if raw[0] >> 5 == 0x01 {
                        return Err(R::Error::INVALID_PARAMETER);
                    }
                    let value = R::new(raw).uint()?;
                    super::protocol::<R::Error>(value)?;
                    protocol = Some(value);
                }
                super::PIN_AUTH => {
                    let bytes = reader.bytes()?;
                    super::auth_length::<R::Error>(bytes.len())?;
                    auth = Some(bytes);
                }
                _ => {
                    reader.item()?;
                }
            }
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
    let mut fields = Fields::default();
    if bytes.is_empty() {
        return Ok(fields);
    }
    let mut reader = R::new(bytes);
    for _ in 0..reader.map()? {
        match reader.uint()? {
            0x01 => {
                fields.rp = Some(
                    reader
                        .bytes()?
                        .try_into()
                        .map_err(|_| R::Error::INVALID_LENGTH)?,
                )
            }
            0x02 => {
                let mut public_key = false;
                for _ in 0..reader.map()? {
                    match reader.text()? {
                        "id" => {
                            fields.id = Some(
                                reader
                                    .bytes()?
                                    .try_into()
                                    .map_err(|_| R::Error::NO_CREDENTIALS)?,
                            )
                        }
                        "type" => public_key = reader.text()? == "public-key",
                        _ => {
                            reader.item()?;
                        }
                    }
                }
                if !public_key || fields.id.is_none() {
                    return Err(R::Error::MISSING_PARAMETER);
                }
            }
            0x03 => {
                let (mut id, mut name, mut display) = (None, None, None);
                for _ in 0..reader.map()? {
                    match reader.text()? {
                        "id" => {
                            let bytes = reader.bytes()?;
                            if bytes.is_empty() || bytes.len() > USER_ID_MAX {
                                return Err(R::Error::INVALID_LENGTH);
                            }
                            id = Some(bytes);
                        }
                        "name" => name = Some(reader.text()?),
                        "displayName" => display = Some(reader.text()?),
                        _ => {
                            reader.item()?;
                        }
                    }
                }
                fields.user = Some(User {
                    id: id.ok_or(R::Error::MISSING_PARAMETER)?,
                    name,
                    display,
                });
            }
            key if METADATA_ONLY && key == u64::from(VENDOR_METADATA_ONLY) => {
                fields.metadata_only = reader.boolean()?
            }
            _ => {
                reader.item()?;
            }
        }
    }
    Ok(fields)
}
