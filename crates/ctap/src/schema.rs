// SPDX-License-Identifier: Apache-2.0
//! Host-only GetInfo compiler. Products declare capabilities; this module owns
//! CTAP field identifiers, container lengths and standard value encodings.
//! It reads no environment or product files and adds no firmware parser.
use crate::{
    client_pin::Protocol,
    info::{Flag, Value},
};
use minicbor::{Encoder, encode::Error};
use std::{convert::Infallible, format, string::String, vec::Vec};

type E = Encoder<Vec<u8>>;
type R = Result<(), Error<Infallible>>;

pub enum Boolean {
    Fixed(bool),
    AlwaysUv,
    ClientPin,
    MakeCredUvNotRqd,
}
pub enum Algorithm {
    Fixed(i32),
    /// The product resolves its configured algorithm at request time.
    Configured,
}

/// Fields follow CTAP 2.3 section 6.4, authenticatorGetInfo. Declarations must
/// use increasing field order. Limits are bytes or counts as named; algorithm
/// values are COSE identifiers. Optional product capabilities stay absent.
pub enum Field<'a> {
    Versions {
        u2f: bool,
        vendor: &'a [&'a str],
    },
    Extensions(&'a [&'a str]),
    Aaguid,
    Options(&'a [(&'a str, Boolean)]),
    MaxMessageSize(u16),
    PinUvAuthProtocols,
    MaxCredentialCountInList(u8),
    MaxCredentialIdLength(u16),
    Transports(&'a [&'a str]),
    /// Runtime NFC capability prepends "nfc" to the fixed transport list.
    NfcTransports(&'a [&'a str]),
    Algorithms(&'a [Algorithm]),
    MaxSerializedLargeBlobArray(u16),
    ForcePinChange,
    MinimumPinLength,
    FirmwareVersion(u32),
    MaxCredBlobLength(u8),
    MaxRpIdsForSetMinPinLength(u8),
    RemainingDiscoverableCredentials,
    AttestationFormats(&'a [&'a str]),
    LongTouchForReset,
    TransportsForReset(&'a [&'a str]),
    MaxPinLength(u8),
    AuthenticatorConfigCommands(&'a [u8]),
}
impl Field<'_> {
    fn key(&self) -> u8 {
        match self {
            Self::Versions { .. } => 0x01,
            Self::Extensions(_) => 0x02,
            Self::Aaguid => 0x03,
            Self::Options(_) => 0x04,
            Self::MaxMessageSize(_) => 0x05,
            Self::PinUvAuthProtocols => 0x06,
            Self::MaxCredentialCountInList(_) => 0x07,
            Self::MaxCredentialIdLength(_) => 0x08,
            Self::Transports(_) | Self::NfcTransports(_) => 0x09,
            Self::Algorithms(_) => 0x0a,
            Self::MaxSerializedLargeBlobArray(_) => 0x0b,
            Self::ForcePinChange => 0x0c,
            Self::MinimumPinLength => 0x0d,
            Self::FirmwareVersion(_) => 0x0e,
            Self::MaxCredBlobLength(_) => 0x0f,
            Self::MaxRpIdsForSetMinPinLength(_) => 0x10,
            Self::RemainingDiscoverableCredentials => 0x14,
            Self::AttestationFormats(_) => 0x16,
            Self::LongTouchForReset => 0x18,
            Self::TransportsForReset(_) => 0x1a,
            Self::MaxPinLength(_) => 0x1d,
            Self::AuthenticatorConfigCommands(_) => 0x1f,
        }
    }
}

enum Fragment {
    Encoded(Vec<u8>),
    Choice(Flag, Vec<u8>, Vec<u8>),
    Value(Value),
}
struct Builder {
    parts: Vec<Fragment>,
}
impl Builder {
    fn bytes(encode: impl FnOnce(&mut E) -> R) -> Vec<u8> {
        let mut encoder = E::new(Vec::new());
        encode(&mut encoder).expect("encode immutable GetInfo fragment");
        encoder.into_writer()
    }
    fn encoded(&mut self, encode: impl FnOnce(&mut E) -> R) {
        let bytes = Self::bytes(encode);
        if let Some(Fragment::Encoded(previous)) = self.parts.last_mut() {
            previous.extend_from_slice(&bytes);
        } else if !bytes.is_empty() {
            self.parts.push(Fragment::Encoded(bytes));
        }
    }
    fn choice(&mut self, flag: Flag, yes: impl FnOnce(&mut E) -> R, no: impl FnOnce(&mut E) -> R) {
        self.parts
            .push(Fragment::Choice(flag, Self::bytes(yes), Self::bytes(no)));
    }
    fn value(&mut self, value: Value) {
        self.parts.push(Fragment::Value(value));
    }
    fn field(&mut self, field: &Field<'_>) {
        // forcePINChange's optional key must be in the same conditional fragment
        // as its value; the matching conditional map length is emitted below.
        if let Field::ForcePinChange = field {
            self.choice(
                Flag::ForceChange,
                |e| {
                    e.u8(field.key())?.bool(true)?;
                    Ok(())
                },
                |_| Ok(()),
            );
            return;
        }
        self.encoded(|e| {
            e.u8(field.key())?;
            Ok(())
        });
        match field {
            Field::Versions { u2f, vendor } => {
                // CTAP suppresses U2F while alwaysUv is enabled. Vendor versions
                // append to the standard list without changing that condition.
                let count = 3 + vendor.len() as u64;
                if *u2f {
                    self.choice(
                        Flag::AlwaysUv,
                        |e| {
                            e.array(count)?;
                            Ok(())
                        },
                        |e| {
                            e.array(count + 1)?.str("U2F_V2")?;
                            Ok(())
                        },
                    );
                } else {
                    self.encoded(|e| {
                        e.array(count)?;
                        Ok(())
                    });
                }
                self.encoded(|e| {
                    e.str("FIDO_2_0")?.str("FIDO_2_1")?.str("FIDO_2_3")?;
                    for version in *vendor {
                        e.str(version)?;
                    }
                    Ok(())
                });
            }
            Field::Extensions(values)
            | Field::Transports(values)
            | Field::AttestationFormats(values)
            | Field::TransportsForReset(values) => self.encoded(|e| strings(e, values)),
            Field::Aaguid => self.value(Value::Aaguid),
            Field::Options(options) => {
                self.encoded(|e| {
                    e.map(options.len() as u64)?;
                    Ok(())
                });
                for (name, value) in *options {
                    self.encoded(|e| {
                        e.str(name)?;
                        Ok(())
                    });
                    match value {
                        Boolean::Fixed(value) => self.encoded(|e| {
                            e.bool(*value)?;
                            Ok(())
                        }),
                        Boolean::AlwaysUv => self.value(Value::AlwaysUv),
                        Boolean::ClientPin => self.value(Value::ClientPin),
                        Boolean::MakeCredUvNotRqd => self.value(Value::MakeCredUvNotRqd),
                    }
                }
            }
            Field::MaxMessageSize(value)
            | Field::MaxCredentialIdLength(value)
            | Field::MaxSerializedLargeBlobArray(value) => self.encoded(|e| {
                e.u16(*value)?;
                Ok(())
            }),
            Field::PinUvAuthProtocols => self.encoded(|e| {
                e.array(2)?
                    .u8(Protocol::One as u8)?
                    .u8(Protocol::Two as u8)?;
                Ok(())
            }),
            Field::MaxCredentialCountInList(value)
            | Field::MaxCredBlobLength(value)
            | Field::MaxRpIdsForSetMinPinLength(value)
            | Field::MaxPinLength(value) => self.encoded(|e| {
                e.u8(*value)?;
                Ok(())
            }),
            Field::NfcTransports(fixed) => {
                self.choice(
                    Flag::Nfc,
                    |e| {
                        e.array(1 + fixed.len() as u64)?.str("nfc")?;
                        Ok(())
                    },
                    |e| {
                        e.array(fixed.len() as u64)?;
                        Ok(())
                    },
                );
                self.encoded(|e| {
                    for transport in *fixed {
                        e.str(transport)?;
                    }
                    Ok(())
                });
            }
            Field::Algorithms(algorithms) => {
                self.encoded(|e| {
                    e.array(algorithms.len() as u64)?;
                    Ok(())
                });
                for algorithm in *algorithms {
                    self.encoded(|e| {
                        e.map(2)?.str("alg")?;
                        Ok(())
                    });
                    match algorithm {
                        Algorithm::Fixed(value) => self.encoded(|e| {
                            e.i32(*value)?;
                            Ok(())
                        }),
                        Algorithm::Configured => self.value(Value::Algorithm),
                    }
                    self.encoded(|e| {
                        e.str("type")?.str("public-key")?;
                        Ok(())
                    });
                }
            }
            Field::ForcePinChange => self.value(Value::ForceChange),
            Field::MinimumPinLength => self.value(Value::MinimumPinLength),
            Field::FirmwareVersion(value) => self.encoded(|e| {
                e.u32(*value)?;
                Ok(())
            }),
            Field::RemainingDiscoverableCredentials => self.value(Value::RemainingCredentials),
            Field::LongTouchForReset => self.value(Value::LongReset),
            Field::AuthenticatorConfigCommands(commands) => self.encoded(|e| {
                e.array(commands.len() as u64)?;
                for command in *commands {
                    e.u8(*command)?;
                }
                Ok(())
            }),
        }
    }
    fn source(&self) -> String {
        fn literal(bytes: &[u8]) -> String {
            let mut output = String::from("&[");
            for byte in bytes {
                output.push_str(&format!("0x{byte:02x},"));
            }
            output.push(']');
            output
        }
        let mut output = String::from(
            "// Generated immutable GetInfo schema.\n#[allow(unused_imports)]\nuse canokey_ctap::info::{Part, Flag, Value};\nconst INFO: &[Part] = &[\n",
        );
        for part in &self.parts {
            output.push_str(&match part {
                Fragment::Encoded(bytes) => format!("Part::Encoded({})", literal(bytes)),
                Fragment::Choice(flag, yes, no) => format!(
                    "Part::Choice(Flag::{flag:?}, {}, {})",
                    literal(yes),
                    literal(no)
                ),
                Fragment::Value(value) => format!("Part::Value(Value::{value:?})"),
            });
            output.push_str(",\n");
        }
        output.push_str("];\n");
        output
    }
}

fn strings(encoder: &mut E, values: &[&str]) -> R {
    encoder.array(values.len() as u64)?;
    for value in values {
        encoder.str(value)?;
    }
    Ok(())
}
fn compile(fields: &[Field<'_>]) -> Builder {
    let mut previous = 0x00;
    let mut optional = false;
    for field in fields {
        assert!(
            field.key() > previous,
            "duplicate or unordered GetInfo field"
        );
        previous = field.key();
        optional |= matches!(field, Field::ForcePinChange);
    }
    let mut builder = Builder { parts: Vec::new() };
    let count = fields.len() as u64;
    if optional {
        builder.choice(
            Flag::ForceChange,
            |e| {
                e.map(count)?;
                Ok(())
            },
            |e| {
                e.map(count - 1)?;
                Ok(())
            },
        );
    } else {
        builder.encoded(|e| {
            e.map(count)?;
            Ok(())
        });
    }
    for field in fields {
        builder.field(field);
    }
    builder
}

/// Compile a product capability declaration into an immutable runtime schema.
/// Adjacent constant fragments coalesce so field-level declarations do not add
/// a firmware table entry or a runtime dispatch for each fixed field.
pub fn get_info(fields: &[Field<'_>]) -> String {
    compile(fields).source()
}
