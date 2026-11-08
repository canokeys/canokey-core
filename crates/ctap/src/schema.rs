// SPDX-License-Identifier: Apache-2.0
//! Host-only schema construction. Inputs and output destination belong to the
//! product build script; this module reads no environment or product files.
use crate::info::{Flag, Value};
use minicbor::{Encoder, encode::Error};
use std::{convert::Infallible, format, string::String, vec::Vec};

type E = Encoder<Vec<u8>>;
type R = Result<(), Error<Infallible>>;
pub struct Builder {
    parts: Vec<String>,
}
impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}
impl Builder {
    pub fn new() -> Self {
        Self { parts: Vec::new() }
    }
    fn bytes(encode: impl FnOnce(&mut E) -> R) -> String {
        let mut encoder = E::new(Vec::new());
        encode(&mut encoder).expect("encode immutable GetInfo fragment");
        let mut output = String::from("&[");
        for byte in encoder.writer() {
            output.push_str(&format!("0x{byte:02x},"));
        }
        output.push(']');
        output
    }
    pub fn encoded(&mut self, encode: impl FnOnce(&mut E) -> R) {
        self.parts
            .push(format!("Part::Encoded({})", Self::bytes(encode)));
    }
    pub fn choice(
        &mut self,
        flag: Flag,
        yes: impl FnOnce(&mut E) -> R,
        no: impl FnOnce(&mut E) -> R,
    ) {
        self.parts.push(format!(
            "Part::Choice(Flag::{flag:?}, {}, {})",
            Self::bytes(yes),
            Self::bytes(no)
        ));
    }
    pub fn value(&mut self, value: Value) {
        self.parts.push(format!("Part::Value(Value::{value:?})"));
    }
    pub fn source(&self) -> String {
        let mut output = String::from(
            "// Generated immutable GetInfo schema.\n#[allow(unused_imports)]\nuse canokey_ctap::info::{Part, Flag, Value};\nconst INFO: &[Part] = &[\n",
        );
        for part in &self.parts {
            output.push_str(part);
            output.push_str(",\n");
        }
        output.push_str("];\n");
        output
    }
}
