// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
use crate::{Platform, auth};
use canokey_pass::{
    codec::Layout,
    domain::{self, Slot, SlotIndex},
    protocol,
};
use canokey_protocol::{apdu::Header, response::StatusWord as Sw};
pub const MANAGEMENT_AID: &[u8] = &[0xf0, 0, 0, 0, 0];
pub const COMMAND_CAPACITY: usize = 64;
pub struct Pass {
    slots: [u8; 142],
    command: [u8; 64],
    used: usize,
    authorized: bool,
}
fn layout() -> Layout {
    Layout::new(1).unwrap()
}
fn failed(_: domain::Error) -> Sw {
    Sw::WRONG_DATA
}
impl Pass {
    pub const fn new() -> Self {
        Self {
            slots: [0; 142],
            command: [0; 64],
            used: 0,
            authorized: false,
        }
    }
    pub fn install(&mut self, p: &mut dyn Platform) -> Result<(), Sw> {
        p.wipe(&mut self.slots);
        match p.size(0) {
            -1 => {
                if p.write(0, &self.slots) != 142 {
                    return Err(Sw::PERSISTENCE_ERROR);
                }
            }
            142 => {
                if p.read(0, &mut self.slots) != 142 {
                    p.wipe(&mut self.slots);
                    return Err(Sw::PERSISTENCE_ERROR);
                }
            }
            _ => return Err(Sw::PERSISTENCE_ERROR),
        }
        Ok(())
    }
    pub fn cancel_command(&mut self, p: &mut dyn Platform) {
        p.wipe(&mut self.command);
        self.used = 0;
    }
    pub fn reset(&mut self, p: &mut dyn Platform) {
        self.cancel_command(p);
        self.authorized = false;
    }
    pub fn consume(&mut self, data: &[u8]) -> Result<(), Sw> {
        let end = self
            .used
            .checked_add(data.len())
            .filter(|n| *n <= 64)
            .ok_or(Sw::WRONG_LENGTH)?;
        self.command[self.used..end].copy_from_slice(data);
        self.used = end;
        Ok(())
    }
    pub fn finish(&mut self, h: Header, p: &mut dyn Platform) -> Result<u32, Sw> {
        let result = self.execute(h, p);
        self.cancel_command(p);
        result
    }
    fn execute(&mut self, h: Header, p: &mut dyn Platform) -> Result<u32, Sw> {
        if h.p2 != 0 {
            return Err(Sw::WRONG_P1P2);
        }
        if h.ins == 0x20 {
            self.authorized = false;
            if h.p1 != 0 {
                return Err(Sw::WRONG_P1P2);
            }
            auth::verify(&self.command[..self.used], p)?;
            self.authorized = true;
            return Ok(0);
        }
        if !matches!(h.ins, 0x43 | 0x44 | 0x13) {
            return Err(Sw::INS_NOT_SUPPORTED);
        }
        if !self.authorized {
            return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        match h.ins {
            0x44 => {
                let (index, slot) = protocol::decode_config(h.p1, &self.command[..self.used])?;
                let record = layout()
                    .record_mut(&mut self.slots, index)
                    .map_err(failed)?;
                p.wipe(record);
                layout().encode_cleared(record, slot).map_err(failed)?;
                if p.write(0, &self.slots) != 142 {
                    p.wipe(&mut self.slots);
                    return Err(Sw::PERSISTENCE_ERROR);
                }
                Ok(0)
            }
            0x43 | 0x13 => {
                if h.p1 != 0 {
                    return Err(Sw::WRONG_P1P2);
                }
                if self.used != 0 {
                    return Err(Sw::WRONG_LENGTH);
                }
                if h.ins == 0x43 {
                    return Ok(
                        protocol::read_config_part(&self.slots, layout(), 0, &mut [])
                            .map_err(failed)? as u32,
                    );
                }
                p.wipe(&mut self.slots);
                if p.write(0, &self.slots) != 142 {
                    return Err(Sw::PERSISTENCE_ERROR);
                }
                Ok(0)
            }
            _ => Err(Sw::INS_NOT_SUPPORTED),
        }
    }
    pub fn read_response(&self, offset: usize, out: &mut [u8]) -> Result<(), Sw> {
        protocol::read_config_part(&self.slots, layout(), offset, out).map_err(failed)?;
        Ok(())
    }
    fn slot(&self, index: u8) -> Result<Slot<'_>, Sw> {
        layout()
            .decode(
                layout()
                    .record(&self.slots, SlotIndex::new(index).map_err(failed)?)
                    .map_err(failed)?,
            )
            .map_err(failed)
    }
    pub fn touch(&self, index: u8, out: &mut [u8], p: &mut dyn Platform) -> Result<usize, Sw> {
        domain::prepare_output(self.slot(index)?, &mut Crypto(p))
            .map_err(failed)?
            .write(out)
            .map_err(failed)
    }
    pub fn challenge(
        &self,
        index: u8,
        input: &[u8],
        out: &mut [u8; 20],
        p: &mut dyn Platform,
    ) -> Result<(), Sw> {
        domain::challenge_response(self.slot(index)?, input, out, &mut Crypto(p)).map_err(failed)
    }
}
struct Crypto<'a>(&'a mut dyn Platform);
impl domain::Crypto for Crypto<'_> {
    // OATH is not installed in this build; never call a legacy C applet.
    fn oath(&mut self, _: u32, _: &mut [u8; 4]) -> i32 {
        -1
    }
    fn hmac(&mut self, key: &[u8; 20], input: &[u8], out: &mut [u8; 20]) {
        self.0.hmac_sha1(key, input, out);
    }
}
