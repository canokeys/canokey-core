// SPDX-License-Identifier: Apache-2.0
//! ISO-DEP frames delivered by FM11NT. The controller checks and retains CRC
//! bytes on receive and appends CRC on transmit. CID/NAD are not advertised.
#![forbid(unsafe_code)]
pub const FRAME_LIMIT: usize = 32;
pub const INF_LIMIT: usize = 29;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Block<'a> {
    Information {
        number: u8,
        chained: bool,
        bytes: &'a [u8],
    },
    Receive {
        number: u8,
        negative: bool,
    },
    Waiting(u8),
    Deselect,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Prologue,
    Multiplier,
}
pub fn decode(frame: &[u8]) -> Result<Block<'_>, Error> {
    if !(3..=FRAME_LIMIT).contains(&frame.len()) {
        return Err(Error::Length);
    }
    let pcb = frame[0];
    let inf = &frame[1..frame.len() - 2];
    match pcb {
        0x02 | 0x03 | 0x12 | 0x13 => Ok(Block::Information {
            number: pcb & 1,
            chained: pcb & 0x10 != 0,
            bytes: inf,
        }),
        0xa2 | 0xa3 | 0xb2 | 0xb3 if inf.is_empty() => Ok(Block::Receive {
            number: pcb & 1,
            negative: pcb & 0x10 != 0,
        }),
        0xc2 if inf.is_empty() => Ok(Block::Deselect),
        0xf2 if inf.len() == 1 => {
            if !(1..=59).contains(&inf[0]) {
                return Err(Error::Multiplier);
            }
            Ok(Block::Waiting(inf[0]))
        }
        0xa2 | 0xa3 | 0xb2 | 0xb3 | 0xc2 | 0xf2 => Err(Error::Length),
        _ => Err(Error::Prologue),
    }
}
/// Packet bytes exclude CRC; the chip generates it. The last successful
/// information packet is retained by the runtime for exact retransmission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Packet {
    bytes: [u8; 30],
    length: u8,
}
impl Packet {
    pub fn information(number: u8, chained: bool, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > INF_LIMIT {
            return Err(Error::Length);
        }
        let mut packet = Self::control(0x02 | (number & 1) | if chained { 0x10 } else { 0 });
        packet.bytes[1..1 + bytes.len()].copy_from_slice(bytes);
        packet.length += bytes.len() as u8;
        Ok(packet)
    }
    pub const fn acknowledgement(number: u8) -> Self {
        Self::control(0xa2 | (number & 1))
    }
    pub const fn deselect() -> Self {
        Self::control(0xc2)
    }
    pub fn waiting(multiplier: u8) -> Result<Self, Error> {
        if !(1..=59).contains(&multiplier) {
            return Err(Error::Multiplier);
        }
        let mut packet = Self::control(0xf2);
        packet.bytes[1] = multiplier;
        packet.length = 2;
        Ok(packet)
    }
    const fn control(pcb: u8) -> Self {
        let mut bytes = [0; 30];
        bytes[0] = pcb;
        Self { bytes, length: 1 }
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length as usize]
    }
}
