// SPDX-License-Identifier: Apache-2.0
//! OpenPGP key roles and algorithm attributes; no transport or platform calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Algorithm(pub u8);
impl Algorithm {
    pub fn rsa(self) -> bool {
        (5..=7).contains(&self.0)
    }
    pub fn scalar(self) -> usize {
        [32, 32, 48, 32, 32, 128, 192, 256, 66][self.0 as usize]
    }
    pub fn public(self) -> usize {
        if self.0 == 3 || self.0 == 4 {
            32
        } else {
            2 * self.scalar()
        }
    }
    pub fn attrs(self, role: usize, out: &mut [u8; 12]) -> usize {
        let attr: &[u8] = match self.0 {
            0 => &[0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7],
            1 => &[0x13, 0x2b, 0x81, 4, 0, 0x0a],
            2 => &[0x13, 0x2b, 0x81, 4, 0, 0x22],
            3 => &[0x16, 0x2b, 6, 1, 4, 1, 0xda, 0x47, 0x0f, 1],
            4 => &[0x12, 0x2b, 6, 1, 4, 1, 0x97, 0x55, 1, 5, 1],
            5 => &[1, 8, 0, 0, 0x20, 2],
            6 => &[1, 12, 0, 0, 0x20, 2],
            7 => &[1, 16, 0, 0, 0x20, 2],
            _ => &[0x13, 0x2b, 0x81, 4, 0, 0x23],
        };
        out[..attr.len()].copy_from_slice(attr);
        if role == 1 && matches!(self.0, 0 | 1 | 2 | 8) {
            out[0] = 0x12;
        }
        attr.len()
    }
    pub fn allowed(self, role: usize) -> bool {
        !(role == 1 && self.0 == 3 || role != 1 && self.0 == 4)
    }
    pub fn parse(bytes: &[u8], role: usize) -> Option<Self> {
        let mut attr = [0; 12];
        (0..9).map(Self).find(|a| {
            a.allowed(role) && {
                let n = a.attrs(role, &mut attr);
                bytes == &attr[..n]
            }
        })
    }
}
pub fn role(reference: u8) -> Option<usize> {
    match reference {
        0xb6 => Some(0),
        0xb8 => Some(1),
        0xa4 => Some(2),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Storage,
    Length,
    Blocked,
    Unauthorized,
    Missing,
    Invalid,
    Presence,
}
