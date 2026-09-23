// SPDX-License-Identifier: Apache-2.0
//! One session-owned workspace, lent by the registry to the selected applet.
//! Key material, crypto input and result are simultaneously live at the crypto
//! boundary. Certificates and encoded import messages never occupy this area.
use crate::ports::{KeyMaterial, Memory};
pub struct Workspace {
    pub key: KeyMaterial,
    pub input: [u8; 513],
    pub output: [u8; 528],
}
impl Workspace {
    pub const fn new() -> Self {
        Self {
            key: KeyMaterial::new(),
            input: [0; 513],
            output: [0; 528],
        }
    }
    pub fn clear(&mut self, memory: &dyn Memory) {
        memory.wipe(&mut self.key.bytes);
        self.key.bits = 0;
        self.key.reserved = 0;
        memory.wipe(&mut self.input);
        memory.wipe(&mut self.output);
    }
}
