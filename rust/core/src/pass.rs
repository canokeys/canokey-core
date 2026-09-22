// SPDX-License-Identifier: Apache-2.0
//! PASS service: no APDU, authorization grants or status words.
#![forbid(unsafe_code)]
use crate::services::{Platform, Record, StorageError};
use canokey_pass::{
    codec::{FILE_SIZE, Layout},
    domain::{self, Error, Slot, SlotIndex},
};
pub struct Pass {
    slots: [u8; FILE_SIZE],
    available: bool,
}
impl Pass {
    pub const fn new() -> Self {
        Self {
            slots: [0; FILE_SIZE],
            available: false,
        }
    }
    pub fn install(&mut self, p: &mut dyn Platform) -> Result<(), Error> {
        self.available = false;
        p.wipe(&mut self.slots);
        match p.load(Record::Pass, &mut self.slots) {
            Err(StorageError::Missing) => self.clear_slots()?,
            Ok(72) => {
                let mut old = [0; 72];
                old.copy_from_slice(&self.slots[..72]);
                for i in 0..2 {
                    let slot = Layout.decode(&old[i * 36..i * 36 + 36])?;
                    Layout.encode_cleared(
                        Layout.record_mut(&mut self.slots, SlotIndex::new(i as u8)?)?,
                        slot,
                    )?;
                }
                p.wipe(&mut old);
                self.persist(p)?;
            }
            Ok(FILE_SIZE) => {
                for i in 0..2 {
                    Layout.decode(Layout.record(&self.slots, SlotIndex::new(i)?)?)?;
                }
            }
            _ => {
                p.wipe(&mut self.slots);
                return Err(Error::Persistence);
            }
        }
        self.available = true;
        Ok(())
    }
    fn clear_slots(&mut self) -> Result<(), Error> {
        for i in 0..2 {
            Layout.encode_cleared(
                Layout.record_mut(&mut self.slots, SlotIndex::new(i)?)?,
                Slot::Off,
            )?;
        }
        Ok(())
    }
    fn persist(&mut self, p: &mut dyn Platform) -> Result<(), Error> {
        if p.replace(Record::Pass, &self.slots).is_err() {
            self.available = false;
            p.wipe(&mut self.slots);
            return Err(Error::Persistence);
        }
        Ok(())
    }
    pub fn configure(
        &mut self,
        index: SlotIndex,
        slot: Slot<'_>,
        p: &mut dyn Platform,
    ) -> Result<(), Error> {
        if !self.available {
            return Err(Error::Persistence);
        }
        slot.validate()?;
        let record = Layout.record_mut(&mut self.slots, index)?;
        p.wipe(record);
        Layout.encode_cleared(record, slot)?;
        self.persist(p)
    }
    pub fn clear(&mut self, p: &mut dyn Platform) -> Result<(), Error> {
        if !self.available {
            return Err(Error::Persistence);
        }
        p.wipe(&mut self.slots);
        self.clear_slots()?;
        self.persist(p)
    }
    pub fn records(&self) -> Result<&[u8], Error> {
        if self.available {
            Ok(&self.slots)
        } else {
            Err(Error::Persistence)
        }
    }
    pub fn slot(&self, index: u8) -> Result<Slot<'_>, Error> {
        Layout.decode(Layout.record(self.records()?, SlotIndex::new(index)?)?)
    }
    #[cfg(feature = "oath")]
    pub fn remove_oath(&mut self, id: Option<u32>, p: &mut dyn Platform) -> Result<(), Error> {
        let mut changed = false;
        for index in 0..2 {
            if let Slot::Oath { id: stored, .. } = self.slot(index)?
                && id.is_none_or(|id| id == stored)
            {
                let record = Layout.record_mut(&mut self.slots, SlotIndex::new(index)?)?;
                p.wipe(record);
                Layout.encode_cleared(record, Slot::Off)?;
                changed = true;
            }
        }
        if changed {
            self.persist(p)?;
        }
        Ok(())
    }
    pub fn touch(&self, index: u8, out: &mut [u8]) -> Result<usize, Error> {
        domain::write_output(self.slot(index)?, out)
    }
    pub fn challenge(
        &self,
        index: u8,
        input: &[u8],
        out: &mut [u8; 20],
        p: &mut dyn Platform,
    ) -> Result<(), Error> {
        domain::challenge_response(self.slot(index)?, input, out, &mut Crypto(p))
    }
}
struct Crypto<'a>(&'a mut dyn Platform);
impl domain::Crypto for Crypto<'_> {
    fn hmac(&mut self, key: &[u8; 20], input: &[u8], out: &mut [u8; 20]) {
        self.0.hmac_sha1(key, input, out);
    }
}
