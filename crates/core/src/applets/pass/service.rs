// SPDX-License-Identifier: Apache-2.0
//! PASS service: no APDU, authorization grants or status words.
#![forbid(unsafe_code)]
use crate::applets::pass::{
    codec::{FILE_SIZE, Layout},
    domain::{self, Error, Slot, SlotIndex},
};
use crate::ports::{Memory, Platform, Record, Storage, StorageError};
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
    pub fn install(
        &mut self,
        storage: &mut (impl Storage + ?Sized),
        memory: &(impl Memory + ?Sized),
    ) -> Result<(), Error> {
        self.available = false;
        memory.wipe(&mut self.slots);
        match storage.load(Record::Pass, &mut self.slots) {
            Err(StorageError::Missing) => {
                self.clear_slots()?;
                // Materialize the empty layout so a first boot has the same
                // durable PASS record contract as a configured card.
                self.persist(storage, memory, None)?;
            }
            Ok(n) => {
                if super::codec::validate(&self.slots, n).is_err() {
                    memory.wipe(&mut self.slots);
                    return Err(Error::Persistence);
                }
            }
            _ => {
                memory.wipe(&mut self.slots);
                return Err(Error::Persistence);
            }
        }
        self.available = true;
        Ok(())
    }
    fn clear_slots(&mut self) -> Result<(), Error> {
        for i in 0..super::codec::SLOT_COUNT {
            Layout.encode_cleared(
                Layout.record_mut(&mut self.slots, SlotIndex::new(i as u8)?)?,
                Slot::Off,
            )?;
        }
        Ok(())
    }
    fn persist(
        &mut self,
        storage: &mut (impl Storage + ?Sized),
        memory: &(impl Memory + ?Sized),
        range: Option<core::ops::Range<usize>>,
    ) -> Result<(), Error> {
        let result = match range {
            Some(range) => storage.replace_at(Record::Pass, range.start as u32, &self.slots[range]),
            None => storage.replace(Record::Pass, &self.slots),
        }
        .map_err(|_| Error::Persistence);
        if result.is_err() {
            self.available = false;
            memory.wipe(&mut self.slots);
            return Err(Error::Persistence);
        }
        Ok(())
    }
    pub fn configure(
        &mut self,
        index: SlotIndex,
        slot: Slot<'_>,
        storage: &mut (impl Storage + ?Sized),
        memory: &(impl Memory + ?Sized),
    ) -> Result<(), Error> {
        if !self.available {
            return Err(Error::Persistence);
        }
        slot.validate()?;
        let record = Layout.record_mut(&mut self.slots, index)?;
        memory.wipe(record);
        Layout.encode_cleared(record, slot)?;
        let start = index.get() * super::codec::SLOT_SIZE;
        self.persist(
            storage,
            memory,
            Some(start..start + super::codec::SLOT_SIZE),
        )
    }
    pub fn clear(
        &mut self,
        storage: &mut (impl Storage + ?Sized),
        memory: &(impl Memory + ?Sized),
    ) -> Result<(), Error> {
        if !self.available {
            return Err(Error::Persistence);
        }
        memory.wipe(&mut self.slots);
        self.clear_slots()?;
        self.persist(storage, memory, Some(0..FILE_SIZE))
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
    pub fn remove_oath(
        &mut self,
        id: Option<u32>,
        storage: &mut (impl Storage + ?Sized),
        memory: &(impl Memory + ?Sized),
    ) -> Result<(), Error> {
        let mut changed = false;
        for index in 0..crate::applets::pass::codec::SLOT_COUNT {
            if let Slot::Oath { id: stored, .. } = self.slot(index as u8)?
                && id.is_none_or(|id| id == stored)
            {
                let record = Layout.record_mut(&mut self.slots, SlotIndex::new(index as u8)?)?;
                memory.wipe(record);
                Layout.encode_cleared(record, Slot::Off)?;
                changed = true;
            }
        }
        if changed {
            // Unlinking may affect both slots; publish the combined change once.
            self.persist(storage, memory, Some(0..FILE_SIZE))?;
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
        out: &mut [u8; super::domain::KEY_LENGTH],
        p: &mut Platform<'_>,
    ) -> Result<(), Error> {
        domain::challenge_response(self.slot(index)?, input, out, &mut Crypto(p.crypto))
    }
}
struct Crypto<'a>(&'a mut crate::ports::CryptoPort<'a>);
impl domain::Crypto for Crypto<'_> {
    fn hmac(
        &mut self,
        key: &[u8; super::domain::KEY_LENGTH],
        input: &[u8],
        out: &mut [u8; super::domain::KEY_LENGTH],
    ) {
        self.0.hmac_sha1(key, input, out);
    }
}

impl Default for Pass {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod storage_tests;
