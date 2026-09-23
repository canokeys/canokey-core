// SPDX-License-Identifier: Apache-2.0
use crate::{
    Platform,
    ports::{Record, StorageError},
};
use canokey_protocol::{apdu::Header, response::StatusWord as Sw};
const STATE_LEN: usize = 24;
const RETRIES: u8 = 3;
pub(super) const PIN: &[u8; 8] = b"123456\xff\xff";
pub(super) const PUK: &[u8; 8] = b"12345678";
#[derive(Clone, Copy)]
pub(super) struct State {
    pub pin_tries: u8,
    pub puk_tries: u8,
    pub pin_ok: bool,
    pub puk_ok: bool,
    pub pin: [u8; 8],
    pub pin_limit: u8,
    pub puk_limit: u8,
    pub puk: [u8; 8],
}
impl State {
    const fn fresh() -> Self {
        Self {
            pin_tries: RETRIES,
            puk_tries: RETRIES,
            pin_ok: false,
            puk_ok: false,
            pin: *PIN,
            pin_limit: RETRIES,
            puk_limit: RETRIES,
            puk: *PUK,
        }
    }
    fn encode(self, out: &mut [u8; STATE_LEN]) {
        out.fill(0);
        out[0] = 1;
        out[1] = self.pin_tries;
        out[2] = self.puk_tries;
        out[5] = self.pin_limit;
        out[6] = self.puk_limit; // Authorization is session-only; legacy flag bytes remain reserved.
        out[8..16].copy_from_slice(&self.pin);
        out[16..24].copy_from_slice(&self.puk);
    }
    fn decode(input: &[u8; STATE_LEN]) -> Option<Self> {
        let pin_limit = if input[5] == 0 { 3 } else { input[5] };
        let puk_limit = if input[6] == 0 { 3 } else { input[6] };
        if input[0] != 1
            || pin_limit > 15
            || puk_limit > 15
            || input[1] > pin_limit
            || input[2] > puk_limit
            || input[3] > 1
            || input[4] > 1
        {
            return None;
        }
        Some(Self {
            pin_tries: input[1],
            puk_tries: input[2],
            pin_ok: false,
            puk_ok: false,
            pin_limit,
            puk_limit,
            pin: input[8..16].try_into().ok()?,
            puk: input[16..24].try_into().ok()?,
        })
    }
}

pub(super) struct Pins {
    pub state: State,
    pub available: bool,
}
impl Pins {
    pub const fn new() -> Self {
        Self {
            state: State::fresh(),
            available: false,
        }
    }
    pub fn reset(&mut self) {
        self.state.pin_ok = false;
        self.state.puk_ok = false;
    }
    pub fn defaults(
        &mut self,
        pin_limit: u8,
        puk_limit: u8,
        p: &mut Platform<'_>,
    ) -> Result<(), Sw> {
        self.reset();
        self.state = State::fresh();
        self.state.pin_limit = pin_limit;
        self.state.puk_limit = puk_limit;
        self.state.pin_tries = pin_limit;
        self.state.puk_tries = puk_limit;
        self.save(p)?;
        self.available = true;
        Ok(())
    }
    pub fn install(&mut self, p: &mut Platform<'_>) -> Result<(), Sw> {
        self.available = false;
        self.state.pin_ok = false;
        self.state.puk_ok = false;
        let mut bytes = [0; STATE_LEN];
        let result = match p.storage.load(Record::PivState, &mut bytes) {
            Ok(STATE_LEN) => State::decode(&bytes).ok_or(Sw::UNABLE_TO_PROCESS),
            Err(StorageError::Missing) => {
                self.state = State::fresh();
                self.save(p).map(|()| self.state)
            }
            _ => Err(Sw::UNABLE_TO_PROCESS),
        };
        p.memory.wipe(&mut bytes);
        self.state = result?;
        self.available = true;
        Ok(())
    }
    pub(super) fn save(&mut self, p: &mut Platform<'_>) -> Result<(), Sw> {
        let mut bytes = [0; STATE_LEN];
        self.state.encode(&mut bytes);
        let result = p.storage.replace(Record::PivState, &bytes);
        p.memory.wipe(&mut bytes);
        if result.is_err() {
            // A failed commit may have taken effect. Reload before any further
            // credential operation; never authorize from the speculative cache.
            self.available = false;
            self.state.pin_ok = false;
            self.state.puk_ok = false;
            return Err(Sw::UNABLE_TO_PROCESS);
        }
        Ok(())
    }
    pub(super) fn ready(&self) -> Result<(), Sw> {
        if self.available {
            Ok(())
        } else {
            Err(Sw::UNABLE_TO_PROCESS)
        }
    }
    fn reference(h: Header, allow_puk: bool) -> Result<bool, Sw> {
        match h.p2 {
            0x80 => Ok(false),
            0x81 if allow_puk => Ok(true),
            _ => Err(Sw(0x6a88)),
        }
    }
    fn authenticate(&mut self, puk: bool, data: &[u8], p: &mut Platform<'_>) -> Result<(), Sw> {
        self.ready()?;
        use crate::mechanisms::pin::{Charge, Credential, Error};
        if puk {
            self.state.puk_ok = false;
        } else {
            self.state.pin_ok = false;
        }
        // Keep the PIN/PUK pair in its existing atomic record. The shared
        // mechanism borrows this short encoding; it never owns session flags.
        let mut bytes = [0; STATE_LEN];
        self.state.encode(&mut bytes);
        let (value, counter) = if puk { (16..24, 2) } else { (8..16, 1) };
        let result = Credential::new(
            &mut bytes,
            value,
            counter,
            if puk {
                self.state.puk_limit
            } else {
                self.state.pin_limit
            },
        )
        .and_then(|mut credential| {
            credential.verify(&data[..8], Charge::OnMismatch, &mut |record| {
                p.storage
                    .replace(Record::PivState, record)
                    .map_err(|_| Error::Persistence)
            })
        });
        self.state.pin_tries = bytes[1];
        self.state.puk_tries = bytes[2];
        p.memory.wipe(&mut bytes);
        result.map_err(|error| match error {
            Error::Persistence => {
                self.available = false;
                self.state.pin_ok = false;
                self.state.puk_ok = false;
                Sw::UNABLE_TO_PROCESS
            }
            #[cfg(any(feature = "admin", feature = "openpgp"))]
            Error::Length => Sw::WRONG_LENGTH,
            Error::Blocked => Sw::AUTHENTICATION_BLOCKED,
            Error::Retries(n) => Sw(0x63c0 | u16::from(n)),
        })?;
        if puk {
            self.state.puk_ok = true;
        } else {
            self.state.pin_ok = true;
        }
        Ok(())
    }
    pub(super) fn verify(
        &mut self,
        h: Header,
        data: &[u8],
        p: &mut Platform<'_>,
    ) -> Result<u32, Sw> {
        if !matches!(h.p1, 0 | 0xff) {
            return Err(Sw::WRONG_P1P2);
        }
        Self::reference(h, false)?;
        self.ready()?;
        if h.p1 == 0xff {
            if !data.is_empty() {
                return Err(Sw::WRONG_LENGTH);
            }
            self.state.pin_ok = false;
            return Ok(0);
        }
        if data.is_empty() {
            return if self.state.pin_ok {
                Ok(0)
            } else {
                Err(Sw(0x63c0 | self.state.pin_tries as u16))
            };
        }
        if data.len() != 8 {
            return Err(Sw::WRONG_LENGTH);
        }
        self.authenticate(false, data, p)?;
        Ok(0)
    }
    pub(super) fn change(
        &mut self,
        h: Header,
        data: &[u8],
        p: &mut Platform<'_>,
    ) -> Result<u32, Sw> {
        if h.p1 != 0 {
            return Err(Sw::WRONG_P1P2);
        }
        let puk = Self::reference(h, true)?;
        if data.len() != 16 {
            return Err(Sw::WRONG_LENGTH);
        }
        self.authenticate(puk, data, p)?;
        if puk {
            self.state.puk_ok = false;
            self.state.puk.copy_from_slice(&data[8..16]);
        } else {
            self.state.pin_ok = false;
            self.state.pin.copy_from_slice(&data[8..16]);
        }
        self.save(p)?;
        Ok(0)
    }
    pub(super) fn reset_retry(
        &mut self,
        h: Header,
        data: &[u8],
        p: &mut Platform<'_>,
    ) -> Result<u32, Sw> {
        if h.p1 != 0 {
            return Err(Sw::WRONG_P1P2);
        }
        Self::reference(h, false)?;
        if data.len() != 16 {
            return Err(Sw::WRONG_LENGTH);
        }
        self.authenticate(true, data, p)?;
        self.state.pin_tries = self.state.pin_limit;
        self.state.pin_ok = false;
        self.state.pin.copy_from_slice(&data[8..16]);
        self.save(p)?;
        Ok(0)
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
