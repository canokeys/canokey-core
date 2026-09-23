// SPDX-License-Identifier: Apache-2.0
use super::wire::reference;
use crate::{
    Platform,
    ports::{Record, StorageError},
};
use canokey_protocol::{apdu::Header, response::StatusWord as Sw};
// One atomic disk record contains both secrets and their retry counters.
// Authorization grants (pin_ok/puk_ok) are session-only and never serialized.
// PIV values occupy eight bytes; a six-digit default PIN ends in FF FF padding.
const FORMAT_VERSION: u8 = 1;
const VERSION: usize = 0;
const PIN_REMAINING: usize = 1;
const PUK_REMAINING: usize = 2;
const PIN_LIMIT: usize = 3;
const PUK_LIMIT: usize = 4;
const PIN_VALUE: usize = 5;
pub(super) const VALUE_BYTES: usize = 8;
const PUK_VALUE: usize = PIN_VALUE + VALUE_BYTES;
const STATE_LEN: usize = PUK_VALUE + VALUE_BYTES;
pub(super) const MAX_RETRIES: u8 = 0x0f;
const RETRIES: u8 = 3;
pub(super) const PIN: &[u8; VALUE_BYTES] = b"123456\xff\xff";
pub(super) const PUK: &[u8; VALUE_BYTES] = b"12345678";
#[derive(Clone, Copy)]
pub(super) struct State {
    pub pin_tries: u8,
    pub puk_tries: u8,
    pub pin_ok: bool,
    pub puk_ok: bool,
    pub pin: [u8; VALUE_BYTES],
    pub pin_limit: u8,
    pub puk_limit: u8,
    pub puk: [u8; VALUE_BYTES],
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
        out[VERSION] = FORMAT_VERSION;
        out[PIN_REMAINING] = self.pin_tries;
        out[PUK_REMAINING] = self.puk_tries;
        out[PIN_LIMIT] = self.pin_limit;
        out[PUK_LIMIT] = self.puk_limit;
        out[PIN_VALUE..PUK_VALUE].copy_from_slice(&self.pin);
        out[PUK_VALUE..STATE_LEN].copy_from_slice(&self.puk);
    }
    fn decode(input: &[u8; STATE_LEN]) -> Option<Self> {
        let pin_limit = input[PIN_LIMIT];
        let puk_limit = input[PUK_LIMIT];
        if input[VERSION] != FORMAT_VERSION
            || !(1..=MAX_RETRIES).contains(&pin_limit)
            || !(1..=MAX_RETRIES).contains(&puk_limit)
            || input[PIN_REMAINING] > pin_limit
            || input[PUK_REMAINING] > puk_limit
        {
            return None;
        }
        Some(Self {
            pin_tries: input[PIN_REMAINING],
            puk_tries: input[PUK_REMAINING],
            pin_ok: false,
            puk_ok: false,
            pin_limit,
            puk_limit,
            pin: input[PIN_VALUE..PUK_VALUE].try_into().ok()?,
            puk: input[PUK_VALUE..STATE_LEN].try_into().ok()?,
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
            reference::PIN => Ok(false),
            reference::PUK if allow_puk => Ok(true),
            _ => Err(Sw::REFERENCE_NOT_FOUND),
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
        let (value, counter) = if puk {
            (PUK_VALUE..STATE_LEN, PUK_REMAINING)
        } else {
            (PIN_VALUE..PUK_VALUE, PIN_REMAINING)
        };
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
            credential.verify(&data[..VALUE_BYTES], Charge::OnMismatch, &mut |record| {
                p.storage
                    .replace(Record::PivState, record)
                    .map_err(|_| Error::Persistence)
            })
        });
        self.state.pin_tries = bytes[PIN_REMAINING];
        self.state.puk_tries = bytes[PUK_REMAINING];
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
            Error::Retries(n) => Sw::retries(n),
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
        // VERIFY: P1=00 verifies (or queries with empty data); P1=FF logs
        // out and requires empty data. P2 must identify the PIN (80).
        if !matches!(h.p1, 0x00 | 0xff) {
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
                Err(Sw::retries(self.state.pin_tries))
            };
        }
        if data.len() != VALUE_BYTES {
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
        if h.p1 != 0x00 {
            return Err(Sw::WRONG_P1P2);
        }
        // CHANGE REFERENCE DATA: P1=00, P2=80 PIN / 81 PUK. The body
        // concatenates the old and new eight-byte values.
        let puk = Self::reference(h, true)?;
        if data.len() != 2 * VALUE_BYTES {
            return Err(Sw::WRONG_LENGTH);
        }
        self.authenticate(puk, data, p)?;
        if puk {
            self.state.puk_ok = false;
            self.state
                .puk
                .copy_from_slice(&data[VALUE_BYTES..2 * VALUE_BYTES]);
        } else {
            self.state.pin_ok = false;
            self.state
                .pin
                .copy_from_slice(&data[VALUE_BYTES..2 * VALUE_BYTES]);
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
        if h.p1 != 0x00 {
            return Err(Sw::WRONG_P1P2);
        }
        Self::reference(h, false)?;
        if data.len() != 2 * VALUE_BYTES {
            return Err(Sw::WRONG_LENGTH);
        }
        // RESET RETRY COUNTER: P1=00, P2=80 selects the PIN being reset;
        // authentication uses the PUK supplied before the replacement PIN.
        self.authenticate(true, data, p)?;
        self.state.pin_tries = self.state.pin_limit;
        self.state.pin_ok = false;
        self.state
            .pin
            .copy_from_slice(&data[VALUE_BYTES..2 * VALUE_BYTES]);
        self.save(p)?;
        Ok(0)
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
