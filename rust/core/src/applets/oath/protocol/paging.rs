// SPDX-License-Identifier: Apache-2.0
//! OATH A5 page generation; the runtime still owns GET RESPONSE offsets.
use super::*;
impl State {
    pub(super) fn page(&mut self, le: u32, p: &mut Platform<'_>) -> Result<Sw, Sw> {
        let mut store = Store::new(p.storage, p.memory);
        let mut mac = Mac::new(p.crypto, p.memory);
        let capacity = le.min(256) as usize;
        if matches!(self.page, Page::None) {
            return Err(Sw::CONDITIONS_NOT_SATISFIED);
        }
        while let Some((id, next)) = store.at(self.cursor).map_err(status)? {
            let mut record = store.load(id).map_err(status)?;
            let estimate = match self.page {
                Page::List => 3 + record.name().len(),
                Page::Calculate(t) => 5 + record.name().len() + if t { 4 } else { 64 },
                Page::None => 0,
            };
            if self.length + estimate > capacity {
                record.clear(&mut mac);
                return Ok(Sw(0x61ff));
            }
            self.cursor = next;
            let at = self.length;
            match self.page {
                Page::List => {
                    self.response[at..at + 3].copy_from_slice(&[
                        0x72,
                        (record.name().len() + 1) as u8,
                        record.kind() as u8 | record.algorithm() as u8,
                    ]);
                    self.response[at + 3..at + 3 + record.name().len()]
                        .copy_from_slice(record.name());
                    self.length += 3 + record.name().len();
                }
                Page::Calculate(truncated) => {
                    self.response[at..at + 2].copy_from_slice(&[0x71, record.name().len() as u8]);
                    self.response[at + 2..at + 2 + record.name().len()]
                        .copy_from_slice(record.name());
                    self.length += 2 + record.name().len();
                    let marker = if record.kind() == Kind::Hotp {
                        Some(0x77)
                    } else if record.properties().touch() {
                        Some(0x7c)
                    } else {
                        None
                    };
                    if let Some(tag) = marker {
                        let at = self.length;
                        self.response[at..at + 3].copy_from_slice(&[tag, 1, record.digits()]);
                        self.length += 3;
                    } else {
                        // CALCULATE ALL shares the single-credential policy.
                        let input = &self.challenge[..self.challenge_len];
                        let result = service::calculate(
                            &mut store,
                            &mut mac,
                            id,
                            input,
                            Presence::NotConfirmed,
                        );
                        record.clear(&mut mac);
                        let mut result = result.map_err(status)?;
                        self.emit_digest(&result, truncated);
                        result.clear(&mut mac);
                    }
                }
                Page::None => (),
            }
            record.clear(&mut mac);
        }
        self.page = Page::None;
        Ok(Sw::SUCCESS)
    }
}
