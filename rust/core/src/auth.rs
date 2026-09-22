// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
use crate::Platform;
use canokey_protocol::response::StatusWord as Sw;

/// Prototype record: SHA-256 digest, remaining retries, maximum retries.
/// Provisioning is external; an absent record never grants authorization.
pub fn verify(pin: &[u8], platform: &mut dyn Platform) -> Result<(), Sw> {
    let mut record = [0; 34];
    if platform.size(1) != 34 || platform.read(1, &mut record) != 34 {
        platform.wipe(&mut record);
        return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
    }
    let result = (|| {
        if record[33] == 0 || record[33] > 15 || record[32] > record[33] {
            return Err(Sw::PERSISTENCE_ERROR);
        }
        if record[32] == 0 {
            return Err(Sw::AUTHENTICATION_BLOCKED);
        }
        if pin.is_empty() {
            return Err(Sw(0x63c0 | u16::from(record[32])));
        }
        if !(6..=64).contains(&pin.len()) {
            return Err(Sw::WRONG_LENGTH);
        }
        // Persist an attempt before doing crypto, so reset cannot bypass retries.
        record[32] -= 1;
        if platform.write(1, &record) != 34 {
            return Err(Sw::PERSISTENCE_ERROR);
        }
        let mut digest = [0; 32];
        platform.sha256(pin, &mut digest);
        let different = digest
            .iter()
            .zip(&record[..32])
            .fold(0u8, |v, (a, b)| v | (a ^ b));
        platform.wipe(&mut digest);
        if different != 0 {
            return Err(Sw(0x63c0 | u16::from(record[32])));
        }
        record[32] = record[33];
        if platform.write(1, &record) != 34 {
            return Err(Sw::PERSISTENCE_ERROR);
        }
        Ok(())
    })();
    platform.wipe(&mut record);
    result
}
