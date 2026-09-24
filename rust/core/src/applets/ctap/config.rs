// SPDX-License-Identifier: Apache-2.0
//! Authenticator policy updates use one compact atomic PIN/policy record.
use super::{Session, Status, envelope::Parameters, pin};
use crate::{ports::Platform, runtime::workspace::Workspace};

impl Session {
    #[inline(never)]
    pub(super) fn configure(
        &mut self,
        params: &Parameters,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<usize, Status> {
        let mut record = pin::load(p)?;
        let result = (|| {
            let configured = record[pin::PIN_LENGTH] != 0;
            let always_uv = record[pin::FLAGS] & pin::ALWAYS_UV != 0;
            let enabling_always_uv_without_pin = params.subcommand == 2 && !configured && always_uv;
            if (configured || always_uv) && !enabling_always_uv_without_pin {
                if params.auth_len == 0 {
                    return Err(Status::PuatRequired);
                }
                if params.protocol == 0 {
                    return Err(Status::MissingParameter);
                }
                self.authorize(
                    params.protocol,
                    &params.auth[..params.auth_len],
                    &params.message[..params.len],
                    pin::PERMISSION_CONFIG,
                    None,
                    p,
                )?;
            }
            match params.subcommand {
                2 => record[pin::FLAGS] ^= pin::ALWAYS_UV,
                3 => {
                    let minimum = params.minimum.unwrap_or(record[pin::MIN_PIN_LENGTH]);
                    if minimum < record[pin::MIN_PIN_LENGTH] {
                        return Err(Status::PinPolicy);
                    }
                    if params.force && !configured {
                        return Err(Status::PinNotSet);
                    }
                    if params.force || (configured && minimum > record[pin::PIN_LENGTH]) {
                        record[pin::FLAGS] |= pin::FORCE_CHANGE;
                    }
                    record[pin::MIN_PIN_LENGTH] = minimum;
                    if let Some(count) = params.rp_count {
                        record[pin::RP_HASHES..].fill(0);
                        record[pin::FLAGS] = (record[pin::FLAGS] & pin::RETRY_MASK)
                            | ((count as u8) << pin::RP_HASH_COUNT_SHIFT);
                        for (&(offset, len), out) in params.rps[..count]
                            .iter()
                            .zip(record[pin::RP_HASHES..].chunks_exact_mut(32))
                        {
                            let rp =
                                &params.message[usize::from(offset)..usize::from(offset + len)];
                            p.crypto
                                .sha256(rp, out.try_into().unwrap())
                                .map_err(|_| Status::Other)?;
                        }
                    }
                }
                4 => record[pin::FLAGS] |= pin::LONG_RESET,
                _ => return Err(Status::InvalidParameter),
            }
            pin::save(&record, p)?;
            if record[pin::FLAGS] & pin::FORCE_CHANGE != 0 {
                self.clear_token(p.memory);
            }
            w.output[0] = 0;
            Ok(1)
        })();
        p.memory.wipe(&mut record);
        result
    }
}

#[cfg(test)]
mod tests;
