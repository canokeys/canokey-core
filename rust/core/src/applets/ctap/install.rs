// SPDX-License-Identifier: Apache-2.0
//! Boot validation is distinct from command-time validation and reader power.
use super::{Session, Status, provision, settings::Sm2};
use crate::ports::{Platform, Record, StorageError};

fn size(record: Record, p: &mut Platform<'_>) -> Result<Option<u32>, Status> {
    match p.storage.size(record) {
        Ok(n) => Ok(Some(n)),
        Err(StorageError::Missing) => Ok(None),
        Err(_) => Err(Status::Other),
    }
}

impl Session {
    pub(super) fn install(&mut self, p: &mut Platform<'_>) -> Result<(), Status> {
        let key_size = size(Record::CtapAttestationKey, p)?;
        let certificate = size(Record::CtapCertificate, p)?;
        let mut rebuild = key_size != Some(32)
            || !certificate.is_some_and(|n| n != 0 && n <= provision::CERT_LIMIT as u32);
        // A metadata lookup alone must not mask a failed private-key read.
        if key_size == Some(32) {
            let mut key = [0; 32];
            let result = p.storage.load(Record::CtapAttestationKey, &mut key);
            p.memory.wipe(&mut key);
            match result {
                Ok(32) => (),
                Ok(_) | Err(StorageError::Missing) => rebuild = true,
                Err(_) => return Err(Status::Other),
            }
        }
        let sm2 = if size(Record::CtapSm2, p)? == Some(8) {
            let mut wire = [0; 8];
            match p.storage.load(Record::CtapSm2, &mut wire) {
                Ok(8) => Sm2::decode(&wire),
                Ok(_) | Err(StorageError::Missing) => None,
                Err(_) => return Err(Status::Other),
            }
        } else {
            None
        };
        if rebuild || sm2.is_none() {
            // Keep the invalid prerequisite until cleanup completes, so a
            // failed cleanup is retried at the next boot. Erase does not touch
            // manufacturing records, including malformed attestation material.
            self.erase(p)?;
            if sm2.is_none() {
                p.storage
                    .replace(Record::CtapSm2, &Sm2::DEFAULT.encode())
                    .map_err(|_| Status::Other)?;
            }
        }
        self.sm2 = sm2.unwrap_or(Sm2::DEFAULT);
        Ok(())
    }
}
