// SPDX-License-Identifier: Apache-2.0
//! Persistent initialization and reset, preserving the F9 attestation identity.
use super::*;

// Durable restart marker. Write the pending operation before erasing records;
// publish COMPLETE only after every write succeeds. Installation can then resume
// the same operation without mistaking a damaged existing card for a new one.
const RESET_PENDING: u8 = 0;
const COMPLETE: u8 = 1;
const INSTALL_PENDING: u8 = 2;
// Offsets in the complete stored TLVs below, excluding tag/length bytes from
// the mutable ranges: CCC F0 card identifier (21 bytes), CHUID 34 GUID (16 bytes).
const CCC_CARD_ID: core::ops::Range<usize> = 4..25;
const CHUID_GUID: core::ops::Range<usize> = 31..47;

impl Piv {
    pub(crate) fn reset_persistent(&mut self, p: &mut Platform<'_>) -> Result<(), Sw> {
        self.provision(true, p)
    }

    pub fn install(&mut self, p: &mut Platform<'_>) -> Result<(), Sw> {
        self.pins.install(p)?;
        let mut status = [0; 1];
        let provision = match p.storage.load(Record::PivProvision, &mut status) {
            Ok(1) if status[0] == COMPLETE => None,
            Ok(1) if status[0] == RESET_PENDING => Some(true),
            Ok(1) if status[0] == INSTALL_PENDING => Some(false),
            Err(StorageError::Missing) => {
                // Missing completion metadata must not erase an established card.
                for record in [Record::PivConfig, Record::PivManagement]
                    .iter()
                    .chain(repo::KEYS.iter())
                    .chain(repo::OBJECTS.iter())
                {
                    if !matches!(p.storage.size(*record), Err(StorageError::Missing)) {
                        return Err(Sw::UNABLE_TO_PROCESS);
                    }
                }
                Some(false)
            }
            _ => return Err(Sw::UNABLE_TO_PROCESS),
        };
        if let Some(reset_credentials) = provision {
            // Preserve custom IDs when resuming an interrupted explicit reset.
            // A corrupt existing mapping must never trigger an implicit reset.
            match p.storage.load(Record::PivConfig, &mut self.config) {
                Ok(10) if repo::config_valid(&self.config) => (),
                Err(StorageError::Missing) => self.config = repo::DEFAULT_CONFIG,
                _ => return Err(Sw::UNABLE_TO_PROCESS),
            }
            self.provision(reset_credentials, p)?;
        }
        if p.storage
            .load(Record::PivConfig, &mut self.config)
            .map_err(repo::io)?
            != 10
            || !repo::config_valid(&self.config)
        {
            return Err(Sw::UNABLE_TO_PROCESS);
        }
        Ok(())
    }
    pub(super) fn provision(
        &mut self,
        reset_credentials: bool,
        p: &mut Platform<'_>,
    ) -> Result<(), Sw> {
        p.storage
            .replace(
                Record::PivProvision,
                &[if reset_credentials {
                    RESET_PENDING
                } else {
                    INSTALL_PENDING
                }],
            )
            .map_err(repo::io)?;
        for id in repo::KEYS.iter().take(repo::USER_KEY_COUNT) {
            p.storage.remove(*id).map_err(repo::io)?;
        }
        for (i, id) in repo::OBJECTS.iter().enumerate() {
            if i != repo::ATTESTATION_KEY {
                p.storage.remove(*id).map_err(repo::io)?;
            }
        }
        let mut m = repo::management_record(policy::TOUCH_NEVER, &repo::DEFAULT_MGMT);
        let r = p
            .storage
            .replace(Record::PivManagement, &m)
            .map_err(repo::io);
        p.memory.wipe(&mut m);
        r?;
        // Card Capability Container (CCC): F0 identifier, F1/F2 version 2.1,
        // F5 data-model number 10; remaining optional fields are empty.
        let mut ccc = [
            0x53, 0x33, 0xf0, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1, 0x01, 0x21,
            0xf2, 0x01, 0x21, 0xf3, 0x00, 0xf4, 0x01, 0x00, 0xf5, 0x01, 0x10, 0xf6, 0x00, 0xf7,
            0x00, 0xfa, 0x00, 0xfb, 0x00, 0xfc, 0x00, 0xfd, 0x00, 0xfe, 0x00,
        ];
        p.crypto
            .random(&mut ccc[CCC_CARD_ID])
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        p.storage
            .replace(repo::OBJECTS[repo::CAPABILITY_OBJECT_INDEX], &ccc)
            .map_err(repo::io)?;
        // Cardholder Unique Identifier (CHUID): fixed FASC-N (30), random GUID
        // (34), expiration date 20500101 (35), empty issuer signature (3E),
        // and error-detection code (FE). The outer 53 wraps the object content.
        let mut chuid = [
            0x53, 0x3b, 0x30, 0x19, 0xd4, 0xe7, 0x39, 0xda, 0x73, 0x9c, 0xed, 0x39, 0xce, 0x73,
            0x9d, 0x83, 0x68, 0x58, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0xc8, 0x42, 0x10, 0xc3,
            0xeb, 0x34, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x35, 0x08, 0x32, 0x30, 0x35, 0x30, 0x30, 0x31, 0x30,
            0x31, 0x3e, 0x00, 0xfe, 0x00,
        ];
        p.crypto
            .random(&mut chuid[CHUID_GUID])
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        p.storage
            .replace(repo::OBJECTS[repo::CHUID_OBJECT_INDEX], &chuid)
            .map_err(repo::io)?;
        if reset_credentials {
            self.pins.defaults(3, 3, p)?;
        }
        p.storage
            .replace(Record::PivConfig, &self.config)
            .map_err(repo::io)?;
        p.storage
            .replace(Record::PivProvision, &[COMPLETE])
            .map_err(repo::io)
    }
}
