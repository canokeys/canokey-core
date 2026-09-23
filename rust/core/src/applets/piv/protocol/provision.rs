// SPDX-License-Identifier: Apache-2.0
//! Persistent initialization and reset, preserving the F9 attestation identity.
use super::*;

impl Piv {
    pub(crate) fn reset_persistent(&mut self, p: &mut Platform<'_>) -> Result<(), Sw> {
        self.provision(true, p)
    }

    pub fn install(&mut self, p: &mut Platform<'_>) -> Result<(), Sw> {
        self.pins.install(p)?;
        let mut status = [0; 1];
        let provision = match p.storage.load(Record::PivProvision, &mut status) {
            Ok(1) if status[0] == 1 => None,
            Ok(1) if status[0] == 0 => Some(true),
            Ok(1) if status[0] == 2 => Some(false),
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
                &[if reset_credentials { 0 } else { 2 }],
            )
            .map_err(repo::io)?;
        for id in repo::KEYS.iter().take(24) {
            p.storage.remove(*id).map_err(repo::io)?;
        }
        for (i, id) in repo::OBJECTS.iter().enumerate() {
            if i != 24 {
                p.storage.remove(*id).map_err(repo::io)?;
            }
        }
        let mut m = [0; 26];
        m[0] = 1;
        m[1] = 1;
        m[2..].copy_from_slice(&repo::DEFAULT_MGMT);
        let r = p
            .storage
            .replace(Record::PivManagement, &m)
            .map_err(repo::io);
        p.memory.wipe(&mut m);
        r?;
        let mut ccc = [
            0x53, 0x33, 0xf0, 0x15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0xf1, 1, 0x21, 0xf2, 1, 0x21, 0xf3, 0, 0xf4, 1, 0, 0xf5, 1, 0x10, 0xf6, 0, 0xf7, 0,
            0xfa, 0, 0xfb, 0, 0xfc, 0, 0xfd, 0, 0xfe, 0,
        ];
        p.crypto
            .random(&mut ccc[4..25])
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        p.storage
            .replace(repo::OBJECTS[28], &ccc)
            .map_err(repo::io)?;
        let mut chuid = [
            0x53, 0x3b, 0x30, 0x19, 0xd4, 0xe7, 0x39, 0xda, 0x73, 0x9c, 0xed, 0x39, 0xce, 0x73,
            0x9d, 0x83, 0x68, 0x58, 0x21, 8, 0x42, 0x10, 0x84, 0x21, 0xc8, 0x42, 0x10, 0xc3, 0xeb,
            0x34, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x35, 8, 0x32, 0x30, 0x35,
            0x30, 0x30, 0x31, 0x30, 0x31, 0x3e, 0, 0xfe, 0,
        ];
        p.crypto
            .random(&mut chuid[31..47])
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        p.storage
            .replace(repo::OBJECTS[25], &chuid)
            .map_err(repo::io)?;
        if reset_credentials {
            self.pins.defaults(3, 3, p)?;
        }
        p.storage
            .replace(Record::PivConfig, &self.config)
            .map_err(repo::io)?;
        p.storage
            .replace(Record::PivProvision, &[1])
            .map_err(repo::io)
    }
}
