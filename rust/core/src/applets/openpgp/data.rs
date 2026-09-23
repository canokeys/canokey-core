// SPDX-License-Identifier: Apache-2.0
//! OpenPGP data-object schema; persistence remains in the repository.
use super::domain::{key_role, touch_policy};
use super::repository::{key_meta, state_layout};
use super::wire::{limits, tag};
use super::{
    domain::Algorithm,
    encoding::Writer,
    pin,
    protocol::{AID, OpenPgp},
    repository::{self as repo, KEYS, io},
};
use crate::ports::alg;
use crate::{Platform, ports::Record};
use canokey_protocol::response::StatusWord as Sw;
// Suffix of the OpenPGP application identifier (AID), before the device serial:
// specification version 3.4, then CanoKey manufacturer ID 0xF1D0 (big-endian).
const CARD_VERSION_AND_MANUFACTURER: &[u8] = &[0x03, 0x04, 0xf1, 0xd0];
// OpenPGP Card 3.4, DO 5F52 (ISO 7816 historical bytes). This is card discovery
// metadata, not an event log. Compact-TLV headers encode tag/length in nibbles.
// Keep the advertised profile aligned with applets/openpgp/openpgp.c.
const HISTORICAL_BYTES: &[u8] = &[
    0x00, // Category indicator: final three bytes contain card status.
    0x31, 0xc5, // Card-service data: compact tag 3, one-byte service flags.
    0x73, // Card capabilities: compact tag 7, three-byte value follows.
    0xc0, // Application selection by full or partial DF name (AID).
    0x01, // Data-coding byte from the OpenPGP card profile.
    0x80, // Command chaining supported; extended-length APDUs not advertised.
    0x05, // Card life-cycle indicator: operational (activated).
    0x90, 0x00, // Card-status word: normal processing.
];
// OpenPGP Card 3.4, DO C0: extended capabilities, returned as a value without
// the C0 tag/length. All two-byte limits below are big-endian byte counts.
const EXTENDED_CAPABILITIES: &[u8] = &[
    0x74, // Flags: GET CHALLENGE (40), key import (20), PW1 mode (10), algorithms (04).
    0x00, // No secure-messaging algorithm (SM).
    0x01,
    0x00, // Maximum GET CHALLENGE response: 256 bytes.
    // Same big-endian certificate byte limit enforced by the command router.
    limits::CERTIFICATE_BYTES.to_be_bytes()[0],
    limits::CERTIFICATE_BYTES.to_be_bytes()[1],
    0x00,
    0xff, // Maximum special data-object content: 255 bytes.
    0x00, // ISO 9564 PIN block format 2 is not supported.
    0x00, // MANAGE SECURITY ENVIRONMENT (MSE) is not supported.
];
impl OpenPgp {
    #[inline(never)]
    pub(super) fn get(&self, tag: u16, out: &mut [u8], p: &mut Platform<'_>) -> Result<usize, Sw> {
        let mut s = [0; repo::STATE_LEN];
        repo::state(p, &mut s)?;
        let mut v = Writer::new(out);
        if matches!(
            tag,
            tag::CARDHOLDER
                | tag::APPLICATION
                | tag::DISCRETIONARY
                | tag::SECURITY_SUPPORT
                | tag::ALGORITHM_INFORMATION
        ) {
            let start = v.open(tag)?;
            self.emit(tag, &mut v, &s, p)?;
            v.close(start)?;
        } else {
            self.emit(tag, &mut v, &s, p)?;
        }
        Ok(v.len)
    }
    fn emit(
        &self,
        tag: u16,
        v: &mut Writer<'_>,
        s: &[u8; repo::STATE_LEN],
        p: &mut Platform<'_>,
    ) -> Result<(), Sw> {
        if let Some((off, _)) = repo::field(tag) {
            return v.bytes(&s[off + 1..off + 1 + s[off] as usize]);
        }
        match tag {
            tag::AID => {
                let mut serial = [0; 4];
                p.device.serial(&mut serial);
                v.bytes(AID)?;
                v.bytes(CARD_VERSION_AND_MANUFACTURER)?;
                v.bytes(&serial)?;
                // Last two bytes of the 16-byte OpenPGP AID are reserved.
                v.bytes(&[0x00, 0x00])
            }
            tag::HISTORICAL_BYTES => v.bytes(HISTORICAL_BYTES),
            // General Feature Management: tag 81, one-byte feature bitmap;
            // bit 0x20 advertises the button used for user-presence checks.
            tag::GENERAL_FEATURES => v.bytes(&[0x81, 0x01, 0x20]),
            tag::EXTENDED_CAPABILITIES => v.bytes(EXTENDED_CAPABILITIES),
            tag::CARDHOLDER | tag::APPLICATION | tag::DISCRETIONARY => {
                let tags: &[u16] = match tag {
                    tag::CARDHOLDER => &[tag::NAME, tag::LANGUAGE, tag::SEX],
                    tag::APPLICATION => &[
                        tag::AID,
                        tag::HISTORICAL_BYTES,
                        tag::GENERAL_FEATURES,
                        tag::DISCRETIONARY,
                    ],
                    _ => &[
                        tag::EXTENDED_CAPABILITIES,
                        tag::ALGORITHM_SIG,
                        tag::ALGORITHM_DEC,
                        tag::ALGORITHM_AUT,
                        tag::PW_STATUS,
                        tag::FINGERPRINTS,
                        tag::CA_FINGERPRINTS,
                        tag::CREATION_TIMES,
                        tag::KEY_INFORMATION,
                        tag::UIF_SIG,
                        tag::UIF_DEC,
                        tag::UIF_AUT,
                    ],
                };
                for &t in tags {
                    let at = v.open(t)?;
                    self.emit(t, v, s, p)?;
                    v.close(at)?;
                }
                Ok(())
            }
            tag::ALGORITHM_SIG..=tag::ALGORITHM_AUT => {
                let r = (tag - tag::ALGORITHM_SIG) as usize;
                let a = Algorithm(repo::meta(p, r)?[key_meta::ALGORITHM]);
                let mut b = [0; 12];
                let n = a.attrs(r, &mut b);
                v.bytes(&b[..n])
            }
            tag::PW_STATUS => {
                let pw1 = pin::info(Record::PgpPw1, p)?.retries_remaining;
                let rc = pin::info(Record::PgpRc, p)?.retries_remaining;
                let pw3 = pin::info(Record::PgpPw3, p)?.retries_remaining;
                // PW status: signature-PW1 reuse flag, maximum PW1/RC/PW3
                // lengths (64 bytes each), then their remaining retry counts.
                v.bytes(&[s[state_layout::PW1_REUSE], 0x40, 0x40, 0x40, pw1, rc, pw3])
            }
            tag::FINGERPRINTS => {
                for r in 0..key_role::COUNT {
                    v.bytes(&repo::meta(p, r)?[key_meta::FINGERPRINT..key_meta::FINGERPRINT_END])?;
                }
                Ok(())
            }
            tag::CA_FINGERPRINTS => {
                v.bytes(&s[state_layout::CA_FINGERPRINTS..state_layout::CA_FINGERPRINTS_END])
            }
            tag::FINGERPRINT_SIG..=tag::FINGERPRINT_AUT => v.bytes(
                &repo::meta(p, (tag - tag::FINGERPRINT_SIG) as usize)?
                    [key_meta::FINGERPRINT..key_meta::FINGERPRINT_END],
            ),
            tag::CA_FINGERPRINT_1..=tag::CA_FINGERPRINT_3 => {
                let at = state_layout::CA_FINGERPRINTS
                    + (tag - tag::CA_FINGERPRINT_1) as usize * state_layout::FINGERPRINT_BYTES;
                v.bytes(&s[at..at + state_layout::FINGERPRINT_BYTES])
            }
            tag::CREATION_TIMES => {
                for r in 0..key_role::COUNT {
                    v.bytes(&repo::meta(p, r)?[key_meta::CREATED..key_meta::CREATED_END])?;
                }
                Ok(())
            }
            tag::CREATED_SIG..=tag::CREATED_AUT => v.bytes(
                &repo::meta(p, (tag - tag::CREATED_SIG) as usize)?
                    [key_meta::CREATED..key_meta::CREATED_END],
            ),
            tag::UIF_SIG..=tag::UIF_AUT => v.bytes(&[
                repo::meta(p, (tag - tag::UIF_SIG) as usize)?[key_meta::TOUCH_POLICY],
                0x20,
            ]),
            tag::KEY_INFORMATION => {
                for r in 0..key_role::COUNT {
                    v.bytes(&[r as u8 + 1, repo::meta(p, r)?[key_meta::ORIGIN]])?;
                }
                Ok(())
            }
            tag::SECURITY_SUPPORT => {
                v.header(tag::SIGNATURE_COUNTER, 3)?;
                v.bytes(&repo::meta(p, 0)?[key_meta::SIGNATURE_COUNTER..key_meta::END])
            }
            tag::TOUCH_CACHE => {
                v.bytes(&s[state_layout::TOUCH_CACHE_SECONDS..state_layout::FLAGS_END])
            }
            tag::ALGORITHM_INFORMATION => {
                for r in 0..key_role::COUNT {
                    for a in (alg::P256..=alg::P521)
                        .map(Algorithm)
                        .filter(|a| a.allowed(r))
                    {
                        let mut b = [0; 12];
                        let n = a.attrs(r, &mut b);
                        v.header(tag::ALGORITHM_SIG + r as u16, n)?;
                        v.bytes(&b[..n])?;
                    }
                }
                Ok(())
            }
            _ => Err(Sw::REFERENCE_NOT_FOUND),
        }
    }
    #[inline(never)]
    pub(super) fn put(&mut self, tag: u16, b: &[u8], p: &mut Platform<'_>) -> Result<(), Sw> {
        if (tag::ALGORITHM_SIG..=tag::ALGORITHM_AUT).contains(&tag) {
            let r = (tag - tag::ALGORITHM_SIG) as usize;
            let a = Algorithm::parse(b, r).ok_or(Sw::WRONG_DATA)?;
            let mut m = repo::meta(p, r)?;
            if m[key_meta::ALGORITHM] != a.0 {
                m[key_meta::ALGORITHM] = a.0;
                m[key_meta::ORIGIN] = 0;
                p.storage.replace(KEYS[r], &m).map_err(io)?;
            }
            return Ok(());
        }
        if (tag::FINGERPRINT_SIG..=tag::FINGERPRINT_AUT).contains(&tag)
            || (tag::CREATED_SIG..=tag::CREATED_AUT).contains(&tag)
            || (tag::UIF_SIG..=tag::UIF_AUT).contains(&tag)
        {
            let (r, off, n) = if tag <= tag::FINGERPRINT_AUT {
                (
                    (tag - tag::FINGERPRINT_SIG) as usize,
                    key_meta::FINGERPRINT,
                    state_layout::FINGERPRINT_BYTES,
                )
            } else if tag <= tag::CREATED_AUT {
                (
                    (tag - tag::CREATED_SIG) as usize,
                    key_meta::CREATED,
                    key_meta::CREATED_END - key_meta::CREATED,
                )
            } else {
                ((tag - tag::UIF_SIG) as usize, key_meta::TOUCH_POLICY, 2)
            };
            if b.len() != n {
                return Err(Sw::WRONG_LENGTH);
            }
            let mut m = repo::meta(p, r)?;
            if off == key_meta::TOUCH_POLICY {
                if m[key_meta::TOUCH_POLICY] == touch_policy::FIXED {
                    return Err(Sw::CONDITIONS_NOT_SATISFIED);
                }
                if b[0] > 2 || b[1] != 0x20 {
                    return Err(Sw::WRONG_DATA);
                }
                m[key_meta::TOUCH_POLICY] = b[0];
                self.session.clear_touch();
            } else {
                m[off..off + n].copy_from_slice(b);
            }
            return repo::put_meta(p, r, &m).map_err(Into::into);
        }
        if tag == tag::RESET_CODE {
            if b.is_empty() {
                let limit = pin::info(Record::PgpRc, p)?.retry_limit;
                return pin::create(Record::PgpRc, b, limit, p).map_err(Into::into);
            }
            return pin::change(Record::PgpRc, b, p).map_err(Into::into);
        }
        let mut s = [0; repo::STATE_LEN];
        repo::state(p, &mut s)?;
        if let Some((off, max)) = repo::field(tag) {
            if b.len() > max {
                return Err(Sw::WRONG_LENGTH);
            }
            s[off] = b.len() as u8;
            s[off + 1..off + 1 + max].fill(0);
            s[off + 1..off + 1 + b.len()].copy_from_slice(b);
        } else {
            match tag {
                tag::PW_STATUS => {
                    if b.len() != 1 {
                        return Err(Sw::WRONG_LENGTH);
                    }
                    if b[0] > 1 {
                        return Err(Sw::WRONG_DATA);
                    }
                    s[state_layout::PW1_REUSE] = b[0];
                }
                tag::TOUCH_CACHE => {
                    if b.len() != 1 {
                        return Err(Sw::WRONG_LENGTH);
                    }
                    s[state_layout::TOUCH_CACHE_SECONDS] = b[0];
                    self.session.clear_touch();
                }
                tag::CA_FINGERPRINT_1..=tag::CA_FINGERPRINT_3 => {
                    if b.len() != 20 {
                        return Err(Sw::WRONG_LENGTH);
                    }
                    let at = state_layout::CA_FINGERPRINTS
                        + (tag - tag::CA_FINGERPRINT_1) as usize * state_layout::FINGERPRINT_BYTES;
                    s[at..at + state_layout::FINGERPRINT_BYTES].copy_from_slice(b);
                }
                _ => return Err(Sw::REFERENCE_NOT_FOUND),
            }
        }
        repo::save_state(p, &s).map_err(Into::into)
    }
}
