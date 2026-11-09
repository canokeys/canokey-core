// SPDX-License-Identifier: Apache-2.0
//! Ordinary credential selection and product create/assert transaction adapter.
use super::*;
use canokey_ctap::selection::{self, Walk};
pub(super) struct Operation<'a, 'p, B: crate::ports::Backends> {
    pub session: &'a mut Session,
    pub params: &'a Parameters,
    pub workspace: &'a mut SessionWorkspace,
    pub platform: &'a mut Platform<'p, B>,
    pub rp: &'a [u8; 32],
    pub uv: bool,
    pub min_pin_length: Option<u8>,
    pub selected: Option<credential::Id>,
    pub user_slot: Option<u8>,
    pub count: u8,
}
impl<B: crate::ports::Backends> selection::Backend for Operation<'_, '_, B> {
    type Error = Status;
    type Output = usize;
    #[inline(always)]
    fn select(&mut self) -> Result<bool, Status> {
        let params = self.params;
        let rp = self.rp;
        let p = &mut *self.platform;
        let w = &mut self.workspace.classic_with(p.memory);
        let session = &mut *self.session;
        let selected = selection::listed(
            params.ids().iter().map(|id| Ok::<_, Status>(Some(id))),
            Walk::First,
            |id| {
                if !credential::permitted_id(id) {
                    return Ok(None);
                }
                let user_slot = if id[1] & resident::RESIDENT != 0 {
                    let Some((index, _)) = resident::find(id, rp, w.input, p)? else {
                        return Ok(None);
                    };
                    Some(index)
                } else {
                    None
                };
                match credential::open(id, session.sm2, rp, w.key, p) {
                    Ok(_) if id[1] & credential::CRED_PROTECT_MASK != 3 || self.uv => {
                        Ok(Some((*id, user_slot)))
                    }
                    Ok(_) | Err(Status::NoCredentials) => Ok(None),
                    Err(error) => Err(error),
                }
            },
        )?;
        if let Some((id, user_slot)) = selected {
            self.selected = Some(id);
            self.user_slot = user_slot;
        }
        if !params.make && !params.list_present {
            let mut next = crate::ports::Record::CTAP_CREDENTIALS;
            while let Some((index, id)) = resident::discover(&mut next, rp, self.uv, w.input, p)? {
                self.count += 1;
                if self.selected.is_none() {
                    self.selected = Some(id);
                    self.user_slot = Some(index);
                }
            }
        }
        p.memory.wipe(&mut w.key.bytes);
        Ok(self.selected.is_some())
    }
    #[inline(always)]
    fn presence(&mut self, up: bool) -> Result<(), Status> {
        if up {
            self.session.credential_presence(
                &mut self.workspace.classic_with(self.platform.memory),
                self.platform,
            )
        } else {
            Ok(())
        }
    }
    #[inline(always)]
    fn excluded(result: Result<(), Status>) -> Status {
        match result {
            Err(Status::Cancelled) => Status::Cancelled,
            _ => Status::CredentialExcluded,
        }
    }
    #[inline(always)]
    fn no_credentials() -> Status {
        Status::NoCredentials
    }
    #[inline(always)]
    fn consume_presence(&mut self) {
        // Successful normal UP consumes standard grants except LBW. Silent
        // assertions keep the authorization used for interactive assertions.
        self.session.pin_token.permissions = canokey_ctap::client_pin::token::after_presence(
            u16::from(self.session.pin_token.permissions),
            u16::from(pin::PERMISSION_LARGE_BLOB_WRITE),
        ) as u8;
        if self.session.pin_token.permissions == 0 {
            self.session.clear_token(self.platform.memory);
        }
    }
    #[inline(always)]
    fn complete(self) -> Result<usize, Status> {
        let params = self.params;
        let rp = self.rp;
        let p = &mut *self.platform;
        let w = &mut self.workspace.classic_with(p.memory);
        let session = &mut *self.session;
        let uv = self.uv;
        if let Some(hmac) = &params.hmac {
            session.prepare_hmac(hmac, w, p)?;
        }
        if !params.make {
            session.assertion.rp = *rp;
            session.assertion.client_hash = params.client_hash;
            session.assertion.next = self.user_slot.unwrap_or(0);
            session.assertion.remaining = self.count.saturating_sub(1);
            session.assertion.uv = uv;
            session.assertion.up = params.up;
            session.assertion.get_cred_blob = params.get_cred_blob;
            session.assertion.third_party_payment = params.third_party_payment;
            return session.sign_assertion(
                &self.selected.ok_or(Status::NoCredentials)?,
                self.user_slot,
                self.count,
                self.count > 1,
                w,
                p,
            );
        }
        let algorithm = params.algorithm.ok_or(Status::UnsupportedAlgorithm)?;
        canokey_ctap::registration::execute(
            params.resident,
            Registration {
                session,
                params,
                workspace: self.workspace,
                platform: p,
                rp,
                uv,
                min_pin_length: self.min_pin_length,
                algorithm,
            },
        )
    }
}

struct Registration<'a, 'p, B: crate::ports::Backends> {
    session: &'a mut Session,
    params: &'a Parameters,
    workspace: &'a mut SessionWorkspace,
    platform: &'a mut Platform<'p, B>,
    rp: &'a [u8; 32],
    uv: bool,
    min_pin_length: Option<u8>,
    algorithm: u8,
}
impl<B: crate::ports::Backends> canokey_ctap::registration::Backend for Registration<'_, '_, B> {
    type Error = Status;
    type Credential = credential::Id;
    type Publication = crate::ports::Record;
    type Output = usize;
    #[inline(always)]
    fn create(&mut self) -> Result<Self::Credential, Status> {
        let params = self.params;
        let rp = self.rp;
        let p = &mut *self.platform;
        let w = &mut self.workspace.classic_with(p.memory);
        let session = &mut *self.session;
        let algorithm = self.algorithm;
        let id = credential::create(
            algorithm,
            params.protection
                | if params.third_party_payment {
                    credential::THIRD_PARTY_PAYMENT
                } else {
                    0
                }
                | if params.large_blob_key {
                    resident::LARGE_BLOB_KEY
                } else {
                    0
                }
                | if params.resident {
                    resident::RESIDENT
                } else {
                    0
                },
            session.sm2,
            rp,
            w.key,
            p,
        )?;
        Ok(id)
    }
    #[inline(always)]
    fn stage(&mut self, id: &Self::Credential) -> Result<Self::Publication, Status> {
        let params = self.params;
        let rp = self.rp;
        let p = &mut *self.platform;
        let w = &mut self.workspace.classic_with(p.memory);
        // Stage the complete group while the ECC/PQ credential key is live.
        // Release this scratch before signing; only commit publishes the stage.
        // Unrelated record replacements use the separate platform temp file.
        const COPY_OFFSET: usize =
            crate::ports::key_layout::ECC_PUBLIC + crate::ports::key_layout::ECC_PUBLIC_BYTES;
        const {
            assert!(crate::ports::key_layout::SIZE - COPY_OFFSET >= resident::COPY_BYTES);
        }
        resident::prepare(
            params,
            id,
            rp,
            w.output,
            (&mut w.key.bytes[COPY_OFFSET..COPY_OFFSET + resident::COPY_BYTES])
                .try_into()
                .unwrap(),
            p,
        )
    }
    #[inline(always)]
    fn commit(&mut self, _: &Self::Credential, record: &Self::Publication) -> Result<(), Status> {
        use canokey_ports::Storage as _;
        self.platform
            .storage
            .stage_commit(*record)
            .map_err(|_| Status::Other)
    }
    #[inline(always)]
    fn abort(&mut self, _: &Self::Publication) {
        use canokey_ports::Storage as _;
        self.platform.storage.stage_abort();
    }
    #[inline(always)]
    fn respond(&mut self, id: &Self::Credential) -> Result<usize, Status> {
        let params = self.params;
        let rp = self.rp;
        let p = &mut *self.platform;
        let w = &mut self.workspace.classic_with(p.memory);
        let session = &mut *self.session;
        let algorithm = self.algorithm;
        let uv = self.uv;
        let min_pin_length = self.min_pin_length;
        let length = respond(
            &Signing {
                id,
                rp,
                client_hash: &params.client_hash,
                algorithm,
                sm2: session.sm2,
                make: true,
                up: params.up,
                uv,
                user_slot: None,
                count: 0,
                details: false,
                min_pin_length,
                hmac_secret: params.hmac_secret,
                hmac: &session.assertion.hmac,
                cred_blob: params.cred_blob_len.map(|n| params.resident && n <= 32),
                get_cred_blob: params.get_cred_blob,
                third_party_payment: params.third_party_payment,
                protection: params.protection_requested.then_some(params.protection),
            },
            w,
            p,
            &mut session.auth_response,
        )?;
        // A PQ framing plan is not a prepared response: public hashing,
        // attestation and reopening must succeed before resident publication.
        if let Some(super::super::Response::Pending(plan)) = &session.auth_response {
            let plan = *plan;
            let length = super::super::pq::Stream::prepare(plan, self.workspace, p)?;
            session.auth_response = Some(super::super::Response::Stream(length));
            Ok(length)
        } else {
            Ok(length)
        }
    }
}
