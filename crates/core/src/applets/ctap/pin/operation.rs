// SPDX-License-Identifier: Apache-2.0
//! ClientPIN record/workspace transaction adapter. Secrets stay in owner backing.
use super::*;
use canokey_ctap::client_pin::operation::{self, AdmissionError, State};

pub(super) struct Operation<'a, 'p, 'w, B: crate::ports::Backends> {
    pub session: &'a mut Session,
    pub parameters: &'a mut Parameters,
    pub workspace: &'a mut Workspace<'w>,
    pub platform: &'a mut Platform<'p, B>,
    pub shared: &'a mut [u8; 64],
    pub record: &'a mut [u8; RECORD_BYTES],
}
impl<B: crate::ports::Backends> Operation<'_, '_, '_, B> {
    fn replace_pin(&mut self) -> Result<usize, Status> {
        let cp = &mut *self.parameters;
        let w = &mut *self.workspace;
        let p = &mut *self.platform;
        let record = &mut *self.record;
        let aes_key = self.shared[32..].try_into().unwrap();
        let new_len = wire::new_pin_bytes(cp.protocol);
        decrypt(cp.protocol, aes_key, &mut cp.new_pin[..new_len], p)?;
        let unpadded =
            shared_pin::unpad_pin((&cp.new_pin[..wire::PADDED_PIN_BYTES]).try_into().unwrap());
        let pin = shared_pin::validate_pin(unpadded, usize::from(record[MIN_PIN_LENGTH]))
            .ok_or(Status::PinPolicy)?;
        let count = pin.chars().count();
        let mut digest = [0x00; 32];
        let hash = p
            .crypto
            .sha256(pin.as_bytes(), &mut digest)
            .map_err(|_| Status::Other);
        record[..PIN_HASH_BYTES].copy_from_slice(&digest[..PIN_HASH_BYTES]);
        p.memory.wipe(&mut digest);
        hash?;
        record[RETRIES] = MAX_RETRIES;
        record[PIN_LENGTH] = count as u8;
        record[FLAGS] &= !FORCE_CHANGE;
        save(record, p)?;
        self.session.clear_token(p.memory);
        w.output[0] = 0x00;
        Ok(1)
    }
}
impl<B: crate::ports::Backends> operation::Backend for Operation<'_, '_, '_, B> {
    type Error = Status;
    type Output = usize;
    type Shared = ();
    type CurrentPin = ();
    fn admission_error(error: AdmissionError) -> Status {
        match error {
            AdmissionError::AlreadyConfigured => Status::PinAuthInvalid,
            AdmissionError::NotConfigured => Status::PinNotSet,
            AdmissionError::Blocked => Status::PinBlocked,
            AdmissionError::PowerCycleBlocked => Status::PinAuthBlocked,
        }
    }
    fn state(&mut self) -> Result<State, Status> {
        load(self.platform, self.record)?;
        Ok(State {
            configured: self.record[PIN_LENGTH] != 0,
            retries: self.record[RETRIES],
            power_cycle_blocked: self.session.pin_attempts == 0,
        })
    }
    fn agree(&mut self) -> Result<(), Status> {
        self.session.decapsulate(
            self.parameters.protocol,
            &self.parameters.agreement,
            self.shared,
            self.workspace,
            self.platform,
        )
    }
    fn authenticate_new_pin(&mut self, _: &(), changing: bool) -> Result<(), Status> {
        let cp = &mut *self.parameters;
        let w = &mut *self.workspace;
        let p = &mut *self.platform;
        let shared = &*self.shared;
        let new_len = wire::new_pin_bytes(cp.protocol);
        let hash_len = wire::auth_bytes(cp.protocol);
        w.input[..new_len].copy_from_slice(&cp.new_pin[..new_len]);
        let n = if changing {
            w.input[new_len..new_len + hash_len].copy_from_slice(&cp.pin_hash[..hash_len]);
            new_len + hash_len
        } else {
            new_len
        };
        verify_mac(&shared[..32], &cp.auth[..hash_len], &w.input[..n], p)?;
        Ok(())
    }
    fn prepare_current_pin(&mut self, _: &()) -> Result<(), Status> {
        let cp = &mut *self.parameters;
        let p = &mut *self.platform;
        let record = &mut *self.record;
        let aes_key = self.shared[32..].try_into().unwrap();
        retry::verify(&mut CurrentPin {
            session: self.session,
            parameters: cp,
            record,
            aes_key,
            platform: p,
        })
    }
    fn set_pin(&mut self, _: &()) -> Result<usize, Status> {
        self.replace_pin()
    }
    fn change_pin(&mut self, _: &(), _: &()) -> Result<usize, Status> {
        self.replace_pin()
    }
    fn issue_token(&mut self, _: &(), _: &()) -> Result<usize, Status> {
        let cp = &mut *self.parameters;
        let w = &mut *self.workspace;
        let p = &mut *self.platform;
        let record = &mut *self.record;
        let aes_key = self.shared[32..].try_into().unwrap();
        if record[FLAGS] & FORCE_CHANGE != 0 {
            return Err(if cp.subcommand == wire::GET_TOKEN {
                Status::PinInvalid
            } else {
                Status::PinPolicy
            });
        }
        self.session.clear_token(p.memory);
        p.crypto
            .random(&mut self.session.token)
            .map_err(|_| Status::Other)?;
        let n = shared_pin::cipher::encrypt(
            cipher_protocol(cp.protocol),
            aes_key,
            &self.session.token,
            &mut w.output[TOKEN_RESPONSE_HEADER_BYTES..],
            &mut PinCrypto(p),
        )
        .map_err(cipher_error)?;
        w.output[0] = 0x00;
        w.output[1..TOKEN_RESPONSE_HEADER_BYTES]
            .copy_from_slice(&response::token_prefix(cipher_protocol(cp.protocol)));
        self.session.token_started = p.device.now();
        self.session.token_used = self.session.token_started;
        if cp.subcommand == wire::GET_TOKEN_PERMISSIONS && cp.rp_len != 0 {
            p.crypto
                .sha256(&cp.rp[..cp.rp_len], &mut self.session.rp_binding)
                .map_err(|_| Status::Other)?;
            self.session.rp_bound = true;
        }
        self.session.permissions = if cp.subcommand == wire::GET_TOKEN {
            wire::PERMISSION_RP
        } else {
            cp.permissions
        };
        Ok(TOKEN_RESPONSE_HEADER_BYTES + n)
    }
}
