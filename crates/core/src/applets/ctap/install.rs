// SPDX-License-Identifier: Apache-2.0
//! Boot initializes volatile state; manufacturing records are admitted at use.
use super::{Session, settings::Sm2};

impl Session {
    pub(super) fn install(&mut self) {
        // Missing or corrupt manufacturing records cannot authorize credential
        // erasure or prevent ADMIN recovery. Commands load SM2 settings and
        // select attestation material through the shared admission functions.
        // Only boot installation restores the volatile retry allowance.
        // Transport/session reset must not bypass temporary PIN lockout.
        self.pin_attempts = super::wire::pin_protocol::SESSION_ATTEMPTS;
        self.sm2 = Sm2::DEFAULT;
    }
}
