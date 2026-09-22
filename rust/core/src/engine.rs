// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
use canokey_protocol::{
    apdu,
    response::{ResponsePlan, StatusWord},
};

/// Platform services only. File IDs are opaque to the C interface; all record
/// formats, authorization and applet behavior are implemented in Rust.
pub trait Platform {
    fn size(&mut self, file: u8) -> i32;
    fn read(&mut self, file: u8, output: &mut [u8]) -> i32;
    fn write(&mut self, file: u8, input: &[u8]) -> i32;
    fn wipe(&mut self, bytes: &mut [u8]);
    fn sha256(&mut self, input: &[u8], output: &mut [u8; 32]);
    fn hmac_sha1(&mut self, key: &[u8; 20], input: &[u8], output: &mut [u8; 20]);
}

#[derive(Clone, Copy)]
pub enum Reply {
    Status(StatusWord),
    Data(u32),
}

#[derive(Clone, Copy)]
struct Pending {
    total: u32,
    offset: u32,
    sw: StatusWord,
}

pub struct Core {
    owner: u8,
    selected: bool,
    chain: apdu::CommandChain,
    pending: Option<Pending>,
    #[cfg(feature = "pass")]
    pass: crate::pass::Pass,
}

impl Default for Core {
    fn default() -> Self {
        Self::new()
    }
}

impl Core {
    pub const fn new() -> Self {
        Self {
            owner: 0,
            selected: false,
            chain: apdu::CommandChain::new(),
            pending: None,
            #[cfg(feature = "pass")]
            pass: crate::pass::Pass::new(),
        }
    }
    pub const fn applet_count() -> u8 {
        if cfg!(feature = "pass") { 1 } else { 0 }
    }

    pub fn install(&mut self, platform: &mut dyn Platform) -> Result<(), StatusWord> {
        self.reset(platform);
        #[cfg(feature = "pass")]
        self.pass.install(platform)?;
        Ok(())
    }

    /// Called by the transport on disconnect/reset or an explicitly authorized
    /// owner handoff. Timeout policy belongs to the interface, not an applet.
    pub fn reset(&mut self, platform: &mut dyn Platform) {
        self.owner = 0;
        self.selected = false;
        self.pending = None;
        self.chain.reset();
        #[cfg(feature = "pass")]
        self.pass.reset(platform);
        #[cfg(not(feature = "pass"))]
        let _ = platform;
    }

    /// Consume the complete short transport frame. Its bytes expire at return.
    /// ISO command chains are consumed into the selected applet's bounded
    /// semantic fields, not a core-wide full-command buffer.
    pub fn receive(&mut self, owner: u8, frame: &[u8], platform: &mut dyn Platform) -> Reply {
        if owner == 0 || (self.owner != 0 && self.owner != owner) {
            return Reply::Status(StatusWord::CONDITIONS_NOT_SATISFIED);
        }
        self.owner = owner;
        let command = match apdu::parse(frame) {
            Ok(command) => command,
            Err(_) => {
                self.pending = None;
                self.chain.reset();
                #[cfg(feature = "pass")]
                self.pass.cancel_command(platform);
                return Reply::Status(StatusWord::WRONG_LENGTH);
            }
        };
        // The parser supports extended format; this minimal transport profile
        // admits short frames and ISO chaining only. No implicit FIDO exception.
        if command.info.extended {
            self.pending = None;
            self.chain.reset();
            #[cfg(feature = "pass")]
            self.pass.cancel_command(platform);
            return Reply::Status(StatusWord::WRONG_LENGTH);
        }
        let header = command.info.header;
        let le = command.info.legacy_le();
        if header.is_get_response() {
            self.chain.reset();
            #[cfg(feature = "pass")]
            self.pass.cancel_command(platform);
            return if self.pending.is_some() {
                Reply::Data(le)
            } else {
                Reply::Status(StatusWord::COMMAND_NOT_ALLOWED)
            };
        }
        self.pending = None;
        if header.cla == 0 && header.ins == 0xa4 && header.p1 == 4 {
            self.chain.reset();
            self.selected = false;
            #[cfg(feature = "pass")]
            {
                self.pass.reset(platform);
                if header.p2 == 0 && command.data == crate::pass::MANAGEMENT_AID {
                    self.selected = true;
                    return Reply::Status(StatusWord::SUCCESS);
                }
            }
            return Reply::Status(if header.p2 == 0 {
                StatusWord::FILE_NOT_FOUND
            } else {
                StatusWord::WRONG_P1P2
            });
        }
        if !self.selected {
            return Reply::Status(StatusWord::FILE_NOT_FOUND);
        }
        #[cfg(feature = "pass")]
        {
            if header.unchained().cla != 0 {
                self.chain.reset();
                self.pass.cancel_command(platform);
                return Reply::Status(StatusWord::CLA_NOT_SUPPORTED);
            }
            // PASS needs at most one PIN or password/key field. Large future
            // applets will supply incremental consumers, not enlarge this bound.
            let step = match self
                .chain
                .accept(command.info, crate::pass::COMMAND_CAPACITY as u32)
            {
                Ok(step) => step,
                Err(_) => {
                    self.pass.cancel_command(platform);
                    return Reply::Status(StatusWord::WRONG_LENGTH);
                }
            };
            if step.restarted {
                self.pass.cancel_command(platform);
            }
            if let Err(sw) = self.pass.consume(command.data) {
                self.chain.reset();
                self.pass.cancel_command(platform);
                return Reply::Status(sw);
            }
            if !step.last {
                return Reply::Status(StatusWord::SUCCESS);
            }
            match self.pass.finish(header.unchained(), platform) {
                Ok(0) => Reply::Status(StatusWord::SUCCESS),
                Ok(total) => {
                    self.pending = Some(Pending {
                        total,
                        offset: 0,
                        sw: StatusWord::SUCCESS,
                    });
                    Reply::Data(le)
                }
                Err(sw) => Reply::Status(sw),
            }
        }
        #[cfg(not(feature = "pass"))]
        {
            let _ = platform;
            Reply::Status(StatusWord::INS_NOT_SUPPORTED)
        }
    }

    /// Produce payload plus SW. Called only after the input borrow ends, so a C
    /// interface can use the same transport buffer for RX and TX. Streamed data
    /// is regenerated from stable Rust applet state; no saved-tail C machinery.
    pub fn transmit(&mut self, reply: Reply, output: &mut [u8]) -> Result<usize, StatusWord> {
        if output.len() < 2 {
            return Err(StatusWord::WRONG_LENGTH);
        }
        #[cfg(feature = "pass")]
        let mut len = 0;
        #[cfg(not(feature = "pass"))]
        let len = 0;
        let sw = match reply {
            Reply::Status(sw) => sw,
            Reply::Data(le) => {
                let Some(pending) = self.pending else {
                    return Self::status_only(output, StatusWord::COMMAND_NOT_ALLOWED);
                };
                let capacity = (output.len() - 2).min(256) as u32;
                let plan =
                    ResponsePlan::new(pending.total, pending.offset, le.min(capacity), pending.sw)?;
                #[cfg(feature = "pass")]
                {
                    len = plan.length as usize;
                    if self
                        .pass
                        .read_response(pending.offset as usize, &mut output[..len])
                        .is_err()
                    {
                        self.pending = None;
                        return Self::status_only(output, StatusWord::UNABLE_TO_PROCESS);
                    }
                }
                self.pending = if plan.complete {
                    None
                } else {
                    Some(Pending {
                        offset: plan.next,
                        ..pending
                    })
                };
                plan.sw
            }
        };
        output[len..len + 2].copy_from_slice(&sw.bytes());
        Ok(len + 2)
    }

    fn status_only(output: &mut [u8], sw: StatusWord) -> Result<usize, StatusWord> {
        output[..2].copy_from_slice(&sw.bytes());
        Ok(2)
    }

    #[cfg(feature = "pass")]
    pub fn touch(
        &self,
        index: u8,
        output: &mut [u8],
        platform: &mut dyn Platform,
    ) -> Result<usize, StatusWord> {
        self.pass.touch(index, output, platform)
    }
    #[cfg(feature = "pass")]
    pub fn challenge(
        &self,
        index: u8,
        challenge: &[u8],
        output: &mut [u8; 20],
        platform: &mut dyn Platform,
    ) -> Result<(), StatusWord> {
        self.pass.challenge(index, challenge, output, platform)
    }
}
