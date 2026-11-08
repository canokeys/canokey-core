// SPDX-License-Identifier: Apache-2.0
//! NFC block lifecycle. APDU storage belongs to the shared transport workspace;
//! this state retains only the last transmitted Link packet for retransmission.
#![forbid(unsafe_code)]
pub mod request;
use canokey_protocol::nfc::{self, Block, Packet};
pub const COMMAND_LIMIT: usize = canokey_protocol::apdu::SHORT_FRAME_BYTES;
pub const MAX_RETRANSMITS: u8 = 2;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Wire(nfc::Error),
    Busy,
    Overflow,
    Sequence,
    Retransmits,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Send(Packet),
    Execute(usize),
    NextResponse,
    Waiting(u8),
    Deselect,
    Ignored,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Receiving,
    Executing,
    Responding,
    Ready,
    Complete,
}
pub struct Link {
    phase: Phase,
    number: u8,
    received: usize,
    cached: Option<Packet>,
    retransmits: u8,
    pending: bool,
}
impl Default for Link {
    fn default() -> Self {
        Self::new()
    }
}
impl Link {
    pub const fn new() -> Self {
        Self {
            phase: Phase::Receiving,
            number: 1,
            received: 0,
            cached: None,
            retransmits: 0,
            pending: false,
        }
    }
    pub fn reset(&mut self) {
        *self = Self::new();
    }
    pub fn dirty(&self) -> bool {
        self.received != 0
            || self.pending
            || matches!(
                self.phase,
                Phase::Executing | Phase::Responding | Phase::Ready
            )
    }
    fn retransmit(&mut self) -> Result<Event, Error> {
        if self.pending {
            return Err(Error::Busy);
        }
        let packet = self.cached.ok_or(Error::Sequence)?;
        if self.retransmits >= MAX_RETRANSMITS {
            return Err(Error::Retransmits);
        }
        self.retransmits += 1;
        Ok(Event::Send(packet))
    }
    #[inline(never)]
    fn acknowledge(&mut self) -> Event {
        let packet = Packet::acknowledgement(self.number);
        // Rule11 retries the last transmitted block, including control ACKs.
        // A control reply does not advance the response source or block number.
        self.cached = Some(packet);
        self.retransmits = 0;
        Event::Send(packet)
    }
    /// Called on the main-loop side, never while Core borrows `input`.
    /// CRC/error IRQs must be checked before presenting a FIFO frame here.
    pub fn receive(&mut self, frame: &[u8], input: &mut [u8]) -> Result<Event, Error> {
        self.receive_with(frame, |offset, bytes| {
            let end = offset.checked_add(bytes.len()).ok_or(Error::Overflow)?;
            if end > COMMAND_LIMIT || end > input.len() {
                return Err(Error::Overflow);
            }
            input[offset..end].copy_from_slice(bytes);
            Ok(())
        })
    }
    /// Deliver each accepted I-block exactly once. Storage/admission belongs
    /// to the receiver; Link retains sequence and retransmission policy only.
    pub fn receive_with(
        &mut self,
        frame: &[u8],
        mut receive: impl FnMut(usize, &[u8]) -> Result<(), Error>,
    ) -> Result<Event, Error> {
        match nfc::decode(frame).map_err(Error::Wire)? {
            Block::Waiting(m) => Ok(Event::Waiting(m)),
            Block::Deselect => {
                self.reset();
                Ok(Event::Deselect)
            }
            Block::Information {
                number,
                chained,
                bytes,
            } => {
                if self.pending || matches!(self.phase, Phase::Executing | Phase::Ready) {
                    return Err(Error::Busy);
                }
                if number == self.number {
                    // Repeated command blocks must never execute/write twice.
                    return if self.phase == Phase::Receiving {
                        Ok(self.acknowledge())
                    } else {
                        self.retransmit()
                    };
                }
                if matches!(self.phase, Phase::Responding | Phase::Ready) {
                    return Err(Error::Sequence);
                }
                let end = self
                    .received
                    .checked_add(bytes.len())
                    .ok_or(Error::Overflow)?;
                receive(self.received, bytes)?;
                self.received = end;
                self.number = number;
                self.cached = None;
                self.retransmits = 0;
                if chained {
                    self.phase = Phase::Receiving;
                    Ok(self.acknowledge())
                } else {
                    self.phase = Phase::Executing;
                    Ok(Event::Execute(end))
                }
            }
            Block::Receive { number, negative } => {
                if self.pending || matches!(self.phase, Phase::Executing | Phase::Ready) {
                    return Err(Error::Busy);
                }
                if number == self.number {
                    return self.retransmit();
                }
                if negative {
                    // Rule12's opposite-BN NAK requests an ACK, even while
                    // sending a response. Only a positive ACK advances it.
                    return Ok(self.acknowledge());
                }
                if self.phase == Phase::Responding {
                    self.number = number;
                    self.phase = Phase::Ready;
                    Ok(Event::NextResponse)
                } else {
                    // Rule13 ignores an unsolicited ACK without abandoning an
                    // incoming APDU, selection or an already completed response.
                    Ok(Event::Ignored)
                }
            }
        }
    }
    /// `remaining` is the current response chunk, not a second owned buffer.
    /// `more_chunks` means another engine GET RESPONSE chunk follows this one.
    /// Advance the caller's response cursor only after successful FIFO delivery.
    pub fn response(&mut self, remaining: &[u8], more_chunks: bool) -> Result<Packet, Error> {
        if self.pending || !matches!(self.phase, Phase::Executing | Phase::Ready) {
            return Err(Error::Busy);
        }
        let n = remaining.len().min(nfc::INF_LIMIT);
        let chained = remaining.len() > n || more_chunks;
        let packet =
            Packet::information(self.number, chained, &remaining[..n]).map_err(Error::Wire)?;
        self.cached = Some(packet);
        self.pending = true;
        Ok(packet)
    }
    /// Commit only the initial send, not a retransmission. On hardware failure
    /// reset the link and start recovery instead of committing a phantom packet.
    pub fn sent(&mut self) -> Result<usize, Error> {
        if !self.pending {
            return Err(Error::Sequence);
        }
        let bytes = self.cached.as_ref().ok_or(Error::Sequence)?.bytes();
        self.phase = if bytes[0] & nfc::PCB_CHAIN_OR_NAK != 0 {
            Phase::Responding
        } else {
            Phase::Complete
        };
        let n = bytes.len() - 1;
        self.pending = false;
        self.received = 0;
        self.retransmits = 0;
        Ok(n)
    }
}

pub use canokey_transport_runtime::nfc::{
    Execution, HardwareAction, Irq, RECOVERY_PERIOD, Recovery, RecoveryAction, irq,
};
