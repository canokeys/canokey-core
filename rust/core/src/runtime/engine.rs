// SPDX-License-Identifier: Apache-2.0
//! One frame decoder, logical-command lifecycle and response cursor for all routes.
use crate::ports::Platform;
use canokey_protocol::{
    apdu::{self, CommandInfo, FrameEvent, Header},
    response::{ReadError, Response, Source, StatusWord as Sw},
};

const DEFAULT_APDU_LE: u32 = 256;
const MAX_FRAME_CHUNK: usize = 256;
pub(crate) const OWNER_APDU: u8 = 0;
pub(crate) const OWNER_CCID: u8 = 1;
#[cfg(feature = "ctap")]
pub(crate) const OWNER_CTAP: u8 = 2;

#[derive(Clone, Copy)]
pub enum Reply {
    Status(Sw),
    // Maximum bytes requested by Le, not the total response length.
    Data(u32),
}

/// A bounded source whose unread bytes remain valid during consumer callbacks.
/// Volatile PKE cannot implement this contract when a callback can reuse PKE;
/// that route must first materialize its justified semantic state or use a
/// command-specific source/crypto schedule. Close ends the request lease.
pub trait InputSource {
    fn read(&mut self, output: &mut [u8]) -> Result<usize, Sw>;
    fn close(&mut self);
}

/// Static routing contract. Applets own semantic consumers and response backing;
/// this runtime owns transport/chain boundaries and the only response offset.
pub trait Router {
    fn install(&mut self, p: &mut Platform<'_>) -> Result<(), Sw>;
    fn reset(&mut self, p: &mut Platform<'_>);
    fn selected(&self) -> bool;
    fn select(&mut self, aid: &[u8], p: &mut Platform<'_>) -> Result<u32, Sw>;
    fn command_limit(&self, header: Header) -> Result<u32, Sw>;
    fn allows_extended(&self, _header: Header) -> bool {
        false
    }
    fn abort_command(&mut self, p: &mut Platform<'_>);
    fn begin_command(&mut self, _header: Header, _p: &mut Platform<'_>) -> Result<(), Sw> {
        Ok(())
    }
    fn consume(&mut self, bytes: &[u8], p: &mut Platform<'_>) -> Result<(), Sw>;
    fn end_frame(&mut self, _last: bool, _p: &mut Platform<'_>) -> Result<(), Sw> {
        Ok(())
    }
    fn finish(&mut self, header: Header, le: u32, p: &mut Platform<'_>) -> Result<(u32, Sw), Sw>;
    fn read_response(
        &mut self,
        offset: u32,
        out: &mut [u8],
        p: &mut Platform<'_>,
    ) -> Result<usize, Sw>;
    fn close_response(&mut self, p: &mut Platform<'_>);
    fn output_busy(&self) -> bool {
        false
    }
    fn sample_output(
        &mut self,
        _pressed: bool,
        _now: u32,
        _ready: bool,
        _inhibit: bool,
        _p: &mut Platform<'_>,
    ) -> Option<u8> {
        None
    }
}

struct RoutedSource<'a, 'p, R>(&'a mut R, &'a mut Platform<'p>);
impl<R: Router> Source for RoutedSource<'_, '_, R> {
    fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<usize, ReadError> {
        // ReadError carries the applet's exact status word; the response layer
        // uses it to terminate the lease without collapsing the distinction.
        self.0.read_response(offset, out, self.1).map_err(ReadError)
    }
    fn close(&mut self) {
        self.0.close_response(self.1);
    }
}

enum FrameRoute {
    None,
    Select { aid: [u8; 16], used: usize },
    GetResponse,
    Command,
}

pub struct Runtime<R> {
    // Nonzero transport identity holding the session until reset/release.
    owner: Option<u8>,
    chain: apdu::CommandChain,
    response: Response,
    frame: Option<apdu::FrameDecoder>,
    route: FrameRoute,
    router: R,
}

impl<R: Router> Runtime<R> {
    pub const fn with_router(router: R) -> Self {
        Self {
            owner: None,
            chain: apdu::CommandChain::new(),
            response: Response::new(),
            frame: None,
            route: FrameRoute::None,
            router,
        }
    }
    pub fn router(&self) -> &R {
        &self.router
    }
    /// Release all leases before returning a router to its owner.
    pub fn into_router(mut self, p: &mut Platform<'_>) -> R {
        self.reset(p);
        self.router
    }
    pub fn install(&mut self, p: &mut Platform<'_>) -> Result<(), Sw> {
        self.reset(p);
        self.router.install(p)
    }
    fn close_response(&mut self, p: &mut Platform<'_>) {
        self.response.clear(&mut RoutedSource(&mut self.router, p));
    }
    fn abort_input(&mut self, p: &mut Platform<'_>) {
        self.frame = None;
        self.route = FrameRoute::None;
        self.chain.reset();
        self.router.abort_command(p);
    }
    pub fn reset(&mut self, p: &mut Platform<'_>) {
        self.close_response(p);
        self.abort_input(p);
        self.router.reset(p);
        self.owner = None;
    }
    /// Frame length is supplied by the transport; no body buffer is allocated.
    #[cfg_attr(any(feature = "openpgp", feature = "piv"), inline(never))]
    pub fn begin_frame(&mut self, owner: u8, total: usize, p: &mut Platform<'_>) -> Result<(), Sw> {
        // Platform admission excludes HID while it owns an active USB transfer.
        // A subsequent APDU abandons the idle native session before selecting.
        #[cfg(feature = "ctap")]
        if owner == OWNER_CCID && self.owner == Some(OWNER_CTAP) {
            self.reset(p);
        }
        if owner == OWNER_APDU || self.owner.is_some_and(|current| current != owner) {
            return Err(Sw::CONDITIONS_NOT_SATISFIED);
        }
        self.owner = Some(owner);
        if self.frame.is_some() {
            self.abort_input(p);
        }
        self.route = FrameRoute::None;
        match apdu::FrameDecoder::new(total) {
            Ok(frame) => {
                self.frame = Some(frame);
                Ok(())
            }
            Err(_) => {
                self.close_response(p);
                self.abort_input(p);
                Err(Sw::WRONG_LENGTH)
            }
        }
    }
    fn extended_allowed(&self, owner: u8, header: Header) -> bool {
        owner == OWNER_CCID
            && self.owner.is_none_or(|current| current == owner)
            && !self.chain.active()
            && !self.router.output_busy()
            && self.router.allows_extended(header)
    }
    fn validate_extended(&self, owner: u8, prefix: &[u8; 7], total: usize) -> Result<u16, Sw> {
        let header = Header {
            cla: prefix[0],
            ins: prefix[1],
            p1: prefix[2],
            p2: prefix[3],
        };
        let lc = u16::from_be_bytes([prefix[5], prefix[6]]);
        if !self.extended_allowed(owner, header)
            || prefix[4] != 0
            || lc == 0
            || ![usize::from(lc) + 7, usize::from(lc) + 9].contains(&total)
            || u32::from(lc) > self.router.command_limit(header)?
        {
            return Err(Sw::WRONG_LENGTH);
        }
        Ok(lc)
    }
    /// End old response/input lifetimes BEFORE the caller borrows volatile
    /// scratch. Failed admission may clean up this owner, never a foreign one.
    pub fn prepare_extended(
        &mut self,
        owner: u8,
        prefix: &[u8; 7],
        total: usize,
        p: &mut Platform<'_>,
    ) -> Result<u16, Sw> {
        let result = self.validate_extended(owner, prefix, total);
        if result.is_ok() || self.owner == Some(owner) {
            self.close_response(p);
            self.abort_input(p);
        }
        let lc = result?;
        self.owner = Some(owner);
        Ok(lc)
    }
    #[inline(never)]
    fn start(&mut self, info: CommandInfo, p: &mut Platform<'_>) -> Result<(), Sw> {
        if info.extended && !self.extended_allowed(self.owner.unwrap_or(OWNER_APDU), info.header) {
            return Err(Sw::WRONG_LENGTH);
        }
        let h = info.header;
        if h.is_get_response() {
            self.chain.reset();
            self.router.abort_command(p);
            self.route = FrameRoute::GetResponse;
            return Ok(());
        }
        if self.router.output_busy() {
            return Err(Sw::CONDITIONS_NOT_SATISFIED);
        }
        // Any new command abandons an unread response. GET RESPONSE took
        // the earlier branch so it can continue using the existing backing.
        self.close_response(p);
        if h.is_select_by_name() {
            self.chain.reset();
            self.router.abort_command(p);
            self.route = FrameRoute::Select {
                aid: [0; 16],
                used: 0,
            };
            return Ok(());
        }
        if !self.router.selected() {
            return Err(Sw::FILE_NOT_FOUND);
        }
        let limit = self.router.command_limit(h)?;
        let step = self
            .chain
            .accept(info, limit)
            .map_err(|_| Sw::WRONG_LENGTH)?;
        if step.restarted {
            self.router.abort_command(p);
            self.router.begin_command(h, p)?;
        }
        // Header and chain bit stay in FrameDecoder until end_frame; the
        // route retains only the selected consumer, not a second header copy.
        self.route = FrameRoute::Command;
        Ok(())
    }
    #[inline(never)]
    fn data(&mut self, bytes: &[u8], p: &mut Platform<'_>) -> Result<(), Sw> {
        match &mut self.route {
            FrameRoute::Select { aid, used, .. } => {
                let end = used
                    .checked_add(bytes.len())
                    .filter(|n| *n <= aid.len())
                    .ok_or(Sw::FILE_NOT_FOUND)?;
                aid[*used..end].copy_from_slice(bytes);
                *used = end;
                Ok(())
            }
            FrameRoute::Command => self.router.consume(bytes, p),
            FrameRoute::GetResponse => Ok(()),
            FrameRoute::None => Err(Sw::WRONG_LENGTH),
        }
    }
    /// Ephemeral input may be packet-sized or a complete short APDU. Neither the
    /// frame nor the logical command is reassembled by this runtime.
    // Decoder temporaries are dead before finalization calls into crypto.
    // Keep this stack boundary on small targets instead of inlining both paths.
    #[cfg_attr(any(feature = "openpgp", feature = "piv"), inline(never))]
    pub fn feed_frame(&mut self, bytes: &[u8], p: &mut Platform<'_>) -> Result<(), Sw> {
        let mut frame = self.frame.take().ok_or(Sw::WRONG_LENGTH)?;
        let mut status = Sw::WRONG_LENGTH;
        let result = frame.feed_events(bytes, &mut |event| {
            let result = match event {
                FrameEvent::Start(info) => self.start(info, p),
                FrameEvent::Data(bytes) => self.data(bytes, p),
            };
            result.map_err(|sw| {
                status = sw;
                apdu::Error::Consumer
            })
        });
        if result.is_err() {
            self.close_response(p);
            self.abort_input(p);
            return Err(status);
        }
        self.frame = Some(frame);
        Ok(())
    }
    pub fn end_frame(&mut self, p: &mut Platform<'_>) -> Reply {
        let info = match self.frame.as_ref().and_then(|frame| frame.finish().ok()) {
            Some(info) => info,
            None => {
                self.close_response(p);
                self.abort_input(p);
                return Reply::Status(Sw::WRONG_LENGTH);
            }
        };
        self.frame = None;
        // This short-APDU profile treats omitted Le as a 256-byte response
        // allowance; the decoder has already normalized encoded Le=00 to 256.
        let le = info.le.unwrap_or(DEFAULT_APDU_LE);
        let route = core::mem::replace(&mut self.route, FrameRoute::None);
        let result = match route {
            FrameRoute::GetResponse => {
                return if self.response.active() {
                    Reply::Data(le)
                } else {
                    Reply::Status(Sw::COMMAND_NOT_ALLOWED)
                };
            }
            FrameRoute::Select { aid, used } => {
                if info.header.p2 != 0x00 {
                    Err(Sw::WRONG_P1P2)
                } else {
                    self.router
                        .select(&aid[..used], p)
                        .map(|n| (n, Sw::SUCCESS))
                }
            }
            FrameRoute::Command => {
                let last = !info.header.chained();
                if let Err(sw) = self.router.end_frame(last, p) {
                    self.abort_input(p);
                    return Reply::Status(sw);
                }
                if !last {
                    return Reply::Status(Sw::SUCCESS);
                }
                self.router.finish(info.header.unchained(), le, p)
            }
            FrameRoute::None => Err(Sw::WRONG_LENGTH),
        };
        match result {
            Ok((0, sw)) => {
                self.router.close_response(p);
                Reply::Status(sw)
            }
            Ok((total, sw)) => {
                // A command cannot replace an undrained response lease. Close
                // the previous source before publishing the new cursor.
                if self.response.active() {
                    self.close_response(p);
                }
                if self.response.start(total, sw) {
                    Reply::Data(le)
                } else {
                    // Keep the source lease fail-closed even if a future
                    // caller violates the close-before-start contract.
                    self.close_response(p);
                    Reply::Status(Sw::UNABLE_TO_PROCESS)
                }
            }
            Err(sw) => {
                self.abort_input(p);
                self.router.close_response(p);
                Reply::Status(sw)
            }
        }
    }
    pub fn receive(&mut self, owner: u8, frame: &[u8], p: &mut Platform<'_>) -> Reply {
        if let Err(sw) = self
            .begin_frame(owner, frame.len(), p)
            .and_then(|()| self.feed_frame(frame, p))
        {
            return Reply::Status(sw);
        }
        self.end_frame(p)
    }
    /// Pull-backed frames use exactly the same decoder/consumer as push input.
    /// Close before final domain execution (which may wait or reuse hardware).
    pub fn receive_source(
        &mut self,
        owner: u8,
        total: usize,
        source: &mut (impl InputSource + ?Sized),
        p: &mut Platform<'_>,
    ) -> Reply {
        let result = (|| {
            self.begin_frame(owner, total, p)?;
            let mut window = [0; 64];
            let mut remaining = total;
            while remaining != 0 {
                let capacity = remaining.min(window.len());
                let read = match source.read(&mut window[..capacity]) {
                    Ok(n) if n > 0 && n <= capacity => n,
                    Err(sw) => {
                        p.memory.wipe(&mut window);
                        return Err(sw);
                    }
                    _ => {
                        p.memory.wipe(&mut window);
                        return Err(Sw::WRONG_LENGTH);
                    }
                };
                let result = self.feed_frame(&window[..read], p);
                p.memory.wipe(&mut window);
                result?;
                remaining -= read;
            }
            Ok(())
        })();
        source.close();
        match result {
            Ok(()) => self.end_frame(p),
            Err(sw) => {
                // A rejected foreign owner must not abort the current owner's work.
                if self.owner == Some(owner) {
                    self.close_response(p);
                    self.abort_input(p);
                }
                Reply::Status(sw)
            }
        }
    }
    /// RX borrows must end before this call. Endpoint bytes remain transport-owned
    /// until transfer completion, independent of source close after its final read.
    pub fn transmit(
        &mut self,
        reply: Reply,
        output: &mut [u8],
        p: &mut Platform<'_>,
    ) -> Result<usize, Sw> {
        if output.len() < 2 {
            return Err(Sw::WRONG_LENGTH);
        }
        let (len, sw) = match reply {
            Reply::Status(sw) => (0, sw),
            Reply::Data(le) => {
                let capacity = (output.len() - 2).min(MAX_FRAME_CHUNK);
                match self.response.next(
                    &mut RoutedSource(&mut self.router, p),
                    &mut output[..capacity],
                    le,
                ) {
                    Ok(chunk) => (chunk.len, chunk.sw),
                    Err(sw) => (0, sw),
                }
            }
        };
        output[len..len + 2].copy_from_slice(&sw.bytes());
        Ok(len + 2)
    }
    pub fn sample_output(
        &mut self,
        pressed: bool,
        now: u32,
        ready: bool,
        p: &mut Platform<'_>,
    ) -> Option<u8> {
        self.router.sample_output(
            pressed,
            now,
            ready,
            self.frame.is_some() || self.chain.active() || self.response.active(),
            p,
        )
    }
}

pub type Core = Runtime<super::registry::Registry>;
impl Core {
    pub const fn new() -> Self {
        Self::with_router(super::registry::Registry::new())
    }
    #[cfg(feature = "ctap")]
    pub fn begin_ctap(&mut self, p: &mut Platform<'_>) {
        // Native HID holds owner 2 across commands; preserve its PIN agreement
        // and authorization state. Preempting an idle APDU owner resets it.
        if self.owner != Some(OWNER_CTAP) {
            self.reset(p);
            self.owner = Some(OWNER_CTAP);
        }
        self.router.close_ctap(p);
    }
    #[cfg(feature = "ctap")]
    pub fn begin_hid_request(&mut self, message_length: Option<usize>, p: &mut Platform<'_>) {
        self.router.begin_hid_request(message_length, p);
    }
    #[cfg(feature = "ctap")]
    pub fn consume_hid_request(&mut self, bytes: &[u8]) {
        self.router.consume_hid_request(bytes);
    }
    #[cfg(feature = "ctap")]
    pub fn finish_hid_request(&mut self, p: &mut Platform<'_>) -> usize {
        self.router.finish_hid_request(p)
    }
    #[cfg(feature = "ctap")]
    pub fn execute_ctap(
        &mut self,
        command: Result<crate::applets::ctap::Command, crate::applets::ctap::Status>,
        p: &mut Platform<'_>,
    ) -> usize {
        self.router.execute_ctap(command, p)
    }
    #[cfg(feature = "ctap")]
    pub fn execute_ctap_message(
        &mut self,
        command: crate::applets::ctap::apdu::Message,
        p: &mut Platform<'_>,
    ) -> usize {
        self.router.execute_ctap_message(command, p)
    }
    #[cfg(feature = "ctap")]
    pub fn read_ctap(
        &mut self,
        offset: usize,
        out: &mut [u8],
        p: &mut Platform<'_>,
    ) -> Result<(), Sw> {
        self.router.read_ctap(offset, out, p)
    }
    #[cfg(feature = "ctap")]
    pub fn close_ctap(&mut self, p: &mut Platform<'_>) {
        self.router.close_ctap(p);
    }
    pub const fn applet_count() -> u8 {
        cfg!(feature = "admin") as u8
            + cfg!(feature = "oath") as u8
            + cfg!(feature = "openpgp") as u8
            + cfg!(feature = "piv") as u8
            + cfg!(feature = "ctap") as u8
    }
    #[cfg(feature = "pass")]
    pub fn touch(&self, index: u8, out: &mut [u8], p: &mut Platform<'_>) -> Result<usize, Sw> {
        self.router.touch(index, out, p)
    }
    #[cfg(feature = "pass")]
    pub fn challenge(
        &self,
        index: u8,
        input: &[u8],
        out: &mut [u8; 20],
        p: &mut Platform<'_>,
    ) -> Result<(), Sw> {
        self.router.challenge(index, input, out, p)
    }
}
impl Default for Core {
    fn default() -> Self {
        Self::new()
    }
}
