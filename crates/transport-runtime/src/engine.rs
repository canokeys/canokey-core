// SPDX-License-Identifier: Apache-2.0
//! Frame/chain/response lifecycle over static product dispatch capabilities.
use canokey_protocol::{
    apdu::{self, CommandInfo, FrameEvent, Header},
    response::{ReadError, Response, Source, StatusWord as Sw},
};
use core::marker::PhantomData;
pub const DEFAULT_APDU_LE: u32 = 256;
const MAX_FRAME_CHUNK: usize = 256;
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
    /// End the lease even after failure. A cancellation observed during cleanup
    /// must fail here so a fully parsed request cannot enter applet execution.
    fn close(&mut self) -> Result<(), Sw>;
}

/// Pure product routing decisions, independent of a backend/context type.
pub trait Router {
    fn native_pending(&self) -> bool {
        false
    }
    fn selected(&self) -> bool;
    /// NFC rejects envelopes before applet dispatch. Independent applet input
    /// cursors may survive that rejection; FIDO's transport chain does not.
    fn retain_nfc_input(&self) -> bool {
        false
    }
    /// Resolve omitted Le once for both applet validation and response allowance.
    fn absent_le(&self, _info: apdu::CommandInfo) -> u32 {
        DEFAULT_APDU_LE
    }
    fn command_limit(&self, header: Header) -> Result<u32, Sw>;
    fn chain_header(&self, header: Header) -> Header {
        header
    }
    fn allows_extended(&self, _header: Header) -> bool {
        false
    }
    /// Applet state retained between completed commands may own shared scratch.
    fn can_yield(&self) -> bool {
        true
    }
    fn output_busy(&self) -> bool {
        false
    }
}
/// Synchronous borrowed application capability. Context may contain product IO;
/// the engine cannot access it except through these statically dispatched calls.
pub trait Dispatch<C>: Router {
    fn yield_native(&mut self, _p: &mut C) {}
    fn install(&mut self, p: &mut C) -> Result<(), Sw>;
    fn reset(&mut self, p: &mut C);
    fn select(&mut self, aid: &[u8], transport: apdu::Transport, p: &mut C) -> Result<u32, Sw>;
    /// Rejected USB SELECT must revoke a previously selected FIDO context.
    fn reject_select(&mut self, _transport: apdu::Transport, _p: &mut C) {}
    fn fido_selected(&self, _p: &mut C) -> bool {
        false
    }
    fn abort_command(&mut self, p: &mut C);
    fn begin_command(&mut self, _header: Header, _p: &mut C) -> Result<(), Sw> {
        Ok(())
    }
    fn consume(&mut self, bytes: &[u8], p: &mut C) -> Result<(), Sw>;
    fn end_frame(&mut self, _last: bool, _p: &mut C) -> Result<(), Sw> {
        Ok(())
    }
    fn finish(&mut self, header: Header, le: u32, p: &mut C) -> Result<(u32, Sw), Sw>;
    fn read_response(&mut self, offset: u32, out: &mut [u8], p: &mut C) -> Result<usize, Sw>;
    fn close_response(&mut self, p: &mut C);
    fn is_eject(&self, _header: Header, _p: &mut C) -> bool {
        false
    }
    fn eject(&mut self, _p: &mut C) -> Result<(), Sw> {
        Err(Sw::INS_NOT_SUPPORTED)
    }
    fn sample_output(
        &mut self,
        _pressed: bool,
        _now: u32,
        _ready: bool,
        _inhibit: bool,
        _p: &mut C,
    ) -> Option<u8> {
        None
    }
    fn installed(&mut self, _context: &mut C) {}
    fn wipe(&mut self, bytes: &mut [u8], _context: &mut C) {
        bytes.fill(0x00);
    }
}
/// Local session identity policy, independent of wire APDU transport values.
pub trait OwnerPolicy {
    const INVALID: u8;
    const NFC: u8;
    const EXTENDED_USB: u8;
}
/// Optional product handoff metadata; () allocates no state or behavior.
pub trait Handoff {
    const INITIAL: Self;
    fn recover<C, R: Dispatch<C>>(
        &mut self,
        owner: &mut Option<u8>,
        router: &mut R,
        context: &mut C,
    );
}
impl Handoff for () {
    const INITIAL: Self = ();
    fn recover<C, R: Dispatch<C>>(&mut self, _: &mut Option<u8>, _: &mut R, _: &mut C) {}
}

struct RoutedSource<'a, R, C>(&'a mut R, &'a mut C);
impl<R: Dispatch<C>, C> Source for RoutedSource<'_, R, C> {
    fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<usize, ReadError> {
        // ReadError carries the applet's exact status word; the response layer
        // uses it to terminate the lease without collapsing the distinction.
        self.0.read_response(offset, out, self.1).map_err(ReadError)
    }
    fn close(&mut self) {
        self.0.close_response(self.1);
    }
}

type FrameRoute = crate::frame::route::Route<[u8; crate::frame::Selection::AID_BYTES]>;

struct Routing<'a, R, C, P> {
    owner: Option<u8>,
    chain: &'a mut apdu::CommandChain,
    response: &'a mut Response,
    router: &'a mut R,
    context: &'a mut C,
    policy: PhantomData<P>,
}
impl<R: Dispatch<C>, C, P: OwnerPolicy> crate::frame::route::Backend for Routing<'_, R, C, P> {
    type Aid = [u8; crate::frame::Selection::AID_BYTES];
    fn nfc(&self) -> bool {
        self.owner == Some(P::NFC)
    }
    fn selected(&self) -> bool {
        self.router.selected()
    }
    fn fido_selected(&mut self) -> bool {
        self.router.fido_selected(self.context)
    }
    fn extended_allowed(&self, header: Header) -> bool {
        let owner = self.owner.unwrap_or(P::INVALID);
        (owner == P::EXTENDED_USB || owner == P::NFC)
            && self.owner.is_none_or(|current| current == owner)
            && !self.router.output_busy()
            && (header.is_select_by_name() || self.router.allows_extended(header))
    }
    fn chain_active(&self) -> bool {
        self.chain.active()
    }
    fn restart_message(&mut self) {
        self.abort_input();
    }
    // This small adapter must not retain a separate routing-view call frame.
    #[inline(always)]
    fn abort_input(&mut self) {
        self.chain.reset();
        self.router.abort_command(self.context);
    }
    fn special(&mut self, header: Header) -> bool {
        self.router.is_eject(header, self.context)
    }
    fn response_route(
        &mut self,
        header: Header,
        special: bool,
    ) -> Result<crate::frame::ResponseRoute, Sw> {
        crate::frame::ResponseRoute::begin(
            header,
            !special && self.router.output_busy(),
            self.response,
            &mut RoutedSource(self.router, self.context),
        )
    }
    fn begin_command(&mut self, info: CommandInfo) -> Result<(), Sw> {
        let header = info.header;
        let limit = self.router.command_limit(header)?;
        let mut chain_info = info;
        chain_info.header = self.router.chain_header(header);
        let step = self
            .chain
            .accept(chain_info, limit)
            .map_err(|_| Sw::WRONG_LENGTH)?;
        if step.restarted {
            self.router.abort_command(self.context);
            self.router.begin_command(header, self.context)?;
        }
        Ok(())
    }
    fn select_data(
        &mut self,
        aid: &mut Self::Aid,
        selection: &mut crate::frame::Selection,
        bytes: &[u8],
    ) {
        selection.consume(bytes, aid);
    }
    fn consume(&mut self, bytes: &[u8]) -> Result<(), Sw> {
        self.router.consume(bytes, self.context)
    }
}

/// Borrowed finalization capabilities preserve product execution and lease ownership.
struct Completing<'a, R, P: OwnerPolicy, H: Handoff, C> {
    runtime: &'a mut Runtime<R, P, H>,
    context: &'a mut C,
}
impl<R: Dispatch<C>, P: OwnerPolicy, H: Handoff, C>
    crate::frame::route::Finalize<[u8; crate::frame::Selection::AID_BYTES]>
    for Completing<'_, R, P, H, C>
{
    type Prepared = (u32, Sw);
    type Reply = Reply;
    fn continuation(&mut self, info: CommandInfo) -> Reply {
        match crate::frame::ResponseRoute::continuation(info, &self.runtime.response) {
            Ok(le) => Reply::Data(le),
            Err(sw) => Reply::Status(sw),
        }
    }
    fn absent_le(&self, info: CommandInfo) -> u32 {
        self.runtime.router.absent_le(info)
    }
    fn select(
        &mut self,
        aid: &[u8; crate::frame::Selection::AID_BYTES],
        selection: &crate::frame::Selection,
        info: CommandInfo,
        _: u32,
    ) -> Result<Self::Prepared, Sw> {
        let transport = self.runtime.transport();
        selection
            .finish(info.header.p2, aid)
            .and_then(|aid| self.runtime.router.select(aid, transport, self.context))
            .map(|total| (total, Sw::SUCCESS))
    }
    fn reject_select(&mut self) {
        let transport = self.runtime.transport();
        self.runtime.router.reject_select(transport, self.context);
    }
    fn retain_failed_select(&mut self) -> bool {
        self.runtime.owner == Some(P::NFC)
            && self.runtime.chain.active()
            && self.runtime.router.fido_selected(self.context)
    }
    fn reset_chain(&mut self) {
        self.runtime.chain.reset();
    }
    fn end_frame(&mut self, info: CommandInfo) -> Result<bool, Sw> {
        let last = !self.runtime.router.chain_header(info.header).chained();
        self.runtime.router.end_frame(last, self.context)?;
        Ok(last)
    }
    fn command(&mut self, info: CommandInfo, le: u32) -> Result<Self::Prepared, Sw> {
        self.runtime
            .router
            .finish(info.header.unchained(), le, self.context)
    }
    fn special(&mut self, _: CommandInfo, _: u32) -> Result<Self::Prepared, Sw> {
        self.runtime
            .router
            .eject(self.context)
            .map(|()| (0, Sw::SUCCESS))
    }
    fn abort_input(&mut self) {
        self.runtime.abort_input(self.context);
    }
    fn close_response(&mut self) {
        self.runtime.router.close_response(self.context);
    }
    fn publish(&mut self, (total, status): Self::Prepared, le: u32) -> Reply {
        if total == 0 {
            self.runtime.router.close_response(self.context);
            return Reply::Status(status);
        }
        // Close an undrained source before publishing its replacement cursor.
        if self.runtime.response.active() {
            self.runtime.close_response(self.context);
        }
        if self.runtime.response.start(total, status) {
            Reply::Data(le)
        } else {
            self.runtime.close_response(self.context);
            Reply::Status(Sw::UNABLE_TO_PROCESS)
        }
    }
    fn status(&mut self, status: Sw) -> Reply {
        Reply::Status(status)
    }
}

/// NFC preparation borrows the same owner and command state as frame routing.
struct NfcAdmission<'a, R, P: OwnerPolicy, H: Handoff, C> {
    runtime: &'a mut Runtime<R, P, H>,
    context: &'a mut C,
}
impl<R: Dispatch<C>, P: OwnerPolicy, H: Handoff, C> crate::nfc::request::Admission
    for NfcAdmission<'_, R, P, H, C>
{
    fn begin(&mut self, header: Header) -> Result<(), Sw> {
        if self.runtime.owner.is_some_and(|owner| owner != P::NFC) {
            return Err(Sw::CONDITIONS_NOT_SATISFIED);
        }
        if !header.is_get_response() {
            self.runtime.close_response(self.context);
        }
        self.runtime.owner = Some(P::NFC);
        Ok(())
    }
    fn fido_selected(&mut self) -> bool {
        self.runtime.router.fido_selected(self.context)
    }
    fn replace_input(&mut self) -> Result<(), Sw> {
        self.runtime.abort_input(self.context);
        Ok(())
    }
    fn request_limit(&mut self, header: Header) -> Result<u32, Sw> {
        self.runtime.router.command_limit(header)
    }
}

// Keep transport cursors before the large router on Thumb-1. This is an
// internal layout choice, not a serialized or public C ABI.
#[repr(C)]
pub struct Runtime<R, P: OwnerPolicy, H: Handoff = ()> {
    // Nonzero transport identity holding the session until reset/release.
    owner: Option<u8>,
    handoff: H,
    chain: apdu::CommandChain,
    response: Response,
    frame: Option<apdu::FrameDecoder>,
    route: FrameRoute,
    router: R,
    policy: PhantomData<P>,
}

impl<R: Router, P: OwnerPolicy, H: Handoff> Runtime<R, P, H> {
    pub const fn with_router(router: R) -> Self {
        Self {
            owner: None,
            handoff: H::INITIAL,
            chain: apdu::CommandChain::new(),
            response: Response::new(),
            frame: None,
            route: FrameRoute::None,
            router,
            policy: PhantomData,
        }
    }
    /// Main-loop admission only, after transport TX ownership has ended.
    /// Input chains and ordinary unread replies retain their bounded lease.
    pub fn can_preempt(&self) -> bool {
        self.frame.is_none()
            && !self.chain.active()
            && !self.response.active()
            && !self.router.output_busy()
            && !self.router.native_pending()
            && self.router.can_yield()
    }
    pub fn router(&self) -> &R {
        &self.router
    }
    pub fn router_mut(&mut self) -> &mut R {
        &mut self.router
    }
    pub fn owner(&self) -> Option<u8> {
        self.owner
    }
    pub fn replace_owner(&mut self, owner: Option<u8>) -> Option<u8> {
        core::mem::replace(&mut self.owner, owner)
    }
    pub fn handoff_mut(&mut self) -> &mut H {
        &mut self.handoff
    }
    /// Release all leases before returning a router to its owner.
    pub fn into_router<C>(mut self, p: &mut C) -> R
    where
        R: Dispatch<C>,
    {
        self.reset(p);
        self.router
    }
    pub fn install<C>(&mut self, p: &mut C) -> Result<(), Sw>
    where
        R: Dispatch<C>,
    {
        self.reset(p);
        self.router.install(p)?;
        self.router.installed(p);
        Ok(())
    }
    fn close_response<C>(&mut self, p: &mut C)
    where
        R: Dispatch<C>,
    {
        self.response.clear(&mut RoutedSource(&mut self.router, p));
    }
    #[inline(never)]
    fn abort_input<C>(&mut self, p: &mut C)
    where
        R: Dispatch<C>,
    {
        self.frame = None;
        self.route = FrameRoute::None;
        self.chain.reset();
        self.router.abort_command(p);
    }
    // Cursor-dependent response close must precede input cancellation here.
    // Other paths deliberately use abort followed by unconditional source close.
    #[inline(never)]
    fn close_and_abort<C>(&mut self, p: &mut C)
    where
        R: Dispatch<C>,
    {
        self.close_response(p);
        self.abort_input(p);
    }
    // Share the generic cleanup path across transport reset and CTAP preemption.
    #[inline(never)]
    pub fn reset<C>(&mut self, p: &mut C)
    where
        R: Dispatch<C>,
    {
        self.close_and_abort(p);
        self.router.reset(p);
        self.owner = None;
        self.handoff = H::INITIAL;
    }
    pub fn slot_power<C>(&mut self, p: &mut C)
    where
        R: Dispatch<C>,
    {
        self.reset(p);
    }
    /// Frame length is supplied by the transport; no body buffer is allocated.
    #[inline(never)]
    pub fn begin_frame<C>(&mut self, owner: u8, total: usize, p: &mut C) -> Result<(), Sw>
    where
        R: Dispatch<C>,
    {
        // Native HID execution yields the shared workspace, retaining the
        // APDU selection and authorization held before it borrowed the Core.
        self.handoff.recover(&mut self.owner, &mut self.router, p);
        if owner == P::INVALID || self.owner.is_some_and(|current| current != owner) {
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
                self.close_and_abort(p);
                Err(Sw::WRONG_LENGTH)
            }
        }
    }
    /// Reject an envelope without dispatching it. NFC clears FIDO input and
    /// output, but leaves other applets' command cursors untouched.
    pub fn abort_request<C>(&mut self, owner: u8, p: &mut C)
    where
        R: Dispatch<C>,
    {
        if self.owner.is_none_or(|current| current == owner) {
            if owner == P::NFC && self.router.retain_nfc_input() {
                self.close_response(p);
            } else {
                self.close_and_abort(p);
            }
            self.owner = Some(owner);
        }
    }
    /// Authoritative applet/configuration state for transport response policy.
    pub fn fido_selected<C>(&self, p: &mut C) -> bool
    where
        R: Dispatch<C>,
    {
        self.router.fido_selected(p)
    }
    /// NFC does not know Case3E/4E's total until the final I-block. Validate the
    /// large-body prefix before staging, returning the logical request budget.
    pub fn prepare_nfc<C>(
        &mut self,
        prefix: &[u8; apdu::EXTENDED_HEADER_BYTES],
        p: &mut C,
    ) -> Result<u32, Sw>
    where
        R: Dispatch<C>,
    {
        crate::nfc::request::prepare(
            prefix,
            &mut NfcAdmission {
                runtime: self,
                context: p,
            },
        )
    }

    fn transport(&self) -> apdu::Transport {
        if self.owner == Some(P::NFC) {
            apdu::Transport::Nfc
        } else {
            apdu::Transport::Usb
        }
    }
    #[inline(never)]
    fn start<C>(&mut self, info: CommandInfo, p: &mut C) -> Result<(), Sw>
    where
        R: Dispatch<C>,
    {
        self.route = FrameRoute::begin(
            info,
            &mut Routing::<R, C, P> {
                owner: self.owner,
                chain: &mut self.chain,
                response: &mut self.response,
                router: &mut self.router,
                context: p,
                policy: PhantomData,
            },
        )?;
        Ok(())
    }
    #[inline(never)]
    fn data<C>(&mut self, bytes: &[u8], p: &mut C) -> Result<(), Sw>
    where
        R: Dispatch<C>,
    {
        self.route.data(
            bytes,
            &mut Routing::<R, C, P> {
                owner: self.owner,
                chain: &mut self.chain,
                response: &mut self.response,
                router: &mut self.router,
                context: p,
                policy: PhantomData,
            },
        )
    }
    /// Ephemeral input may be packet-sized or a complete short APDU. Neither the
    /// frame nor the logical command is reassembled by this runtime.
    // Decoder temporaries are dead before finalization calls into crypto.
    // Keep this stack boundary on small targets instead of inlining both paths.
    #[inline(never)]
    pub fn feed_frame<C>(&mut self, bytes: &[u8], p: &mut C) -> Result<(), Sw>
    where
        R: Dispatch<C>,
    {
        let mut frame = self.frame.take().ok_or(Sw::WRONG_LENGTH)?;
        let result =
            crate::frame::feed(
                &mut frame,
                bytes,
                Sw::WRONG_LENGTH,
                &mut |event| match event {
                    FrameEvent::Start(info) => self.start(info, p),
                    FrameEvent::Data(bytes) => self.data(bytes, p),
                },
            );
        if let Err(status) = result {
            self.close_and_abort(p);
            return Err(status);
        }
        self.frame = Some(frame);
        Ok(())
    }
    pub fn end_frame<C>(&mut self, p: &mut C) -> Reply
    where
        R: Dispatch<C>,
    {
        let info = match self.frame.as_ref().and_then(|frame| frame.finish().ok()) {
            Some(info) => info,
            None => {
                self.close_and_abort(p);
                return Reply::Status(Sw::WRONG_LENGTH);
            }
        };
        self.frame = None;
        let route = core::mem::replace(&mut self.route, FrameRoute::None);
        route.finish(
            info,
            &mut Completing {
                runtime: self,
                context: p,
            },
        )
    }

    pub fn receive<C>(&mut self, owner: u8, frame: &[u8], p: &mut C) -> Reply
    where
        R: Dispatch<C>,
    {
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
    pub fn receive_source<C>(
        &mut self,
        owner: u8,
        total: usize,
        source: &mut (impl InputSource + ?Sized),
        p: &mut C,
    ) -> Reply
    where
        R: Dispatch<C>,
    {
        self.receive_source_with_info(owner, total, source, p).0
    }
    /// Return decoded envelope metadata from the same parser used for routing.
    /// NFC uses it for this command's Le budget, without another SELECT parser.
    pub fn receive_source_with_info<C>(
        &mut self,
        owner: u8,
        total: usize,
        source: &mut (impl InputSource + ?Sized),
        p: &mut C,
    ) -> (Reply, Option<CommandInfo>)
    where
        R: Dispatch<C>,
    {
        let result = (|| {
            self.begin_frame(owner, total, p)?;
            // Bounded streaming chunk; independent of APDU length and applet buffers.
            let mut window = [0; 64];
            let mut remaining = total;
            while remaining != 0 {
                let capacity = remaining.min(window.len());
                let read = match source.read(&mut window[..capacity]) {
                    Ok(n) if n > 0 && n <= capacity => n,
                    Err(sw) => {
                        self.router.wipe(&mut window, p);
                        return Err(sw);
                    }
                    _ => {
                        self.router.wipe(&mut window, p);
                        return Err(Sw::WRONG_LENGTH);
                    }
                };
                let result = self.feed_frame(&window[..read], p);
                self.router.wipe(&mut window, p);
                result?;
                remaining -= read;
            }
            Ok(())
        })();
        let info = self.frame.as_ref().and_then(|frame| frame.finish().ok());
        let result = source.close().and(result);
        let reply = match result {
            Ok(()) => self.end_frame(p),
            Err(sw) => {
                // A rejected foreign owner must not abort the current owner's work.
                if self.owner == Some(owner) {
                    self.close_and_abort(p);
                }
                Reply::Status(sw)
            }
        };
        (reply, info)
    }
    /// RX borrows must end before this call. Endpoint bytes remain transport-owned
    /// until transfer completion, independent of source close after its final read.
    pub fn transmit<C>(&mut self, reply: Reply, output: &mut [u8], p: &mut C) -> Result<usize, Sw>
    where
        R: Dispatch<C>,
    {
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
    /// Discard queued output and consume the current contact after USB reset.
    pub fn cancel_output<C>(&mut self, pressed: bool, p: &mut C)
    where
        R: Dispatch<C>,
    {
        self.router.sample_output(pressed, 0, false, true, p);
    }
    pub fn sample_output<C>(
        &mut self,
        pressed: bool,
        now: u32,
        ready: bool,
        p: &mut C,
    ) -> Option<u8>
    where
        R: Dispatch<C>,
    {
        self.router.sample_output(
            pressed,
            now,
            ready,
            self.frame.is_some() || self.chain.active() || self.response.active(),
            p,
        )
    }
}
