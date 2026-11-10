// SPDX-License-Identifier: Apache-2.0
//! Shared APDU routing; products lend consumers and public SELECT backing.
use super::{ResponseRoute, Selection};
use canokey_protocol::{
    apdu::{CLA_FIDO, CommandInfo, FIDO_CBOR_INS, Header},
    response::StatusWord,
};

/// Call-scoped capabilities. No callback or request/response loan is retained.
pub trait Backend {
    type Aid: Default;
    fn nfc(&self) -> bool;
    fn selected(&self) -> bool;
    fn fido_selected(&mut self) -> bool;
    fn extended_allowed(&self, header: Header) -> bool;
    fn chain_active(&self) -> bool;
    fn restart_message(&mut self);
    fn abort_input(&mut self);
    fn special(&mut self, _header: Header) -> bool {
        false
    }
    fn response_route(
        &mut self,
        header: Header,
        special: bool,
    ) -> Result<ResponseRoute, StatusWord>;
    fn begin_command(&mut self, info: CommandInfo) -> Result<(), StatusWord>;
    fn select_data(&mut self, aid: &mut Self::Aid, selection: &mut Selection, bytes: &[u8]);
    fn consume(&mut self, bytes: &[u8]) -> Result<(), StatusWord>;
}

/// Complete-envelope capabilities. Prepared commands may be deferred to the
/// owner's later execution phase; finalization never retains an input lease.
pub trait Finalize<A> {
    type Prepared;
    type Reply;
    fn continuation(&mut self, info: CommandInfo) -> Self::Reply;
    fn absent_le(&self, info: CommandInfo) -> u32;
    fn select(
        &mut self,
        aid: &A,
        selection: &Selection,
        info: CommandInfo,
        le: u32,
    ) -> Result<Self::Prepared, StatusWord>;
    fn reject_select(&mut self);
    fn retain_failed_select(&mut self) -> bool;
    fn reset_chain(&mut self);
    fn end_frame(&mut self, info: CommandInfo) -> Result<bool, StatusWord>;
    fn command(&mut self, info: CommandInfo, le: u32) -> Result<Self::Prepared, StatusWord>;
    fn special(&mut self, info: CommandInfo, le: u32) -> Result<Self::Prepared, StatusWord>;
    fn abort_input(&mut self);
    fn close_response(&mut self);
    fn publish(&mut self, prepared: Self::Prepared, le: u32) -> Self::Reply;
    fn status(&mut self, status: StatusWord) -> Self::Reply;
}

/// The owner chooses inline SELECT backing or lends a separate closed output
/// allocation. Route metadata never allocates another logical request buffer.
pub enum Route<A> {
    None,
    Select { aid: A, selection: Selection },
    GetResponse,
    Special,
    Command,
}
impl<A: Default> Route<A> {
    #[inline]
    pub fn begin(
        info: CommandInfo,
        backend: &mut impl Backend<Aid = A>,
    ) -> Result<Self, StatusWord> {
        let header = info.header;
        if info.extended
            && backend.nfc()
            && header.unchained().cla == CLA_FIDO
            && header.ins == FIDO_CBOR_INS
        {
            // NFC extended MSG starts a new logical input, even with CLA 0x90.
            backend.restart_message();
        }
        if info.extended
            && !header.is_select_by_name()
            && !header.is_get_response()
            && !backend.selected()
        {
            return Err(StatusWord::FILE_NOT_FOUND);
        }
        if info.extended && !backend.extended_allowed(header) {
            return Err(StatusWord::WRONG_LENGTH);
        }
        let special = !header.is_get_response() && backend.special(header);
        if backend.response_route(header, special)? == ResponseRoute::Continuation {
            return Ok(Self::GetResponse);
        }
        if special {
            backend.abort_input();
            return Ok(Self::Special);
        }
        if header.is_select_by_name() {
            if !(backend.nfc() && backend.chain_active() && backend.fido_selected()) {
                backend.abort_input();
            }
            return Ok(Self::Select {
                aid: A::default(),
                selection: Selection::new(),
            });
        }
        if !backend.selected() {
            return Err(StatusWord::FILE_NOT_FOUND);
        }
        backend.begin_command(info)?;
        Ok(Self::Command)
    }
    #[inline]
    pub fn data(
        &mut self,
        bytes: &[u8],
        backend: &mut impl Backend<Aid = A>,
    ) -> Result<(), StatusWord> {
        match self {
            Self::Select { aid, selection } => {
                backend.select_data(aid, selection, bytes);
                Ok(())
            }
            Self::Command => backend.consume(bytes),
            Self::GetResponse | Self::Special => Ok(()),
            Self::None => Err(StatusWord::WRONG_LENGTH),
        }
    }
    /// Call only after the complete envelope and any input-source close have
    /// succeeded. Error cleanup order and intentional input retention are common
    /// to synchronous execution and a product's deferred command publication.
    #[inline]
    pub fn finish<B: Finalize<A>>(self, info: CommandInfo, backend: &mut B) -> B::Reply {
        if matches!(self, Self::GetResponse) {
            return backend.continuation(info);
        }
        let le = info.le.unwrap_or_else(|| backend.absent_le(info));
        let result = match self {
            Self::GetResponse => unreachable!(),
            Self::Select { aid, selection } => {
                let selected = backend.select(&aid, &selection, info, le);
                if let Err(status) = selected {
                    backend.reject_select();
                    if backend.retain_failed_select() {
                        return backend.status(status);
                    }
                } else {
                    backend.reset_chain();
                }
                selected
            }
            Self::Command => {
                let last = match backend.end_frame(info) {
                    Ok(last) => last,
                    Err(status) => {
                        backend.abort_input();
                        return backend.status(status);
                    }
                };
                if !last {
                    return backend.status(StatusWord::SUCCESS);
                }
                backend.command(info, le)
            }
            Self::Special => backend.special(info, le),
            Self::None => Err(StatusWord::WRONG_LENGTH),
        };
        match result {
            Ok(prepared) => backend.publish(prepared, le),
            Err(status) => {
                backend.abort_input();
                backend.close_response();
                backend.status(status)
            }
        }
    }
}
