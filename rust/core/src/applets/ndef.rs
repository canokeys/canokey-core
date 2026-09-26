// SPDX-License-Identifier: Apache-2.0
//! Type-4 NDEF file policy. Payloads are read/written through bounded caller
//! slices, never buffered as a second maximum-size NDEF object.
#![forbid(unsafe_code)]
use canokey_protocol::response::StatusWord as Sw;
pub const AID: &[u8] = &[0xd2, 0x76, 0, 0, 0x85, 1, 1];
pub const FILE_LIMIT: usize = 1024;
pub const DEFAULT_CC: [u8; 15] = [0, 15, 0x20, 4, 0, 4, 0, 4, 6, 0, 1, 4, 0, 0, 0];
const INITIAL: &[u8] = b"\x00\x11\xd1\x01\x0d\x55\x04canokeys.org";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum File {
    Capability,
    Message,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Missing,
    Io,
}
/// The platform adapter exposes only byte-file operations. Offset arithmetic,
/// initialization, permissions and cache invalidation remain in this applet.
pub trait Store {
    fn size(&mut self, file: File) -> Result<usize, Failure>;
    fn read(&mut self, file: File, offset: usize, bytes: &mut [u8]) -> Result<(), Failure>;
    fn write(
        &mut self,
        file: File,
        offset: usize,
        bytes: &[u8],
        truncate: bool,
    ) -> Result<(), Failure>;
    fn resize(&mut self, file: File, length: usize) -> Result<(), Failure>;
}
pub struct Ndef {
    selected: Option<File>,
    cc: [u8; 15],
    valid: bool,
    write_offset: Option<usize>,
}
impl Default for Ndef {
    fn default() -> Self {
        Self::new()
    }
}
impl Ndef {
    pub const fn new() -> Self {
        Self {
            selected: None,
            cc: [0; 15],
            valid: false,
            write_offset: None,
        }
    }
    pub fn poweroff(&mut self) {
        self.selected = None;
        self.write_offset = None;
    }
    pub fn abort_write(&mut self) {
        self.write_offset = None;
    }
    fn cc(&mut self, s: &mut (impl Store + ?Sized)) -> Result<(), Sw> {
        if !self.valid {
            // A failed/short backing read must not expose partially refreshed
            // permission bytes. The Store contract requires an exact read.
            s.read(File::Capability, 0, &mut self.cc)
                .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
            self.valid = true;
        }
        Ok(())
    }
    pub fn install(&mut self, reset: bool, s: &mut (impl Store + ?Sized)) -> Result<(), Sw> {
        self.poweroff();
        self.valid = false;
        let size = |result: Result<usize, Failure>| match result {
            Ok(n) => Ok(n),
            Err(Failure::Missing) => Ok(0),
            Err(Failure::Io) => Err(Sw::UNABLE_TO_PROCESS),
        };
        if !reset {
            let cc = size(s.size(File::Capability))?;
            let message = size(s.size(File::Message))?;
            if cc == 15 && message > 0 {
                if message != FILE_LIMIT {
                    s.resize(File::Message, FILE_LIMIT)
                        .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
                }
                return self.cc(s);
            }
        }
        s.write(File::Message, 0, INITIAL, true)
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        s.resize(File::Message, FILE_LIMIT)
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        s.write(File::Capability, 0, &DEFAULT_CC, true)
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        self.cc = DEFAULT_CC;
        self.valid = true;
        Ok(())
    }
    pub fn read_only(&mut self, s: &mut (impl Store + ?Sized)) -> bool {
        self.cc(s).is_err() || self.cc[14] == 0xff
    }
    /// ADMIN authorization is checked by its dispatcher before this call.
    pub fn set_read_only(&mut self, value: u8, s: &mut (impl Store + ?Sized)) -> Result<(), Sw> {
        if value > 1 {
            return Err(Sw::WRONG_P1P2);
        }
        self.cc(s)?;
        self.cc[14] = if value == 0 { 0 } else { 0xff };
        self.valid = false;
        s.write(File::Capability, 0, &self.cc, true)
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        self.valid = true;
        Ok(())
    }
    pub fn select(&mut self, p1: u8, p2: u8, data: &[u8]) -> Result<(), Sw> {
        self.abort_write();
        if p1 == 4 && p2 == 0 {
            return Ok(());
        }
        if p1 != 0 || p2 != 0x0c {
            return Err(Sw::WRONG_P1P2);
        }
        if data.len() < 2 {
            return Err(Sw::WRONG_LENGTH);
        }
        self.selected = Some(match &data[..2] {
            [0xe1, 3] => File::Capability,
            [0, 1] => File::Message,
            _ => return Err(Sw::FILE_NOT_FOUND),
        });
        Ok(())
    }
    pub fn check_read(
        &mut self,
        offset: usize,
        length: usize,
        s: &mut (impl Store + ?Sized),
    ) -> Result<(), Sw> {
        self.abort_write();
        if offset > FILE_LIMIT || length > FILE_LIMIT {
            return Err(Sw::WRONG_LENGTH);
        }
        let file = self.selected.ok_or(Sw::CONDITIONS_NOT_SATISFIED)?;
        self.cc(s)?;
        let limit = if file == File::Capability {
            15
        } else {
            if self.cc[13] != 0 {
                return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
            }
            FILE_LIMIT
        };
        if offset > limit || length > limit - offset {
            return Err(Sw::WRONG_LENGTH);
        }
        Ok(())
    }
    /// Pull-based response chunks use the same selected file, with no retained
    /// file cache/handle across transport or crypto callbacks.
    pub fn read(
        &mut self,
        offset: usize,
        out: &mut [u8],
        s: &mut (impl Store + ?Sized),
    ) -> Result<(), Sw> {
        self.check_read(offset, out.len(), s)?;
        if self.selected == Some(File::Capability) {
            out.copy_from_slice(&self.cc[offset..offset + out.len()]);
            Ok(())
        } else {
            s.read(File::Message, offset, out)
                .map_err(|_| Sw::UNABLE_TO_PROCESS)
        }
    }
    pub fn update(
        &mut self,
        offset: usize,
        data: &[u8],
        chained: bool,
        s: &mut (impl Store + ?Sized),
    ) -> Result<(), Sw> {
        if offset > FILE_LIMIT || data.len() > FILE_LIMIT {
            self.abort_write();
            return Err(Sw::WRONG_LENGTH);
        }
        if self.selected != Some(File::Message) {
            self.abort_write();
            return Err(Sw::CONDITIONS_NOT_SATISFIED);
        }
        self.cc(s)?;
        if self.cc[14] != 0 {
            return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        let offset = self.write_offset.unwrap_or(offset);
        if data.len() > FILE_LIMIT - offset {
            self.abort_write();
            return Err(Sw::WRONG_LENGTH);
        }
        // Do not retain a continuation after an uncertain persistence result.
        self.write_offset = None;
        s.write(File::Message, offset, data, false)
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        if chained {
            self.write_offset = Some(offset + data.len());
        }
        Ok(())
    }
}

fn record(file: File) -> crate::ports::Record {
    match file {
        File::Capability => crate::ports::Record::NdefCapability,
        File::Message => crate::ports::Record::NdefMessage,
    }
}
fn failure(error: crate::ports::StorageError) -> Failure {
    match error {
        crate::ports::StorageError::Missing => Failure::Missing,
        _ => Failure::Io,
    }
}
impl<T: crate::ports::Storage + ?Sized> Store for T {
    fn size(&mut self, file: File) -> Result<usize, Failure> {
        crate::ports::Storage::size(self, record(file))
            .map(|n| n as usize)
            .map_err(failure)
    }
    fn read(&mut self, file: File, offset: usize, bytes: &mut [u8]) -> Result<(), Failure> {
        self.read_at(
            record(file),
            u32::try_from(offset).map_err(|_| Failure::Io)?,
            bytes,
        )
        .map_err(failure)
    }
    fn write(
        &mut self,
        file: File,
        offset: usize,
        bytes: &[u8],
        truncate: bool,
    ) -> Result<(), Failure> {
        if truncate {
            if offset != 0 {
                return Err(Failure::Io);
            }
            self.replace(record(file), bytes).map_err(failure)
        } else {
            self.replace_at(
                record(file),
                u32::try_from(offset).map_err(|_| Failure::Io)?,
                bytes,
            )
            .map_err(failure)
        }
    }
    fn resize(&mut self, file: File, length: usize) -> Result<(), Failure> {
        crate::ports::Storage::resize(
            self,
            record(file),
            u32::try_from(length).map_err(|_| Failure::Io)?,
        )
        .map_err(failure)
    }
}

/// Stored in the registry's mutually exclusive applet enum. This short frame
/// window overlaps other classic applet state, never CTAP/crypto scratch.
pub struct Applet {
    file: Ndef,
    input: [u8; 255],
    used: usize,
    header: canokey_protocol::apdu::Header,
    response_offset: usize,
    response_length: usize,
}
impl Default for Applet {
    fn default() -> Self {
        Self::new()
    }
}
impl Applet {
    pub const fn new() -> Self {
        Self {
            file: Ndef::new(),
            input: [0; 255],
            used: 0,
            header: canokey_protocol::apdu::Header {
                cla: 0,
                ins: 0,
                p1: 0,
                p2: 0,
            },
            response_offset: 0,
            response_length: 0,
        }
    }
    pub fn install(reset: bool, p: &mut crate::Platform<'_>) -> Result<(), Sw> {
        Ndef::new().install(reset, p.storage)
    }
    pub fn cancel(&mut self) {
        self.input.fill(0);
        self.used = 0;
        self.file.abort_write();
    }
    pub fn begin(&mut self, h: canokey_protocol::apdu::Header) -> Result<(), Sw> {
        self.cancel();
        self.header = h;
        if !matches!(h.ins, 0xa4 | 0xb0 | 0xd6) {
            return Err(Sw::INS_NOT_SUPPORTED);
        }
        Ok(())
    }
    pub fn consume(&mut self, bytes: &[u8]) -> Result<(), Sw> {
        let end = self
            .used
            .checked_add(bytes.len())
            .filter(|&n| n <= self.input.len())
            .ok_or(Sw::WRONG_LENGTH)?;
        self.input[self.used..end].copy_from_slice(bytes);
        self.used = end;
        Ok(())
    }
    pub fn end_frame(&mut self, last: bool, p: &mut crate::Platform<'_>) -> Result<(), Sw> {
        if self.header.ins == 0xd6 {
            let offset = u16::from_be_bytes([self.header.p1, self.header.p2]) as usize;
            let result = self
                .file
                .update(offset, &self.input[..self.used], !last, p.storage);
            self.input.fill(0);
            self.used = 0;
            result
        } else {
            Ok(())
        }
    }
    pub fn finish(&mut self, le: u32, p: &mut crate::Platform<'_>) -> Result<(u32, Sw), Sw> {
        match self.header.ins {
            0xa4 => {
                self.file
                    .select(self.header.p1, self.header.p2, &self.input[..self.used])?;
                Ok((0, Sw::SUCCESS))
            }
            0xb0 => {
                let offset = u16::from_be_bytes([self.header.p1, self.header.p2]) as usize;
                self.file.check_read(offset, le as usize, p.storage)?;
                self.response_offset = offset;
                self.response_length = le as usize;
                Ok((le, Sw::SUCCESS))
            }
            0xd6 => Ok((0, Sw::SUCCESS)),
            _ => Err(Sw::INS_NOT_SUPPORTED),
        }
    }
    pub fn read(
        &mut self,
        offset: usize,
        out: &mut [u8],
        p: &mut crate::Platform<'_>,
    ) -> Result<usize, Sw> {
        if offset > self.response_length || out.len() > self.response_length - offset {
            return Err(Sw::WRONG_LENGTH);
        }
        self.file
            .read(self.response_offset + offset, out, p.storage)?;
        Ok(out.len())
    }
    pub fn close(&mut self) {
        self.response_length = 0;
    }
}
