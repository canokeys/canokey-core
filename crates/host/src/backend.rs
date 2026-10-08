// SPDX-License-Identifier: Apache-2.0
//! Host capabilities lock callback state per operation, never across Core entry.
use super::{PKE_BYTES, device_get_tick, host, progress, touched};
use canokey_ports::{
    BackendTypes, Device, MemoryBackend, Platform, Record, Storage, StorageError,
    stage_operation as stage,
};
use canokey_rust_ffi::composition::{Provider, Staging, hid};

pub(crate) struct HostProvider;
pub(crate) struct Records;
pub(crate) struct Clock;
pub(crate) struct Scratch;
// Preserve the native projection's bounded staged-record vector contract.
const MAX_STAGE_PARTS: usize = 8;
impl Provider for HostProvider {
    type Backends =
        BackendTypes<Records, canokey_ports::native::CryptoBackend, Clock, MemoryBackend>;
    type Staging = Scratch;
    fn with_platform<T>(run: impl FnOnce(&mut Platform<'_, Self::Backends>) -> T) -> T {
        let mut crypto = unsafe { canokey_ports::native::CryptoBackend::new() };
        run(&mut Platform::new(
            &mut Records,
            &mut crypto,
            &mut Clock,
            &MemoryBackend,
        ))
    }
}
fn count(
    value: Result<usize, i32>,
    expected: Option<usize>,
    failure: StorageError,
) -> Result<usize, StorageError> {
    match value {
        Ok(n) if expected.is_none_or(|expected| n == expected) => Ok(n),
        Err(-1) if expected.is_none() => Err(StorageError::Missing),
        _ => Err(failure),
    }
}
fn mutation(value: Result<(), i32>) -> Result<(), StorageError> {
    value.map_err(|_| StorageError::Uncertain)
}
impl Records {
    fn stage(&mut self, operation: u8, id: u8, bytes: &[u8]) -> Result<(), StorageError> {
        mutation(host(|h| h.storage.stage(operation, id, bytes)))
    }
}
impl Storage for Records {
    fn load(&mut self, record: Record, out: &mut [u8]) -> Result<usize, StorageError> {
        count(
            host(|h| h.storage.read(record.id(), 0, out, true)),
            None,
            StorageError::Unavailable,
        )
    }
    fn replace(&mut self, record: Record, bytes: &[u8]) -> Result<(), StorageError> {
        count(
            host(|h| h.storage.write(record.id(), bytes)),
            Some(bytes.len()),
            StorageError::Uncertain,
        )
        .map(|_| ())
    }
    fn size(&mut self, record: Record) -> Result<u32, StorageError> {
        count(
            host(|h| h.storage.size(record.id())),
            None,
            StorageError::Unavailable,
        )
        .map(|n| n as u32)
    }
    fn read_at(&mut self, record: Record, offset: u32, out: &mut [u8]) -> Result<(), StorageError> {
        count(
            host(|h| h.storage.read(record.id(), offset as usize, out, false)),
            Some(out.len()),
            StorageError::Unavailable,
        )
        .map(|_| ())
    }
    fn replace_at(
        &mut self,
        record: Record,
        offset: u32,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        count(
            host(|h| h.storage.patch(record.id(), offset as usize, bytes)),
            Some(bytes.len()),
            StorageError::Uncertain,
        )
        .map(|_| ())
    }
    fn resize(&mut self, record: Record, length: u32) -> Result<(), StorageError> {
        mutation(host(|h| h.storage.resize(record.id(), length as usize)))
    }
    fn usage(&mut self) -> Result<(u32, u32), StorageError> {
        host(|h| h.storage.usage())
            .map_err(|_| StorageError::Unavailable)
            .and_then(|(used, total)| {
                if used <= total {
                    Ok((used, total))
                } else {
                    Err(StorageError::Unavailable)
                }
            })
    }
    fn has_space(&mut self, bytes: u32, reserve: u32) -> Result<bool, StorageError> {
        self.usage()
            .map(|(used, total)| total - used >= reserve && total - used - reserve >= bytes)
    }
    fn config_read(&mut self, offset: usize, bytes: &mut [u8]) -> Result<(), StorageError> {
        host(|h| h.storage.config_read(offset, bytes)).map_err(|_| StorageError::Unavailable)
    }
    fn config_write(&mut self, bytes: &[u8; 512]) -> Result<(), StorageError> {
        mutation(host(|h| h.storage.config_write(bytes)))
    }
    fn stage_begin(&mut self) -> Result<(), StorageError> {
        self.stage(stage::BEGIN, 0, &[])
    }
    fn stage_append(&mut self, bytes: &[u8]) -> Result<(), StorageError> {
        self.stage(stage::APPEND, 0, bytes)
    }
    fn stage_commit(&mut self, record: Record) -> Result<(), StorageError> {
        self.stage(stage::PUBLISH, record.id(), &[])
    }
    fn stage_abort(&mut self) {
        let _ = self.stage(stage::ABORT, 0, &[]);
    }
    fn stage_parts(&mut self, parts: &[&[u8]]) -> Result<(), StorageError> {
        if parts.len() > MAX_STAGE_PARTS {
            return Err(StorageError::Unavailable);
        }
        let result = (|| {
            self.stage_begin()?;
            for part in parts {
                self.stage_append(part)?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.stage_abort();
        }
        result
    }
    fn remove(&mut self, record: Record) -> Result<(), StorageError> {
        self.stage(stage::REMOVE, record.id(), &[])
    }
    fn move_record(&mut self, from: Record, to: Record) -> Result<(), StorageError> {
        self.stage(stage::RENAME, from.id(), &[to.id()])
    }
}
impl Device for Clock {
    fn serial(&mut self, out: &mut [u8; 4]) {
        out.fill(0);
    }
    fn information(&mut self, kind: u8, out: &mut [u8]) -> usize {
        use canokey_ports::contracts::{CHIP_ID_BYTES, board_info_kind};
        let bytes: &[u8] = match kind {
            board_info_kind::FIRMWARE => option_env!("CANOKEY_ADMIN_VERSION")
                .unwrap_or("0.0.0")
                .as_bytes(),
            board_info_kind::PRODUCT => b"CanoKey Rust Virtual Card",
            board_info_kind::CHIP_ID => &[0; CHIP_ID_BYTES],
            _ => option_env!("CANOKEY_CORE_SHA")
                .unwrap_or("unknown")
                .as_bytes(),
        };
        let n = out.len().min(bytes.len());
        out[..n].copy_from_slice(&bytes[..n]);
        n
    }
    fn now(&mut self) -> u32 {
        device_get_tick()
    }
    fn touched(&mut self) -> bool {
        touched()
    }
    fn contactless(&mut self) -> bool {
        host(|h| h.nfc)
    }
    fn led(&mut self, on: bool) {
        host(|h| h.led = on);
    }
    fn progress(&mut self) -> bool {
        progress()
    }
    fn keepalive(&mut self, waiting: bool) {
        if !self.contactless() {
            unsafe { hid::keepalive(waiting) };
        }
    }
    fn wink(&mut self) {
        host(|h| h.presence.wink(device_get_tick_unlocked(h)));
    }
    fn poll_presence(&mut self) -> bool {
        host(|h| {
            let accepted = h.presence.take(device_get_tick_unlocked(h));
            if accepted {
                h.led = false;
            }
            accepted
        })
    }
}
fn device_get_tick_unlocked(h: &super::Host) -> u32 {
    h.ticks
        .unwrap_or_else(|| h.boot.elapsed().as_millis() as u32)
}
pub(crate) fn presence_sample() {
    if host(|h| h.nfc) {
        return;
    }
    let pressed = touched();
    host(|h| {
        if let Some(on) = h.presence.sample(pressed, device_get_tick_unlocked(h)) {
            h.led = on;
        }
    });
}
impl Staging for Scratch {
    fn capacity() -> usize {
        PKE_BYTES
    }
    fn acquire(owner: u8) -> bool {
        host(|h| {
            if owner == 0 || (h.owner != 0 && h.owner != owner) {
                return false;
            }
            h.owner = owner;
            true
        })
    }
    fn clear() -> bool {
        host(|h| {
            h.pke.fill(0);
            true
        })
    }
    fn release(owner: u8) -> bool {
        host(|h| {
            if owner == 0 || h.owner != owner {
                return false;
            }
            h.owner = 0;
            true
        })
    }
    fn read(offset: usize, out: &mut [u8]) -> bool {
        host(|h| {
            if h.owner == 0 {
                return false;
            }
            let Some(bytes) = offset
                .checked_add(out.len())
                .and_then(|end| h.pke.get(offset..end))
            else {
                return false;
            };
            out.copy_from_slice(bytes);
            true
        })
    }
    fn write(offset: usize, input: &[u8]) -> bool {
        host(|h| {
            if h.owner == 0 {
                return false;
            }
            let Some(bytes) = offset
                .checked_add(input.len())
                .and_then(|end| h.pke.get_mut(offset..end))
            else {
                return false;
            };
            bytes.copy_from_slice(input);
            true
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn direct_staging_ownership_bounds_and_clear() {
        let _entry = super::super::ENTRY.lock().unwrap();
        let path = std::env::temp_dir().join(format!("canokey-backend-{}.img", std::process::id()));
        super::super::initialize_storage(None, path.to_str().unwrap(), true, false).unwrap();
        let payload: Vec<_> = (0..PKE_BYTES).map(|i| i as u8).collect();
        let mut out = vec![0; PKE_BYTES];
        assert!(!Scratch::acquire(0));
        assert!(Scratch::acquire(3));
        assert!(Scratch::acquire(3));
        assert!(!Scratch::acquire(2));
        assert!(Scratch::write(0, &payload));
        assert!(!Scratch::release(2));
        assert!(Scratch::release(3));
        assert!(!Scratch::read(0, &mut out));
        assert!(Scratch::acquire(2));
        assert!(Scratch::read(0, &mut out));
        assert_eq!(out, payload);
        for offset in [PKE_BYTES, PKE_BYTES + 1, usize::MAX] {
            assert!(!Scratch::read(offset, &mut [0]));
            assert!(!Scratch::write(offset, &[0]));
        }
        assert!(!Scratch::read(PKE_BYTES + 1, &mut []));
        assert!(!Scratch::write(PKE_BYTES + 1, &[]));
        assert!(Scratch::clear());
        assert!(Scratch::read(0, &mut out));
        assert!(out.iter().all(|b| *b == 0));
        assert!(Scratch::release(2));
        super::super::HOST.lock().unwrap().take();
        std::fs::remove_file(path).unwrap();
    }
}
