// SPDX-License-Identifier: Apache-2.0
//! Storage and staged-record adapter for the `core.h` ck_platform_* ABI.
//! Firmware implements it with LittleFS; host virtual cards use record images.
use crate::{Record, Storage, StorageError};

#[cfg(any(feature = "openpgp", feature = "piv"))]
#[derive(Clone, Copy)]
#[repr(C)]
struct StoragePart {
    data: *const u8,
    length: usize,
}
#[cfg(any(feature = "openpgp", feature = "piv"))]
unsafe extern "C" {
    fn ck_platform_stage_parts(parts: *const StoragePart, count: usize) -> i32;
}

/// Native platform capability, created only at the serialized FFI boundary.
/// The marker prevents transferring a borrowed hardware session across threads.
pub struct StorageBackend(core::marker::PhantomData<*mut ()>);

impl StorageBackend {
    /// # Safety
    /// All native platform access, including callbacks and other backend values,
    /// must remain serialized for this value's entire lifetime. Native global
    /// storage, crypto scratch and presence state are not independently locked.
    pub unsafe fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

#[cfg(feature = "storage")]
unsafe extern "C" {
    fn platform_config_page_read(offset: usize, out: *mut u8, len: usize) -> i32;
    fn platform_config_page_write(page: *const u8, len: usize) -> i32;
    fn ck_platform_usage(used: *mut u32, total: *mut u32) -> i32;
    fn ck_platform_size(file: u8) -> i32;
    fn ck_platform_read(file: u8, out: *mut u8, len: usize) -> i32;
    fn ck_platform_write(file: u8, input: *const u8, len: usize) -> i32;
    fn ck_platform_write_at(file: u8, offset: u32, input: *const u8, len: usize) -> i32;
}
#[cfg(any(
    feature = "oath",
    feature = "openpgp",
    feature = "piv",
    feature = "ctap",
    feature = "ndef"
))]
unsafe extern "C" {
    fn ck_platform_stage(operation: u8, file: u8, input: *const u8, len: usize) -> i32;
}
#[cfg(any(
    feature = "oath",
    feature = "openpgp",
    feature = "piv",
    feature = "ctap",
    feature = "ndef"
))]
unsafe extern "C" {
    fn ck_platform_read_at(file: u8, offset: u32, out: *mut u8, len: usize) -> i32;
    fn ck_platform_has_space(bytes: u32, reserve: u32) -> i32;
}

#[cfg(feature = "ndef")]
unsafe extern "C" {
    fn ck_platform_resize(file: u8, length: u32) -> i32;
}

// Stable byte ABI, mirrored in native/include/core.h.
#[cfg(any(
    feature = "oath",
    feature = "openpgp",
    feature = "piv",
    feature = "ctap",
    feature = "ndef"
))]
#[repr(u8)]
// Variants are gated by platform capabilities and applet features; numeric
// values remain aligned with ck_stage_operation in native/include/core.h.
enum StageOperation {
    Begin = crate::contracts::stage_operation::BEGIN,
    Append = crate::contracts::stage_operation::APPEND,
    Publish = crate::contracts::stage_operation::PUBLISH,
    Abort = crate::contracts::stage_operation::ABORT,
    #[cfg(feature = "platform-stage")]
    Remove = crate::contracts::stage_operation::REMOVE,
    #[cfg(feature = "piv")]
    Rename = crate::contracts::stage_operation::RENAME,
}
#[cfg(any(feature = "openpgp", feature = "piv"))]
const MAX_STAGE_PARTS: usize = 8; // ck_platform_stage_parts ABI, core.h.
// C reads return a byte count, -1 for missing, and other negatives for failure.
// Writes/staging use different success conventions (count vs zero). Failed
// mutations map to Uncertain: a backend error does not prove nothing was written,
// so applets must invalidate cached state rather than retry from assumptions.
native_port! { impl Storage for StorageBackend {
    #[cfg(any(feature = "openpgp", feature = "piv"))]
    fn stage_parts(&mut self, parts: &[&[u8]]) -> Result<(), StorageError> {
        if parts.len() > MAX_STAGE_PARTS {
            return Err(StorageError::Unavailable);
        }
        let mut native = [StoragePart {
            data: core::ptr::null(),
            length: 0,
        }; MAX_STAGE_PARTS];
        for (out, part) in native.iter_mut().zip(parts) {
            *out = StoragePart {
                data: part.as_ptr(),
                length: part.len(),
            };
        }
        if unsafe { ck_platform_stage_parts(native.as_ptr(), parts.len()) } == 0 {
            Ok(())
        } else {
            Err(StorageError::Uncertain)
        }
    }
    fn usage(&mut self) -> Result<(u32, u32), StorageError> {
        #[cfg(feature = "storage")]
        {
            let (mut used, mut total) = (0, 0);
            if unsafe { ck_platform_usage(&mut used, &mut total) } == 0 && used <= total {
                Ok((used, total))
            } else {
                Err(StorageError::Unavailable)
            }
        }
        #[cfg(not(feature = "storage"))]
        {
            Err(StorageError::Unavailable)
        }
    }

    fn config_read(&mut self, offset: usize, bytes: &mut [u8]) -> Result<(), StorageError> {
        #[cfg(feature = "storage")]
        {
            if unsafe { platform_config_page_read(offset, bytes.as_mut_ptr(), bytes.len()) } == 0 {
                Ok(())
            } else {
                Err(StorageError::Unavailable)
            }
        }
        #[cfg(not(feature = "storage"))]
        {
            let _ = (offset, bytes);
            Err(StorageError::Missing)
        }
    }
    fn config_write(&mut self, bytes: &[u8; 512]) -> Result<(), StorageError> {
        #[cfg(feature = "storage")]
        {
            if unsafe { platform_config_page_write(bytes.as_ptr(), bytes.len()) } == 0 {
                Ok(())
            } else {
                Err(StorageError::Uncertain)
            }
        }
        #[cfg(not(feature = "storage"))]
        {
            let _ = bytes;
            Err(StorageError::Unavailable)
        }
    }
    #[cfg(feature = "ndef")]
    fn resize(&mut self, record: Record, length: u32) -> Result<(), StorageError> {
        if unsafe { ck_platform_resize(record.id(), length) } == 0 {
            Ok(())
        } else {
            Err(StorageError::Uncertain)
        }
    }
    #[cfg(feature = "platform-stage")]
    fn remove(&mut self, id: Record) -> Result<(), StorageError> {
        if unsafe { ck_platform_stage(StageOperation::Remove as u8, id.id(), core::ptr::null(), 0) }
            == 0
        {
            Ok(())
        } else {
            Err(StorageError::Uncertain)
        }
    }
    #[cfg(feature = "piv")]
    fn move_record(&mut self, from: Record, to: Record) -> Result<(), StorageError> {
        if unsafe { ck_platform_stage(StageOperation::Rename as u8, from.id(), &(to.id()), 1) } == 0
        {
            Ok(())
        } else {
            Err(StorageError::Uncertain)
        }
    }

    #[cfg(any(
        feature = "oath",
        feature = "openpgp",
        feature = "piv",
        feature = "ctap",
        feature = "ndef"
    ))]
    fn stage_begin(&mut self) -> Result<(), StorageError> {
        if unsafe { ck_platform_stage(StageOperation::Begin as u8, 0, core::ptr::null(), 0) } == 0 {
            Ok(())
        } else {
            Err(StorageError::Uncertain)
        }
    }
    #[cfg(any(
        feature = "oath",
        feature = "openpgp",
        feature = "piv",
        feature = "ctap",
        feature = "ndef"
    ))]
    fn stage_append(&mut self, b: &[u8]) -> Result<(), StorageError> {
        if unsafe { ck_platform_stage(StageOperation::Append as u8, 0, b.as_ptr(), b.len()) } == 0 {
            Ok(())
        } else {
            Err(StorageError::Uncertain)
        }
    }
    #[cfg(any(
        feature = "oath",
        feature = "openpgp",
        feature = "piv",
        feature = "ctap",
        feature = "ndef"
    ))]
    fn stage_commit(&mut self, id: Record) -> Result<(), StorageError> {
        if unsafe {
            ck_platform_stage(StageOperation::Publish as u8, id.id(), core::ptr::null(), 0)
        } == 0
        {
            Ok(())
        } else {
            Err(StorageError::Uncertain)
        }
    }
    #[cfg(any(
        feature = "oath",
        feature = "openpgp",
        feature = "piv",
        feature = "ctap",
        feature = "ndef"
    ))]
    fn stage_abort(&mut self) {
        unsafe {
            ck_platform_stage(StageOperation::Abort as u8, 0, core::ptr::null(), 0);
        }
    }

    fn size(&mut self, file: Record) -> Result<u32, StorageError> {
        #[cfg(feature = "storage")]
        {
            match unsafe { ck_platform_size(file.id()) } {
                -1 => Err(StorageError::Missing),
                n if n >= 0 => Ok(n as u32),
                _ => Err(StorageError::Unavailable),
            }
        }
        #[cfg(not(feature = "storage"))]
        {
            let _ = file;
            Err(StorageError::Unavailable)
        }
    }
    #[cfg(any(
        feature = "oath",
        feature = "openpgp",
        feature = "piv",
        feature = "ctap",
        feature = "ndef"
    ))]
    fn read_at(&mut self, file: Record, offset: u32, out: &mut [u8]) -> Result<(), StorageError> {
        if unsafe { ck_platform_read_at(file.id(), offset, out.as_mut_ptr(), out.len()) }
            == out.len() as i32
        {
            Ok(())
        } else {
            Err(StorageError::Unavailable)
        }
    }
    #[cfg(feature = "storage")]
    fn replace_at(&mut self, file: Record, offset: u32, input: &[u8]) -> Result<(), StorageError> {
        if unsafe { ck_platform_write_at(file.id(), offset, input.as_ptr(), input.len()) }
            == input.len() as i32
        {
            Ok(())
        } else {
            Err(StorageError::Uncertain)
        }
    }
    #[cfg(any(
        feature = "oath",
        feature = "openpgp",
        feature = "piv",
        feature = "ctap",
        feature = "ndef"
    ))]
    fn has_space(&mut self, bytes: u32, reserve: u32) -> Result<bool, StorageError> {
        match unsafe { ck_platform_has_space(bytes, reserve) } {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(StorageError::Unavailable),
        }
    }

    fn load(&mut self, file: Record, out: &mut [u8]) -> Result<usize, StorageError> {
        #[cfg(feature = "storage")]
        {
            match unsafe { ck_platform_read(file.id(), out.as_mut_ptr(), out.len()) } {
                -1 => Err(StorageError::Missing),
                n if n >= 0 => Ok(n as usize),
                _ => Err(StorageError::Unavailable),
            }
        }
        #[cfg(not(feature = "storage"))]
        {
            let _ = (file, out);
            Err(StorageError::Unavailable)
        }
    }
    fn replace(&mut self, file: Record, input: &[u8]) -> Result<(), StorageError> {
        #[cfg(feature = "storage")]
        {
            if unsafe { ck_platform_write(file.id(), input.as_ptr(), input.len()) }
                == input.len() as i32
            {
                Ok(())
            } else {
                Err(StorageError::Uncertain)
            }
        }
        #[cfg(not(feature = "storage"))]
        {
            let _ = (file, input);
            Err(StorageError::Unavailable)
        }
    }
}

}
