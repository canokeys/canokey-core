// SPDX-License-Identifier: Apache-2.0
//! Storage and staged-record adapter for the C LittleFS backend.
use crate::{Record, Storage, StorageError};

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
    fn ck_platform_read(file: u8, out: *mut u8, len: usize) -> i32;
    fn ck_platform_write(file: u8, input: *const u8, len: usize) -> i32;
}
#[cfg(any(
    feature = "oath",
    feature = "openpgp",
    feature = "piv",
    feature = "ctap"
))]
unsafe extern "C" {
    fn ck_platform_stage(operation: u8, file: u8, input: *const u8, len: usize) -> i32;
}
#[cfg(any(
    feature = "oath",
    feature = "openpgp",
    feature = "piv",
    feature = "ctap"
))]
unsafe extern "C" {
    fn ck_platform_size(file: u8) -> i32;
    fn ck_platform_read_at(file: u8, offset: u32, out: *mut u8, len: usize) -> i32;
    fn ck_platform_write_at(file: u8, offset: u32, input: *const u8, len: usize) -> i32;
    fn ck_platform_has_space(bytes: u32, reserve: u32) -> i32;
}

// Stable byte ABI, mirrored in interfaces/rust-core/core.h.
#[cfg(any(
    feature = "oath",
    feature = "openpgp",
    feature = "piv",
    feature = "ctap"
))]
#[repr(u8)]
// Variants are gated by the applet profiles that can issue them; the numeric
// values remain aligned with the shared C StageOperation ABI.
enum StageOperation {
    Begin = 0,
    Append = 1,
    Publish = 2,
    Abort = 3,
    #[cfg(feature = "platform-stage")]
    Remove = 4,
    #[cfg(feature = "piv")]
    Rename = 5,
}
// C reads return a byte count, -1 for missing, and other negatives for failure.
// Writes/staging use different success conventions (count vs zero). Failed
// mutations map to Uncertain: a backend error does not prove nothing was written,
// so applets must invalidate cached state rather than retry from assumptions.
native_port! { impl Storage for StorageBackend {
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
        feature = "ctap"
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
        feature = "ctap"
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
        feature = "ctap"
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
        feature = "ctap"
    ))]
    fn stage_abort(&mut self) {
        unsafe {
            ck_platform_stage(StageOperation::Abort as u8, 0, core::ptr::null(), 0);
        }
    }

    #[cfg(any(
        feature = "oath",
        feature = "openpgp",
        feature = "piv",
        feature = "ctap"
    ))]
    fn size(&mut self, file: Record) -> Result<u32, StorageError> {
        match unsafe { ck_platform_size(file.id()) } {
            -1 => Err(StorageError::Missing),
            n if n >= 0 => Ok(n as u32),
            _ => Err(StorageError::Unavailable),
        }
    }
    #[cfg(any(
        feature = "oath",
        feature = "openpgp",
        feature = "piv",
        feature = "ctap"
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
    #[cfg(any(
        feature = "oath",
        feature = "openpgp",
        feature = "piv",
        feature = "ctap"
    ))]
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
        feature = "ctap"
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
