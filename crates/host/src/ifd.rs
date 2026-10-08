// SPDX-License-Identifier: Apache-2.0
//! PC/SC IFD handler v3 boundary; validated against the system headers by CTest.
use crate::pcsc::*;
#[cfg(not(target_os = "macos"))]
use std::ffi::c_ulong;
use std::{
    ffi::{c_char, c_int, c_long},
    mem, ptr,
};
// pcsc-lite wintypes.h defines DWORD as uint32_t on Apple and unsigned long
// elsewhere. RESPONSECODE in ifdhandler.h is long on both supported platforms.
#[cfg(target_os = "macos")]
type Dword = u32;
#[cfg(not(target_os = "macos"))]
type Dword = c_ulong;
type ResponseCode = c_long;
#[repr(C)]
pub struct IoHeader {
    protocol: Dword,
    length: Dword,
}
// Values from pcsc-lite ifdhandler.h / reader.h, checked by the C ABI fixture.
const SUCCESS: ResponseCode = 0;
const ERROR_TAG: ResponseCode = 600;
const ERROR_NOT_SUPPORTED: ResponseCode = 606;
const PROTOCOL_NOT_SUPPORTED: ResponseCode = 607;
const COMMUNICATION_ERROR: ResponseCode = 612;
const NOT_SUPPORTED: ResponseCode = 614;
const ICC_PRESENT: ResponseCode = 615;
const ICC_NOT_PRESENT: ResponseCode = 616;
const NO_SUCH_DEVICE: ResponseCode = 617;
const INSUFFICIENT_BUFFER: ResponseCode = 618;
const TAG_ATR: Dword = 0x0303;
const ATTR_ATR: Dword = 0x00090303;
const TAG_THREAD_SAFE: Dword = 0x0fad;
const TAG_SLOTS: Dword = 0x0fae;
const TAG_SIMULTANEOUS: Dword = 0x0faf;
const TAG_KILLABLE: Dword = 0x0fb1;
const TAG_POLL_TIMEOUT: Dword = 0x0fb3;
const PROTOCOL_T1: Dword = 0x0002;
const POWER_UP: Dword = 500;
const POWER_DOWN: Dword = 501;
const RESET: Dword = 502;
fn status(result: i32) -> ResponseCode {
    match result {
        0 => SUCCESS,
        2 => INSUFFICIENT_BUFFER,
        3 => NOT_SUPPORTED,
        4 => NO_SUCH_DEVICE,
        5 => PROTOCOL_NOT_SUPPORTED,
        6 => ERROR_TAG,
        _ => COMMUNICATION_ERROR,
    }
}
#[unsafe(export_name = "IFDHCreateChannel")]
extern "C" fn create(lun: Dword, _: Dword) -> ResponseCode {
    status(ck_pcsc_open(lun as u64))
}
#[unsafe(export_name = "IFDHCreateChannelByName")]
extern "C" fn create_named(lun: Dword, _: *mut c_char) -> ResponseCode {
    status(ck_pcsc_open(lun as u64))
}
#[unsafe(export_name = "IFDHCloseChannel")]
extern "C" fn close(lun: Dword) -> ResponseCode {
    status(ck_pcsc_close(lun as u64))
}
unsafe extern "C" {
    fn ck_host_pcsc_poll_setup(
        validate: extern "C" fn(Dword) -> c_int,
    ) -> unsafe extern "C" fn(Dword, c_int) -> ResponseCode;
}
extern "C" fn ck_host_pcsc_poll_valid(lun: Dword) -> c_int {
    i32::from(ck_pcsc_present(lun as u64) == 0)
}
#[unsafe(export_name = "IFDHGetCapabilities")]
unsafe extern "C" fn get_capability(
    lun: Dword,
    tag: Dword,
    length: *mut Dword,
    value: *mut u8,
) -> ResponseCode {
    if length.is_null() {
        return COMMUNICATION_ERROR;
    }
    let capacity = unsafe { length.read() } as usize;
    if tag == TAG_POLL_TIMEOUT {
        if ck_pcsc_present(lun as u64) != 0 {
            unsafe {
                length.write(0);
            }
            return NO_SUCH_DEVICE;
        }
        let callback = unsafe { ck_host_pcsc_poll_setup(ck_host_pcsc_poll_valid) };
        let size = mem::size_of_val(&callback);
        unsafe {
            length.write(size as Dword);
        }
        if capacity < size {
            return INSUFFICIENT_BUFFER;
        }
        if value.is_null() {
            return COMMUNICATION_ERROR;
        }
        unsafe {
            ptr::copy_nonoverlapping(ptr::from_ref(&callback).cast::<u8>(), value, size);
        }
        return SUCCESS;
    }
    let kind = match tag {
        TAG_ATR | ATTR_ATR => 0,
        TAG_SIMULTANEOUS => 1,
        TAG_SLOTS => 2,
        TAG_KILLABLE => 3,
        TAG_THREAD_SAFE => 4,
        _ => 255,
    };
    let mut size = 0;
    let result = unsafe { ck_pcsc_capability(lun as u64, kind, value, capacity, &mut size) };
    unsafe {
        length.write(size as Dword);
    }
    status(result)
}
#[unsafe(export_name = "IFDHSetCapabilities")]
extern "C" fn set_capability(_: Dword, _: Dword, _: Dword, _: *mut u8) -> ResponseCode {
    ERROR_TAG
}
#[unsafe(export_name = "IFDHSetProtocolParameters")]
extern "C" fn protocol(lun: Dword, protocol: Dword, _: u8, _: u8, _: u8, _: u8) -> ResponseCode {
    status(ck_pcsc_protocol(
        lun as u64,
        u8::from(protocol == PROTOCOL_T1),
    ))
}
#[unsafe(export_name = "IFDHPowerICC")]
unsafe extern "C" fn power(
    lun: Dword,
    action: Dword,
    atr: *mut u8,
    length: *mut Dword,
) -> ResponseCode {
    if length.is_null() {
        return COMMUNICATION_ERROR;
    }
    let kind = match action {
        POWER_UP => 0,
        POWER_DOWN => 1,
        RESET => 2,
        _ => 255,
    };
    let mut size = 0;
    let result = unsafe { ck_pcsc_power(lun as u64, kind, atr, length.read() as usize, &mut size) };
    unsafe {
        length.write(size as Dword);
    }
    status(result)
}
#[unsafe(export_name = "IFDHTransmitToICC")]
unsafe extern "C" fn transmit(
    lun: Dword,
    send: IoHeader,
    tx: *mut u8,
    n: Dword,
    rx: *mut u8,
    length: *mut Dword,
    receive: *mut IoHeader,
) -> ResponseCode {
    if length.is_null() || receive.is_null() {
        return COMMUNICATION_ERROR;
    }
    unsafe {
        receive.write(IoHeader {
            protocol: send.protocol,
            length: mem::size_of::<IoHeader>() as Dword,
        });
    }
    let mut size = 0;
    let result = unsafe {
        ck_pcsc_transmit(
            lun as u64,
            tx,
            n as usize,
            rx,
            length.read() as usize,
            &mut size,
        )
    };
    unsafe {
        length.write(size as Dword);
    }
    status(result)
}
#[unsafe(export_name = "IFDHControl")]
unsafe extern "C" fn control(
    _: Dword,
    _: Dword,
    _: *mut u8,
    _: Dword,
    _: *mut u8,
    _: Dword,
    returned: *mut Dword,
) -> ResponseCode {
    if returned.is_null() {
        return COMMUNICATION_ERROR;
    }
    unsafe {
        returned.write(0);
    }
    ERROR_NOT_SUPPORTED
}
#[unsafe(export_name = "IFDHICCPresence")]
extern "C" fn presence(lun: Dword) -> ResponseCode {
    if ck_pcsc_present(lun as u64) == 0 {
        ICC_PRESENT
    } else {
        ICC_NOT_PRESENT
    }
}
