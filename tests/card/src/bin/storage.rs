// SPDX-License-Identifier: Apache-2.0
//! Real applets with the native LittleFS fault-injection fixture.
use canokey_ports::Record;
use canokey_rust_ffi::{Native, composition::core};
use std::ffi::{CString, c_char};
use std::io::{self, BufRead, Write};

const APDU_BYTES: usize = 512;
// Match the native flash model's CCID transport ownership.
const OWNER_CCID: u8 = 1;
type Exchange = unsafe extern "C" fn(u8, *const u8, usize, *mut u8, usize) -> i32;
unsafe extern "C" {
    fn ck_test_flash_init(reset: unsafe extern "C" fn(), exchange: Exchange);
    fn ck_test_flash_command(line: *const c_char) -> i32;
    fn ck_test_flash_exchange(
        owner: u8,
        input: *const u8,
        len: usize,
        out: *mut u8,
        capacity: usize,
    ) -> i32;
    fn ck_platform_read(id: u8, out: *mut u8, len: usize) -> i32;
    fn ck_platform_write(id: u8, bytes: *const u8, len: usize) -> i32;
    fn ck_platform_size(id: u8) -> i32;
    fn ck_platform_progress() -> u8;
    fn ck_test_fail_read(id: u8);
    fn ck_test_fail_write(id: u8);
    fn ck_test_remove_record(id: u8);
    fn ck_test_corrupt_record(id: u8, offset: usize, mask: u8);
}
// The C flash model invokes these only in its serialized parent/child process.
unsafe extern "C" fn reset() {
    unsafe { core::reset::<Native>() };
    assert_eq!(unsafe { core::install::<Native>() }, 0);
}
unsafe extern "C" fn exchange(
    owner: u8,
    input: *const u8,
    len: usize,
    out: *mut u8,
    capacity: usize,
) -> i32 {
    unsafe { core::exchange::<Native>(owner, input, len, out, capacity) }
}
fn record(text: &str) -> u8 {
    Record::from_id(text.parse().unwrap()).unwrap().id()
}
fn decode(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2) && text.len() / 2 <= APDU_BYTES);
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(text, "{byte:02x}").unwrap();
    }
    text
}
fn main() {
    unsafe { ck_test_flash_init(reset, exchange) };
    assert_eq!(unsafe { core::install::<Native>() }, 0);
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let c_line = CString::new(line.as_str()).unwrap();
        if unsafe { ck_test_flash_command(c_line.as_ptr()) } != 0 {
            unsafe { libc::fflush(std::ptr::null_mut()) };
            continue;
        }
        let mut fields = line.split_whitespace();
        let command = fields.next().unwrap_or("");
        let mut buffer = [0; APDU_BYTES];
        let response = match command {
            "POLL" => {
                for _ in 0..fields.next().unwrap().parse::<u32>().unwrap() {
                    unsafe {
                        ck_platform_progress();
                        Native::sample_presence();
                    }
                }
                "9000".into()
            }
            "RECORD" => {
                let arguments = line.strip_prefix("RECORD ").unwrap();
                let (id, hex) = arguments
                    .split_once(' ')
                    .map_or((arguments, None), |(id, hex)| (id, Some(hex)));
                let id = record(id);
                if let Some(hex) = hex {
                    let bytes = decode(hex.trim());
                    assert_eq!(
                        unsafe { ck_platform_write(id, bytes.as_ptr(), bytes.len()) },
                        bytes.len() as i32
                    );
                    "9000".into()
                } else {
                    let n = unsafe { ck_platform_read(id, buffer.as_mut_ptr(), buffer.len()) };
                    assert!(n >= 0);
                    format!("{}9000", encode(&buffer[..n as usize]))
                }
            }
            "FAIL_READ" | "FAIL_WRITE" | "REMOVE" => {
                let id = record(fields.next().unwrap());
                unsafe {
                    match command {
                        "FAIL_READ" => ck_test_fail_read(id),
                        "FAIL_WRITE" => ck_test_fail_write(id),
                        _ => ck_test_remove_record(id),
                    }
                }
                "9000".into()
            }
            "CORRUPT" => {
                unsafe {
                    ck_test_corrupt_record(
                        record(fields.next().unwrap()),
                        fields.next().unwrap().parse().unwrap(),
                        fields.next().unwrap().parse().unwrap(),
                    )
                };
                "9000".into()
            }
            "SIZE" => format!(
                "{:08x}",
                unsafe { ck_platform_size(record(fields.next().unwrap())) } as u32
            ),
            "RESET" | "TRY_RESET" => {
                unsafe { core::reset::<Native>() };
                let status = unsafe { core::install::<Native>() };
                if command == "RESET" {
                    assert_eq!(status, 0);
                    "9000".into()
                } else {
                    format!("{:08x}", status as u32)
                }
            }
            "TOUCH" => {
                let n = unsafe {
                    core::touch::<Native>(
                        fields.next().unwrap().parse().unwrap(),
                        buffer.as_mut_ptr(),
                        buffer.len(),
                    )
                };
                assert!(n >= 0);
                encode(&buffer[..n as usize])
            }
            _ => {
                let input = decode(line.trim());
                buffer[..input.len()].copy_from_slice(&input);
                let n = unsafe {
                    ck_test_flash_exchange(
                        OWNER_CCID,
                        buffer.as_ptr(),
                        input.len(),
                        buffer.as_mut_ptr(),
                        buffer.len(),
                    )
                };
                assert!(n >= 0);
                encode(&buffer[..n as usize])
            }
        };
        writeln!(output, "{response}").unwrap();
        output.flush().unwrap();
    }
}
