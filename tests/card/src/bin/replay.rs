// SPDX-License-Identifier: Apache-2.0
//! Line protocol for independently comparing APDU responses with hardware.
use canokey_ports::Record;
use canokey_test_card::Card;
use std::fmt::Write as _;
use std::{
    fs::File,
    io::{self, BufRead, Write},
    os::fd::FromRawFd,
};
const MAX_APDU_BYTES: usize = 4096;
const MAX_LINE_BYTES: usize = MAX_APDU_BYTES * 2 + 5;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_CHAINS: usize = 1024;
const SHORT_RESPONSE_BYTES: usize = 288;
// ISO 7816 GET RESPONSE, short Le=0 (256 bytes).
const GET_RESPONSE: &[u8] = &[0x00, 0xc0, 0x00, 0x00, 0x00];

fn exchange(card: &mut Card, mut input: &[u8], drain: bool) -> Result<String, &'static str> {
    let mut complete = Vec::new();
    let mut short = [0; SHORT_RESPONSE_BYTES];
    for _ in 0..MAX_CHAINS {
        let n = card
            .exchange(input, &mut short)
            .filter(|&n| n >= 2)
            .ok_or("exchange-failed")?;
        let end = n - 2;
        let status = u16::from_be_bytes([short[end], short[end + 1]]);
        if complete.len() + end > MAX_RESPONSE_BYTES {
            return Err("response-too-long");
        }
        complete.extend_from_slice(&short[..end]);
        if !drain || status & 0xff00 != 0x6100 {
            let mut response = format!("RESP {status:04X}");
            for byte in complete {
                write!(response, "{byte:02X}").unwrap();
            }
            return Ok(response);
        }
        input = GET_RESPONSE;
    }
    Err("response-chain-limit")
}
fn process(card: &mut Card, line: &[u8]) -> Result<String, &'static str> {
    let (line, drain) = line
        .strip_prefix(b"!RAW ")
        .map_or((line, true), |line| (line, false));
    if line.starts_with(b"!") {
        match line {
            b"!POWEROFF" => card.slot_power(),
            b"!RESET" => card.reset(),
            _ => {
                let (argument, read) = if let Some(id) = line.strip_prefix(b"!FAIL_READ ") {
                    (id, true)
                } else if let Some(id) = line.strip_prefix(b"!FAIL_WRITE ") {
                    (id, false)
                } else {
                    return Err("unknown-control");
                };
                let id = std::str::from_utf8(argument)
                    .ok()
                    .and_then(|s| s.parse::<u8>().ok())
                    .ok_or("unknown-control")?;
                if read {
                    card.records.fail_read = Record::from_id(id);
                } else {
                    card.records.fail_write = Record::from_id(id);
                }
            }
        }
        return Ok("OK".into());
    }
    if !line.len().is_multiple_of(2) {
        return Err("invalid-hex");
    }
    if line.len() / 2 > MAX_APDU_BYTES {
        return Err("too-long");
    }
    let input = line
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
                .ok_or("invalid-hex")
        })
        .collect::<Result<Vec<_>, _>>()?;
    exchange(card, &input, drain)
}
// Limit allocations even when a peer sends an unbounded line; drain it to keep
// the next command synchronized, just as the previous replay executable did.
fn read_line(input: &mut impl BufRead, line: &mut Vec<u8>) -> io::Result<Option<bool>> {
    line.clear();
    let mut too_long = false;
    loop {
        let bytes = input.fill_buf()?;
        if bytes.is_empty() {
            return Ok((!line.is_empty() || too_long).then_some(too_long));
        }
        let end = bytes.iter().position(|&b| b == b'\n');
        let n = end.unwrap_or(bytes.len());
        if line.len() + n > MAX_LINE_BYTES {
            too_long = true;
        }
        if !too_long {
            line.extend_from_slice(&bytes[..n]);
        }
        input.consume(n + usize::from(end.is_some()));
        if end.is_some() {
            return Ok(Some(too_long));
        }
    }
}
fn run() -> io::Result<()> {
    // Preserve a protocol descriptor before native crypto diagnostics redirect
    // stdout to stderr. File owns only the duplicated descriptor.
    let fd = unsafe { libc::dup(libc::STDOUT_FILENO) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let protocol = unsafe { File::from_raw_fd(fd) };
    if unsafe { libc::dup2(libc::STDERR_FILENO, libc::STDOUT_FILENO) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut output = io::BufWriter::new(protocol);
    // All native crypto use stays on this thread.
    let mut card = unsafe { Card::new() };
    if !card.install() {
        writeln!(output, "ERROR fabrication-failed")?;
        output.flush()?;
        return Err(io::Error::other("fabrication-failed"));
    }
    writeln!(output, "READY")?;
    output.flush()?;
    let mut input = io::stdin().lock();
    let mut line = Vec::new();
    while let Some(too_long) = read_line(&mut input, &mut line)? {
        if line.is_empty() && !too_long {
            continue;
        }
        let response = if too_long {
            Err("too-long")
        } else {
            process(&mut card, &line)
        };
        match response {
            Ok(text) => writeln!(output, "{text}")?,
            Err(error) => writeln!(output, "ERROR {error}")?,
        }
        output.flush()?;
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("APDU replay: {error}");
        std::process::exit(1);
    }
}
