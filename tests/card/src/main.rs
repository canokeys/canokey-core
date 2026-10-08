// SPDX-License-Identifier: Apache-2.0
//! In-process Rust applet fixture for the independent Python protocol oracles.
#[cfg(feature = "ctap")]
use canokey_ports::Device;
use canokey_ports::{Record, Storage};
use canokey_test_card::Card;
use std::io::{self, BufRead, Write};
const APDU_BYTES: usize = 512;
fn record(text: &str) -> Record {
    Record::from_id(text.parse().unwrap()).unwrap()
}
fn decode(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2) && text.len() / 2 <= APDU_BYTES);
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn main() {
    // Native crypto is serialized in this single-threaded fixture.
    let mut card = unsafe { Card::new() };
    assert!(card.install());
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let mut fields = line.split_whitespace();
        let command = fields.next().unwrap_or("");
        let mut buffer = [0; APDU_BYTES];
        let response = match command {
            "RECORD" => {
                let arguments = line.strip_prefix("RECORD ").unwrap();
                let (id, hex) = arguments
                    .split_once(' ')
                    .map_or((arguments, None), |(id, hex)| (id, Some(hex)));
                let id = record(id);
                if let Some(hex) = hex {
                    card.records.replace(id, &decode(hex.trim())).unwrap();
                    b"9000".to_vec()
                } else {
                    let n = card.records.load(id, &mut buffer).unwrap();
                    format!("{}9000", encode(&buffer[..n])).into_bytes()
                }
            }
            "FAIL_READ" => {
                card.records.fail_read = Some(record(fields.next().unwrap()));
                b"9000".to_vec()
            }
            "FAIL_WRITE" => {
                card.records.fail_write = Some(record(fields.next().unwrap()));
                b"9000".to_vec()
            }
            "CORRUPT" => {
                card.records.corrupt(
                    record(fields.next().unwrap()),
                    fields.next().unwrap().parse().unwrap(),
                    fields.next().unwrap().parse().unwrap(),
                );
                b"9000".to_vec()
            }
            "REMOVE" => {
                card.records.discard(record(fields.next().unwrap()));
                b"9000".to_vec()
            }
            "SIZE" => {
                let size = card
                    .records
                    .size(record(fields.next().unwrap()))
                    .map_or(u32::MAX, |n| n);
                format!("{size:08x}").into_bytes()
            }
            #[cfg(feature = "ctap")]
            "POLL" => {
                for _ in 0..fields.next().unwrap().parse::<u32>().unwrap() {
                    card.clock.progress();
                    card.clock.sample();
                }
                b"9000".to_vec()
            }
            "RESET" | "TRY_RESET" => {
                card.reset();
                let installed = card.install();
                if command == "RESET" {
                    assert!(installed);
                    b"9000".to_vec()
                } else {
                    format!("{:08x}", if installed { 0 } else { u32::MAX }).into_bytes()
                }
            }
            "TOUCH" => {
                #[cfg(feature = "pass")]
                let n = card
                    .touch(fields.next().unwrap().parse().unwrap(), &mut buffer)
                    .unwrap();
                #[cfg(not(feature = "pass"))]
                let n = 0;
                encode(&buffer[..n]).into_bytes()
            }
            _ => {
                let input = decode(line.trim());
                let n = card.exchange(&input, &mut buffer).unwrap();
                encode(&buffer[..n]).into_bytes()
            }
        };
        output.write_all(&response).unwrap();
        writeln!(output).unwrap();
        output.flush().unwrap();
    }
}
fn encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(text, "{byte:02x}").unwrap();
    }
    text
}
