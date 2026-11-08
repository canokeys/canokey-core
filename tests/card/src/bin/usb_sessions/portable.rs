// SPDX-License-Identifier: Apache-2.0
//! Portable wire-vector adapter; reuses the actual USB/CCID composition.
use super::*;
use std::io::{self, BufRead};

pub(super) fn run() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let (operation, value) = line.split_once(' ').unwrap();
        match operation {
            "TICK" => advance(value.parse().unwrap()),
            "CCID" => {
                assert!(value.len() % 2 == 0 && !value.is_empty());
                let packet: Vec<u8> = (0..value.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
                    .collect();
                assert!(packet.len() <= PACKET_BYTES);
                assert_eq!(out(usb_wire::EP_CCID, &packet), 0);
            }
            _ => panic!("unknown portable wire operation"),
        }
        let mut response = Vec::new();
        for _ in 0..16 {
            ccid_poll();
            if !pending(usb_wire::EP_CCID) {
                break;
            }
            response.extend(packet(usb_wire::EP_CCID));
            complete(usb_wire::EP_CCID_IN);
        }
        assert!(!pending(usb_wire::EP_CCID));
        print!("WIRE ");
        for byte in response {
            print!("{byte:02x}");
        }
        println!();
    }
}
