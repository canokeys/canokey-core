// SPDX-License-Identifier: Apache-2.0
//! Const USB 2.0 / HID 1.11 / CCID 1.10 composition, retained in product Flash.
use super::CTAP_HID;

const CONFIGURATION_BYTES: usize = 9;
const INTERFACE_BYTES: usize = 9;
const ENDPOINT_BYTES: usize = 7;
const CCID_CLASS_BYTES: usize = 54;
const HID_DESCRIPTOR_BYTES: usize = 9;
const ENDPOINTS_PER_INTERFACE: usize = 2;
const HID_INTERFACE_BYTES: usize =
    INTERFACE_BYTES + HID_DESCRIPTOR_BYTES + ENDPOINTS_PER_INTERFACE * ENDPOINT_BYTES;
const CCID_INTERFACE_BYTES: usize =
    INTERFACE_BYTES + CCID_CLASS_BYTES + ENDPOINTS_PER_INTERFACE * ENDPOINT_BYTES;
const DESCRIPTOR_CONFIGURATION: u8 = 0x02;
const DESCRIPTOR_INTERFACE: u8 = 0x04;
const DESCRIPTOR_ENDPOINT: u8 = 0x05;
const TRANSFER_BULK: u8 = 0x02;
const TRANSFER_INTERRUPT: u8 = 0x03;
const CLASS_HID: u8 = 0x03;
const CLASS_CCID: u8 = 0x0b;
const CLASS_VENDOR: u8 = 0xff;

/// Endpoint addresses are wire addresses, including the IN direction bit.
#[derive(Clone, Copy)]
pub struct Endpoints {
    pub input: u8,
    pub output: u8,
    pub packet_bytes: u16,
}
#[derive(Clone, Copy)]
pub struct Hid {
    pub descriptor: &'static [u8],
    pub endpoints: Endpoints,
}
#[derive(Clone, Copy)]
pub struct Composition {
    pub ctap: Option<Endpoints>,
    pub webusb_string: Option<u8>,
    pub ccid: Endpoints,
    pub maximum_ccid_message_bytes: u16,
    pub keyboard: Option<Hid>,
}
impl Composition {
    pub const fn count(self) -> u8 {
        1 + self.ctap.is_some() as u8
            + self.webusb_string.is_some() as u8
            + self.keyboard.is_some() as u8
    }
    pub const fn webusb(self) -> u8 {
        self.ctap.is_some() as u8
    }
    pub const fn ccid(self) -> u8 {
        self.webusb() + self.webusb_string.is_some() as u8
    }
    pub const fn keyboard(self) -> u8 {
        self.ccid() + 1
    }
}

pub struct Configuration<const CAPACITY: usize> {
    bytes: [u8; CAPACITY],
    length: usize,
}
impl<const CAPACITY: usize> Configuration<CAPACITY> {
    pub const fn new(composition: Composition) -> Self {
        let length = CONFIGURATION_BYTES
            + CCID_INTERFACE_BYTES
            + HID_INTERFACE_BYTES
                * (composition.ctap.is_some() as usize + composition.keyboard.is_some() as usize)
            + INTERFACE_BYTES * composition.webusb_string.is_some() as usize;
        assert!(length <= CAPACITY && length <= u16::MAX as usize);
        let total = (length as u16).to_le_bytes();
        let mut descriptor = Self {
            bytes: [0x00; CAPACITY],
            length: 0,
        };
        // USB 2.0 §9.6.3: length/type, total LE, interfaces, configuration,
        // string, bus-powered attributes, bMaxPower in units of 2 mA (100 mA).
        descriptor.append(&[
            0x09,
            DESCRIPTOR_CONFIGURATION,
            total[0],
            total[1],
            composition.count(),
            0x01,
            0x00,
            0x80,
            0x32,
        ]);
        if let Some(endpoints) = composition.ctap {
            descriptor.hid(0x00, CTAP_HID, endpoints);
        }
        if let Some(string) = composition.webusb_string {
            descriptor.append(&[
                0x09,
                DESCRIPTOR_INTERFACE,
                composition.webusb(),
                0x00,
                0x00,
                CLASS_VENDOR,
                CLASS_VENDOR,
                CLASS_VENDOR,
                string,
            ]);
        }
        descriptor.append(&[
            0x09,
            DESCRIPTOR_INTERFACE,
            composition.ccid(),
            0x00,
            0x02,
            CLASS_CCID,
            0x00,
            0x00,
            0x00,
        ]);
        descriptor.ccid(composition.maximum_ccid_message_bytes);
        descriptor.endpoints(composition.ccid, TRANSFER_BULK, 0x00);
        if let Some(keyboard) = composition.keyboard {
            descriptor.hid(
                composition.keyboard(),
                keyboard.descriptor,
                keyboard.endpoints,
            );
        }
        assert!(descriptor.length == length);
        descriptor
    }
    const fn hid(&mut self, interface: u8, hid: &[u8], endpoints: Endpoints) {
        // USB 2.0 §9.6.5: number/alternate/endpoints/class/subclass/protocol/string.
        assert!(hid.len() == HID_DESCRIPTOR_BYTES);
        self.append(&[
            0x09,
            DESCRIPTOR_INTERFACE,
            interface,
            0x00,
            0x02,
            CLASS_HID,
            0x00,
            0x00,
            0x00,
        ]);
        self.append(hid);
        self.endpoints(endpoints, TRANSFER_INTERRUPT, 0x05);
    }
    const fn endpoints(&mut self, endpoints: Endpoints, attributes: u8, interval: u8) {
        let packet = endpoints.packet_bytes.to_le_bytes();
        // USB 2.0 §9.6.6: length/type/address/attributes/packet size LE/interval.
        // Interrupt polling uses 5 ms; full-speed bulk ignores bInterval.
        self.append(&[
            0x07,
            DESCRIPTOR_ENDPOINT,
            endpoints.input,
            attributes,
            packet[0],
            packet[1],
            interval,
            0x07,
            DESCRIPTOR_ENDPOINT,
            endpoints.output,
            attributes,
            packet[0],
            packet[1],
            interval,
        ]);
    }
    const fn ccid(&mut self, maximum_message_bytes: u16) {
        // CCID 1.10 §5.1: one slot, T=1, IFSD254, automatic negotiation,
        // short APDU exchange (dwFeatures=0x000200FE), no PIN pad or LCD.
        // Clocks are kHz and data rates bps; the limit includes the CCID header.
        self.append(&[
            0x36,
            0x21,
            0x10,
            0x01, // Length54, CCID type, bcdCCID1.10.
            0x00,
            0x07, // Max slot0; 5V/3V/1.8V supported.
            0x02,
            0x00,
            0x00,
            0x00, // dwProtocols: T=1.
            0xa0,
            0x0f,
            0x00,
            0x00, // Default clock4000 kHz.
            0xa0,
            0x0f,
            0x00,
            0x00, // Maximum clock4000 kHz.
            0x00, // No explicit supported-clock table.
            0x00,
            0xb0,
            0x04,
            0x00, // Default data rate307200 bps.
            0x00,
            0xb0,
            0x04,
            0x00, // Maximum data rate307200 bps.
            0x00, // No explicit supported-data-rate table.
            0xfe,
            0x00,
            0x00,
            0x00, // dwMaxIFSD254.
            0x00,
            0x00,
            0x00,
            0x00, // No synchronous protocols.
            0x00,
            0x00,
            0x00,
            0x00, // No mechanical features.
            0xfe,
            0x00,
            0x02,
            0x00, // dwFeatures.
            maximum_message_bytes as u8,
            (maximum_message_bytes >> 8) as u8,
            0x00,
            0x00, // dwMaxCCIDMessageLength.
            0xff,
            0xff, // bClassGetResponse / bClassEnvelope.
            0x00,
            0x00, // wLcdLayout: no display.
            0x00,
            0x01, // No PIN-pad verification; one busy slot.
        ]);
    }
    const fn append(&mut self, bytes: &[u8]) {
        let mut index = 0;
        while index < bytes.len() {
            self.bytes[self.length] = bytes[index];
            self.length += 1;
            index += 1;
        }
    }
    pub fn copy_into(&self, out: &mut [u8; CAPACITY]) -> usize {
        out[..self.length].copy_from_slice(&self.bytes[..self.length]);
        self.length
    }
}

/// USB 2.0 §9.6.1: per-interface classes and one configuration. Numeric IDs and
/// bcdDevice are little-endian; serial is a product-selected string index.
pub const fn device(
    vendor: u16,
    product: u16,
    release: u16,
    ep0_bytes: u8,
    serial: u8,
) -> [u8; 18] {
    let vendor = vendor.to_le_bytes();
    let product = product.to_le_bytes();
    let release = release.to_le_bytes();
    [
        0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, ep0_bytes, vendor[0], vendor[1], product[0],
        product[1], release[0], release[1], 0x01, 0x02, serial, 0x01,
    ]
}
