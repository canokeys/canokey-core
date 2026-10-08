// SPDX-License-Identifier: Apache-2.0
//! Single-threaded virtual hardware for the production Rust core. Callbacks may
//! maintain packet state but never reenter applet execution or hold HOST borrows.
#[cfg(target_os = "none")]
compile_error!("the virtual-card host must never be linked into firmware");
use canokey_rust_ffi::{
    ck_hid_executing, ck_hid_packet_reset, ck_hid_progress,
    composition::{core, hid},
    out_event, rx_can_accept,
};
use std::{
    io,
    net::UdpSocket,
    path::Path,
    sync::{
        Mutex,
        atomic::{AtomicI32, Ordering},
    },
    time::{Duration, Instant},
};
mod backend;
#[cfg(feature = "pcsc-plugin")]
mod ifd;
#[cfg(feature = "pcsc-plugin")]
mod pcsc;
mod storage;
use backend::{HostProvider, presence_sample};
#[cfg(feature = "usbip")]
mod usbip;
use canokey_protocol::apdu as apdu_wire;
#[cfg(not(feature = "usbip"))]
use canokey_protocol::usb;
use storage::Storage;
// CIU PKE register file: 48 registers of 64 bytes each.
const PKE_BYTES: usize = 48 * 64;
static STOPPED: AtomicI32 = AtomicI32::new(0);
pub fn stopping_signal() -> i32 {
    STOPPED.load(Ordering::Relaxed)
}
#[cfg(feature = "udp-binary")]
pub fn install_signal_handlers() -> io::Result<()> {
    extern "C" fn stop(signal: libc::c_int) {
        STOPPED.store(signal, Ordering::Relaxed);
    }
    for signal in [libc::SIGTERM, libc::SIGINT] {
        // Only a lock-free atomic store runs in the signal handler.
        if unsafe { libc::signal(signal, stop as *const () as libc::sighandler_t) } == libc::SIG_ERR
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
struct Host {
    storage: Storage,
    socket: Option<UdpSocket>,
    #[cfg(feature = "pcsc-plugin")]
    pcsc_lun: Option<u64>,
    #[cfg(feature = "pcsc-plugin")]
    powered: bool,
    boot: Instant,
    ticks: Option<u32>,
    nfc: bool,
    led: bool,
    gesture: Gesture,
    presence: canokey_ports::Polling,
    reboot: bool,
    pke: [u8; PKE_BYTES],
    owner: u8,
}
// Entry serialization is separate from callback data. Never hold HOST across
// a core call: a callback may lock HOST, but never recursively lock ENTRY.
static ENTRY: Mutex<()> = Mutex::new(());
static HOST: Mutex<Option<Host>> = Mutex::new(None);
fn host<T>(f: impl FnOnce(&mut Host) -> T) -> T {
    f(HOST.lock().unwrap().as_mut().expect("host not initialized"))
}
#[cfg(any(feature = "pcsc-plugin", not(feature = "usbip")))]
unsafe fn input<'a>(p: *const u8, n: usize) -> &'a [u8] {
    if n == 0 {
        &[]
    } else {
        assert!(!p.is_null() && n <= isize::MAX as usize);
        unsafe { std::slice::from_raw_parts(p, n) }
    }
}
#[cfg(feature = "pcsc-plugin")]
unsafe fn output<'a>(p: *mut u8, n: usize) -> &'a mut [u8] {
    if n == 0 {
        &mut []
    } else {
        assert!(!p.is_null() && n <= isize::MAX as usize);
        unsafe { std::slice::from_raw_parts_mut(p, n) }
    }
}
#[unsafe(no_mangle)]
extern "C" fn device_get_tick() -> u32 {
    host(|h| {
        h.ticks
            .unwrap_or_else(|| h.boot.elapsed().as_millis() as u32)
    })
}
#[unsafe(no_mangle)]
extern "C" fn device_delay(ms: i32) {
    assert!(ms >= 0);
    if !host(|h| {
        if let Some(ticks) = &mut h.ticks {
            *ticks = ticks.wrapping_add(ms as u32);
            true
        } else {
            false
        }
    }) {
        std::thread::sleep(Duration::from_millis(ms as u64));
    }
}
enum Gesture {
    Idle,
    Released(Instant),
    Pressed(Instant),
    Cooldown(Instant),
}
fn touched() -> bool {
    if host(|h| h.ticks.is_some()) {
        return false;
    }
    let count = std::fs::read_to_string("/tmp/canokey-test-up")
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .unwrap_or(-1);
    // A host-only gesture duration lets CCID acceptance exercise long reset.
    let held_ms = std::fs::read_to_string("/tmp/canokey-test-touch-ms")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|duration| (1..=30_000).contains(duration))
        .unwrap_or(40);
    let (pressed, rising) = host(|h| {
        if count < 0 {
            h.gesture = Gesture::Idle;
            return (false, false);
        }
        let now = Instant::now();
        match h.gesture {
            Gesture::Idle if h.led => {
                h.gesture = Gesture::Released(now);
                (false, false)
            }
            Gesture::Released(_) if !h.led => {
                h.gesture = Gesture::Idle;
                (false, false)
            }
            Gesture::Released(at) if at.elapsed() >= Duration::from_millis(20) => {
                h.gesture = Gesture::Pressed(now);
                (true, true)
            }
            Gesture::Pressed(at) if at.elapsed() >= Duration::from_millis(held_ms) => {
                h.gesture = Gesture::Cooldown(now);
                (false, false)
            }
            Gesture::Pressed(_) => (true, false),
            Gesture::Cooldown(at) if at.elapsed() >= Duration::from_millis(20) => {
                h.gesture = Gesture::Idle;
                (false, false)
            }
            _ => (false, false),
        }
    });
    if rising {
        std::fs::write(
            "/tmp/canokey-test-up",
            format!("{}\n", count.saturating_add(1)),
        )
        .expect("write presence counter");
    }
    pressed
}
fn progress() -> bool {
    receive();
    if host(|h| h.reboot) || stopping_signal() != 0 {
        return false;
    }
    let result = if unsafe { ck_hid_executing() != 0 } {
        unsafe { ck_hid_progress() }
    } else {
        1
    };
    std::thread::sleep(Duration::from_millis(1));
    result != 0
}
#[unsafe(no_mangle)]
#[cfg(not(feature = "usbip"))]
extern "C" fn ck_ccid_idle() -> u8 {
    1
}
#[unsafe(no_mangle)]
extern "C" fn ck_usb_dcd_lock() -> u32 {
    0
}
#[unsafe(no_mangle)]
extern "C" fn ck_usb_dcd_unlock(mask: u32) {
    assert_eq!(mask, 0);
}
#[unsafe(no_mangle)]
#[cfg(not(feature = "usbip"))]
extern "C" fn ck_usb_configured() -> u8 {
    host(|h| u8::from(h.socket.is_some() && !h.reboot))
}
#[unsafe(no_mangle)]
#[cfg(not(feature = "usbip"))]
// The UDP virtual card implements only the FIDO HID endpoint.
extern "C" fn ck_usb_tx_idle(ep: u8) -> u8 {
    assert_eq!(ep, usb::EP_HID_IN);
    1
}
#[unsafe(no_mangle)]
#[cfg(not(feature = "usbip"))]
extern "C" fn ck_usb_receive(ep: u8) {
    assert_eq!(ep, usb::EP_HID);
}
#[unsafe(no_mangle)]
#[cfg(not(feature = "usbip"))]
unsafe extern "C" fn ck_usb_submit(ep: u8, p: *const u8, n: u16, zlp: u8) -> i32 {
    assert_eq!(
        (ep, n, zlp),
        (usb::EP_HID_IN, usb::DATA_PACKET_BYTES as u16, 0)
    );
    let bytes = unsafe { input(p, n as usize) };
    host(|h| {
        h.socket
            .as_ref()
            .expect("UDP endpoint without socket")
            .send_to(bytes, "127.0.0.1:7112")
            .map_or(0, |n| i32::from(n == 64))
    })
}
// Host-only UDP control datagrams share an 11-byte identifying prefix after
// their AC reboot / 99 fault-injection discriminators; not a CTAPHID command.
const REBOOT: [u8; 64] = [
    0xac, 0x10, 0x52, 0xca, 0x95, 0xe5, 0x69, 0xde, 0x69, 0xe0, 0x2e, 0xbf, 0xf3, 0x33, 0x48, 0x5f,
    0x13, 0xf9, 0xb2, 0xda, 0x34, 0xc5, 0xa8, 0xa3, 0x40, 0x52, 0x66, 0x97, 0xa9, 0xab, 0x2e, 0x0b,
    0x39, 0x4d, 0x8d, 0x04, 0x97, 0x3c, 0x13, 0x40, 0x05, 0xbe, 0x1a, 0x01, 0x40, 0xbf, 0xf6, 0x04,
    0x5b, 0xb2, 0x6e, 0xb7, 0x7a, 0x73, 0xea, 0xa4, 0x78, 0x13, 0xf6, 0xb4, 0x9a, 0x72, 0x50, 0xdc,
];
const INJECT: [u8; 12] = [
    0x99, 0x10, 0x52, 0xca, 0x95, 0xe5, 0x69, 0xde, 0x69, 0xe0, 0x2e, 0xbf,
];
fn receive() {
    // A full mailbox applies socket backpressure. Never overwrite an INIT
    // queued by execution-time resynchronization with a later UDP datagram.
    if unsafe { rx_can_accept() == 0 } || host(|h| h.reboot || h.socket.is_none()) {
        return;
    }
    let mut data = [0; 2048];
    let n = match host(|h| h.socket.as_ref().unwrap().recv(&mut data)) {
        Ok(n) => n,
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            return;
        }
        Err(e) => panic!("UDP receive: {e}"),
    };
    let data = &data[..n];
    if data == REBOOT {
        host(|h| h.reboot = true);
        unsafe { ck_hid_packet_reset() }; // invalidate execution, do not reenter CORE
    } else if data.starts_with(&INJECT) && data.len() > INJECT.len() + 2 {
        let tail = &data[INJECT.len()..];
        host(|h| h.storage.inject(tail[0], tail[1], &tail[2..]));
    } else if data.len() == 64 {
        assert_ne!(unsafe { out_event(data.as_ptr()) }, 0);
    }
}
fn exchange(command: &[u8]) -> Vec<u8> {
    let mut out = [0; apdu_wire::SHORT_REPLY_BYTES];
    let n = unsafe {
        core::exchange::<HostProvider>(
            1,
            command.as_ptr(),
            command.len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    assert!(n >= 2, "host provisioning transport error");
    out[..n as usize].to_vec()
}
fn apdu(ins: u8, p1: u8, data: &[u8]) {
    let chunks = if data.is_empty() {
        1
    } else {
        data.len().div_ceil(128)
    };
    for chunk in 0..chunks {
        let start = chunk * 128;
        let end = data.len().min(start + 128);
        let mut command = vec![if chunk + 1 < chunks { 0x10 } else { 0 }, ins, p1, 0];
        if end > start {
            command.push((end - start) as u8);
            command.extend_from_slice(&data[start..end]);
        }
        let response = exchange(&command);
        assert!(
            response.ends_with(&[0x90, 0]),
            "host provisioning {ins:02x}: {response:02x?}"
        );
    }
}
// Fresh virtual-card fixtures: SELECT ADMIN, VERIFY factory PIN, provision
// FIDO attestation key/certificate; SELECT OATH, PUT SHA1/HOTP name abc
// (six digits, secret 000102), then link that stable credential to PASS slot 1.
fn provision() {
    apdu(0xa4, 4, &[0xf0, 0, 0, 0, 0]);
    apdu(0x20, 0, b"123456");
    apdu(1, 0, include_bytes!("../fixtures/attestation.key"));
    apdu(2, 0, include_bytes!("../fixtures/attestation.der"));
    apdu(0xa4, 4, &[0xa0, 0, 0, 5, 0x27, 0x21, 1]);
    apdu(
        1,
        0,
        &[0x71, 3, b'a', b'b', b'c', 0x73, 5, 0x11, 6, 0, 1, 2],
    );
    assert_eq!(
        exchange(&[0, 0x55, 1, 1, 5, 0x71, 3, b'a', b'b', b'c']),
        [0x90, 0]
    );
    unsafe { core::reset::<HostProvider>() };
}
fn flag(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .filter(|s| !s.is_empty())
        .map_or(default, |s| s.parse::<i32>().unwrap_or(0) != 0)
}
fn initialize(socket: Option<UdpSocket>, default_path: &str) -> io::Result<()> {
    let path = std::env::var("CANOKEY_VIRT_LFS_ROOT")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default_path.into());
    initialize_storage(
        socket,
        &path,
        flag("CANOKEY_VIRT_RESET_STORAGE", true),
        true,
    )
}
fn initialize_storage(
    socket: Option<UdpSocket>,
    path: &str,
    reset: bool,
    touch_file: bool,
) -> io::Result<()> {
    let (storage, fresh) = Storage::open(Path::new(path), reset)?;
    *HOST.lock().unwrap() = Some(Host {
        storage,
        socket,
        #[cfg(feature = "pcsc-plugin")]
        pcsc_lun: None,
        #[cfg(feature = "pcsc-plugin")]
        powered: false,
        boot: Instant::now(),
        ticks: None,
        nfc: false,
        led: false,
        gesture: Gesture::Idle,
        presence: canokey_ports::Polling::new(),
        reboot: false,
        pke: [0; PKE_BYTES],
        owner: 0,
    });
    if touch_file && (host(|h| h.socket.is_some()) || !Path::new("/tmp/canokey-test-up").exists()) {
        std::fs::write("/tmp/canokey-test-up", "0\n")?;
    }
    if unsafe { core::install::<HostProvider>() } != 0 {
        return Err(io::Error::other("core installation failed"));
    }
    if fresh {
        provision();
    }
    Ok(())
}
fn run() -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:8111")?;
    socket.set_nonblocking(true)?;
    initialize(Some(socket), "/tmp/canokey-fido-hid-over-udp-lfs-root")?;
    host(|h| h.nfc = flag("CANOKEY_VIRT_NFC", false));
    unsafe {
        ck_hid_packet_reset();
        hid::poll::<HostProvider>();
    }
    println!("Rust virtual HID ready on UDP 8111 (responses: 127.0.0.1:7112)");
    while stopping_signal() == 0 {
        receive();
        if host(|h| h.reboot) {
            // All nested callbacks have unwound. Reset authorization and the
            // power-on clock while retaining durable credentials/configuration.
            let storage = host(|h| h.storage.reopen())?;
            host(|h| {
                h.storage = storage;
                h.reboot = false;
                h.boot = Instant::now();
                h.led = false;
                h.gesture = Gesture::Idle;
            });
            unsafe {
                hid::poll::<HostProvider>();
                assert_eq!(core::install::<HostProvider>(), 0);
            }
            println!("MAGIC REBOOT command received!");
        }
        unsafe {
            presence_sample();
            hid::poll::<HostProvider>();
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    unsafe {
        ck_hid_packet_reset();
        hid::poll::<HostProvider>();
    }
    HOST.lock().unwrap().take();
    Ok(())
}
pub fn run_udp() -> i32 {
    let _entry = ENTRY.lock().unwrap();
    match run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("Rust virtual HID: {e}");
            1
        }
    }
}

/// Host-only oracle driver: exercises direct Rust APIs and durable record images.
#[cfg(feature = "regression-binary")]
pub fn run_regression_driver() {
    use std::io::{BufRead, Write};
    const LUN: u64 = 0x10000;
    assert_eq!(pcsc::ck_pcsc_open(LUN), 0);
    host(|h| {
        h.powered = true;
        h.nfc = true;
    });
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let mut words = line.split_whitespace();
        let response = match words.next().unwrap_or("") {
            "TOUCH" => {
                let _entry = ENTRY.lock().unwrap();
                // PASS emits at most 33 bytes; the trailing canary catches overflow.
                let mut bytes = [0xa5; 41];
                let n = unsafe {
                    core::touch::<HostProvider>(
                        words.next().unwrap().parse().unwrap(),
                        bytes.as_mut_ptr(),
                        33,
                    )
                };
                assert_eq!(&bytes[33..], &[0xa5; 8]);
                if n < 0 {
                    "FAIL".to_owned()
                } else {
                    encode(&bytes[..n as usize])
                }
            }
            "INSTALL" => {
                let _entry = ENTRY.lock().unwrap();
                assert_eq!(unsafe { core::install::<HostProvider>() }, 0);
                "9000".to_owned()
            }
            "SLOT_POWER" => {
                let _entry = ENTRY.lock().unwrap();
                unsafe { core::slot_power::<HostProvider>() };
                "9000".to_owned()
            }
            _ => {
                assert!(line.len().is_multiple_of(2) && line.len() <= 2 * 512);
                let command: Vec<_> = line
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                    .collect();
                let mut bytes = [0; 8192];
                let mut n = 0;
                assert_eq!(
                    unsafe {
                        pcsc::ck_pcsc_transmit(
                            LUN,
                            command.as_ptr(),
                            command.len(),
                            bytes.as_mut_ptr(),
                            bytes.len(),
                            &mut n,
                        )
                    },
                    0
                );
                encode(&bytes[..n])
            }
        };
        writeln!(output, "{response}").unwrap();
        output.flush().unwrap();
    }
    assert_eq!(pcsc::ck_pcsc_close(LUN), 0);
    fn encode(bytes: &[u8]) -> String {
        use std::fmt::Write;
        let mut text = String::new();
        for byte in bytes {
            write!(text, "{byte:02x}").unwrap();
        }
        text
    }
}
