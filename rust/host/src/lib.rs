// SPDX-License-Identifier: Apache-2.0
//! Single-threaded virtual hardware for the production Rust core. Callbacks may
//! maintain packet state but never reenter applet execution or hold HOST borrows.
#[cfg(target_os = "none")]
compile_error!("the virtual-card host must never be linked into firmware");
use canokey_rust_ffi as _;
use std::{
    io,
    net::UdpSocket,
    path::Path,
    sync::Mutex,
    time::{Duration, Instant},
};
mod pcsc;
mod storage;
use storage::Storage;
unsafe extern "C" {
    fn ck_core_install() -> i32;
    fn ck_core_exchange(
        owner: u8,
        input: *const u8,
        len: usize,
        out: *mut u8,
        capacity: usize,
    ) -> i32;
    fn ck_core_reset();
    fn ck_core_presence_sample();
    fn CTAPHID_Loop(wait: u8) -> u8;
    fn CTAPHID_OutEvent(data: *const u8) -> u8;
    fn CTAPHID_RxCanAccept() -> u8;
    fn ck_hid_packet_reset();
    fn ck_hid_executing() -> u8;
    fn ck_hid_progress() -> u8;
    fn ck_host_stopping() -> i32;
}
struct Host {
    storage: Storage,
    socket: Option<UdpSocket>,
    pcsc_lun: Option<u64>,
    powered: bool,
    boot: Instant,
    ticks: Option<u32>,
    nfc: bool,
    led: bool,
    gesture: Gesture,
    reboot: bool,
    pke: [u8; 3072],
    owner: u8,
}
// Entry serialization is separate from callback data. Never hold HOST across
// a core call: a callback may lock HOST, but never recursively lock ENTRY.
static ENTRY: Mutex<()> = Mutex::new(());
static HOST: Mutex<Option<Host>> = Mutex::new(None);
fn host<T>(f: impl FnOnce(&mut Host) -> T) -> T {
    f(HOST.lock().unwrap().as_mut().expect("host not initialized"))
}
fn result(r: Result<usize, i32>) -> i32 {
    r.map_or_else(|e| e, |n| n as i32)
}
fn status(r: Result<(), i32>) -> i32 {
    r.map_or_else(|e| e, |()| 0)
}
unsafe fn input<'a>(p: *const u8, n: usize) -> &'a [u8] {
    if n == 0 {
        &[]
    } else {
        assert!(!p.is_null() && n <= isize::MAX as usize);
        unsafe { std::slice::from_raw_parts(p, n) }
    }
}
unsafe fn output<'a>(p: *mut u8, n: usize) -> &'a mut [u8] {
    if n == 0 {
        &mut []
    } else {
        assert!(!p.is_null() && n <= isize::MAX as usize);
        unsafe { std::slice::from_raw_parts_mut(p, n) }
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn ck_platform_size(id: u8) -> i32 {
    result(host(|h| h.storage.size(id)))
}
#[unsafe(no_mangle)]
unsafe extern "C" fn ck_platform_read(id: u8, p: *mut u8, n: usize) -> i32 {
    result(host(|h| {
        h.storage.read(id, 0, unsafe { output(p, n) }, true)
    }))
}
#[unsafe(no_mangle)]
unsafe extern "C" fn ck_platform_read_at(id: u8, off: u32, p: *mut u8, n: usize) -> i32 {
    result(host(|h| {
        h.storage
            .read(id, off as usize, unsafe { output(p, n) }, false)
    }))
}
#[unsafe(no_mangle)]
unsafe extern "C" fn ck_platform_write(id: u8, p: *const u8, n: usize) -> i32 {
    result(host(|h| h.storage.write(id, unsafe { input(p, n) })))
}
#[unsafe(no_mangle)]
unsafe extern "C" fn ck_platform_write_at(id: u8, off: u32, p: *const u8, n: usize) -> i32 {
    result(host(|h| {
        h.storage.patch(id, off as usize, unsafe { input(p, n) })
    }))
}
#[unsafe(no_mangle)]
unsafe extern "C" fn ck_platform_resize(id: u8, n: u32) -> i32 {
    status(host(|h| h.storage.resize(id, n as usize)))
}
#[unsafe(no_mangle)]
unsafe extern "C" fn ck_platform_stage(op: u8, id: u8, p: *const u8, n: usize) -> i32 {
    status(host(|h| h.storage.stage(op, id, unsafe { input(p, n) })))
}
#[unsafe(no_mangle)]
unsafe extern "C" fn ck_platform_usage(used: *mut u32, total: *mut u32) -> i32 {
    status(host(|h| h.storage.usage()).map(|(u, t)| unsafe {
        used.write(u);
        total.write(t)
    }))
}
#[unsafe(no_mangle)]
extern "C" fn ck_platform_has_space(bytes: u32, reserve: u32) -> i32 {
    host(|h| h.storage.usage()).map_or_else(
        |e| e,
        |(u, t)| i32::from(t - u >= reserve && t - u - reserve >= bytes),
    )
}
#[unsafe(no_mangle)]
unsafe extern "C" fn platform_config_page_read(off: usize, p: *mut u8, n: usize) -> i32 {
    status(host(|h| {
        h.storage.config_read(off, unsafe { output(p, n) })
    }))
}
#[unsafe(no_mangle)]
unsafe extern "C" fn platform_config_page_write(p: *const u8, n: usize) -> i32 {
    status(host(|h| h.storage.config_write(unsafe { input(p, n) })))
}
#[unsafe(no_mangle)]
extern "C" fn device_get_tick() -> u32 {
    host(|h| {
        h.ticks
            .unwrap_or_else(|| h.boot.elapsed().as_millis() as u32)
    })
}
#[unsafe(no_mangle)]
extern "C" fn ck_platform_now() -> u32 {
    device_get_tick()
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
#[unsafe(no_mangle)]
extern "C" fn is_nfc() -> u8 {
    host(|h| u8::from(h.nfc))
}
#[unsafe(no_mangle)]
extern "C" fn ck_platform_led(on: u8) {
    host(|h| h.led = on != 0);
}
enum Gesture {
    Idle,
    Released(Instant),
    Pressed(Instant),
    Cooldown(Instant),
}
#[unsafe(no_mangle)]
extern "C" fn ck_platform_touched() -> u8 {
    if host(|h| h.ticks.is_some()) {
        return 0;
    }
    let count = std::fs::read_to_string("/tmp/canokey-test-up")
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .unwrap_or(-1);
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
            Gesture::Pressed(at) if at.elapsed() >= Duration::from_millis(40) => {
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
    u8::from(pressed)
}
#[unsafe(no_mangle)]
extern "C" fn ck_platform_progress() -> u8 {
    receive();
    if host(|h| h.reboot) || unsafe { ck_host_stopping() != 0 } {
        return 0;
    }
    let result = if unsafe { ck_hid_executing() != 0 } {
        unsafe { ck_hid_progress() }
    } else {
        1
    };
    std::thread::sleep(Duration::from_millis(1));
    result
}
#[unsafe(no_mangle)]
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
extern "C" fn ck_usb_configured() -> u8 {
    host(|h| u8::from(h.socket.is_some() && !h.reboot))
}
#[unsafe(no_mangle)]
extern "C" fn ck_usb_tx_idle(ep: u8) -> u8 {
    assert_eq!(ep, 0x82);
    1
}
#[unsafe(no_mangle)]
extern "C" fn ck_usb_receive(ep: u8) {
    assert_eq!(ep, 2);
}
#[unsafe(no_mangle)]
unsafe extern "C" fn ck_usb_submit(ep: u8, p: *const u8, n: u16, zlp: u8) -> i32 {
    assert_eq!((ep, n, zlp), (0x82, 64, 0));
    let bytes = unsafe { input(p, n as usize) };
    host(|h| {
        h.socket
            .as_ref()
            .expect("UDP endpoint without socket")
            .send_to(bytes, "127.0.0.1:7112")
            .map_or(0, |n| i32::from(n == 64))
    })
}
#[unsafe(no_mangle)]
extern "C" fn pke_buffer_size() -> usize {
    3072
}
#[unsafe(no_mangle)]
extern "C" fn pke_buffer_acquire(owner: u8) -> i32 {
    host(|h| {
        if owner == 0 || (h.owner != 0 && h.owner != owner) {
            -1
        } else {
            h.owner = owner;
            0
        }
    })
}
#[unsafe(no_mangle)]
extern "C" fn pke_buffer_release(owner: u8) -> i32 {
    host(|h| {
        if owner == 0 || h.owner != owner {
            -1
        } else {
            h.owner = 0;
            0
        }
    })
}
#[unsafe(no_mangle)]
extern "C" fn pke_buffer_clear() -> i32 {
    host(|h| {
        h.pke.fill(0);
        0
    })
}
#[unsafe(no_mangle)]
unsafe extern "C" fn pke_buffer_read(off: usize, p: *mut u8, n: usize) -> i32 {
    host(|h| {
        if h.owner == 0 || off > h.pke.len() || n > h.pke.len() - off {
            return -1;
        }
        unsafe { output(p, n) }.copy_from_slice(&h.pke[off..off + n]);
        0
    })
}
#[unsafe(no_mangle)]
unsafe extern "C" fn pke_buffer_write(off: usize, p: *const u8, n: usize) -> i32 {
    host(|h| {
        if h.owner == 0 || off > h.pke.len() || n > h.pke.len() - off {
            return -1;
        }
        h.pke[off..off + n].copy_from_slice(unsafe { input(p, n) });
        0
    })
}
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
    if unsafe { CTAPHID_RxCanAccept() == 0 } || host(|h| h.reboot || h.socket.is_none()) {
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
        assert_ne!(unsafe { CTAPHID_OutEvent(data.as_ptr()) }, 0);
    }
}
fn exchange(command: &[u8]) -> Vec<u8> {
    let mut out = [0; 258];
    let n = unsafe {
        ck_core_exchange(
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
    unsafe { ck_core_reset() };
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
        pcsc_lun: None,
        powered: false,
        boot: Instant::now(),
        ticks: None,
        nfc: false,
        led: false,
        gesture: Gesture::Idle,
        reboot: false,
        pke: [0; 3072],
        owner: 0,
    });
    if touch_file && (host(|h| h.socket.is_some()) || !Path::new("/tmp/canokey-test-up").exists()) {
        std::fs::write("/tmp/canokey-test-up", "0\n")?;
    }
    if unsafe { ck_core_install() } != 0 {
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
        CTAPHID_Loop(0);
    }
    println!("Rust virtual HID ready on UDP 8111 (responses: 127.0.0.1:7112)");
    while unsafe { ck_host_stopping() == 0 } {
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
                CTAPHID_Loop(0);
                assert_eq!(ck_core_install(), 0);
            }
            println!("MAGIC REBOOT command received!");
        }
        unsafe {
            ck_core_presence_sample();
            CTAPHID_Loop(0);
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    unsafe {
        ck_hid_packet_reset();
        CTAPHID_Loop(0);
    }
    HOST.lock().unwrap().take();
    Ok(())
}
#[unsafe(no_mangle)]
pub extern "C" fn ck_host_udp_main() -> i32 {
    let _entry = ENTRY.lock().unwrap();
    match run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("Rust virtual HID: {e}");
            1
        }
    }
}
