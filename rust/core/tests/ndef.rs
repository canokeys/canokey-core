// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "ndef")]
use canokey_protocol::response::StatusWord as Sw;
use canokey_rust_core::applets::ndef::{DEFAULT_CC, Failure, File, Ndef, Store};
#[derive(Default)]
struct Disk {
    cc: Option<Vec<u8>>,
    message: Option<Vec<u8>>,
    fail_read: bool,
    fail_write: bool,
    uncertain: bool,
    reads: usize,
}
impl Disk {
    fn file(&mut self, f: File) -> &mut Option<Vec<u8>> {
        match f {
            File::Capability => &mut self.cc,
            File::Message => &mut self.message,
        }
    }
}
impl Store for Disk {
    fn size(&mut self, f: File) -> Result<usize, Failure> {
        self.file(f).as_ref().map(Vec::len).ok_or(Failure::Missing)
    }
    fn read(&mut self, f: File, offset: usize, out: &mut [u8]) -> Result<(), Failure> {
        self.reads += 1;
        if self.fail_read {
            out.fill(0);
            return Err(Failure::Io);
        }
        let bytes = self.file(f).as_ref().ok_or(Failure::Missing)?;
        out.copy_from_slice(bytes.get(offset..offset + out.len()).ok_or(Failure::Io)?);
        Ok(())
    }
    fn write(
        &mut self,
        f: File,
        offset: usize,
        input: &[u8],
        truncate: bool,
    ) -> Result<(), Failure> {
        if self.fail_write && !self.uncertain {
            return Err(Failure::Io);
        }
        let bytes = self.file(f).get_or_insert(Vec::new());
        if truncate {
            bytes.clear();
        }
        bytes.resize(bytes.len().max(offset + input.len()), 0);
        bytes[offset..offset + input.len()].copy_from_slice(input);
        if self.fail_write {
            Err(Failure::Io)
        } else {
            Ok(())
        }
    }
    fn resize(&mut self, f: File, length: usize) -> Result<(), Failure> {
        self.file(f)
            .as_mut()
            .ok_or(Failure::Missing)?
            .resize(length, 0);
        Ok(())
    }
}
#[test]
fn install_initial_uri_and_preserve_existing_content() {
    let mut d = Disk::default();
    let mut n = Ndef::new();
    n.install(false, &mut d).unwrap();
    assert_eq!(d.cc.as_deref(), Some(DEFAULT_CC.as_slice()));
    let bytes = d.message.as_ref().unwrap();
    assert_eq!(bytes.len(), 1024);
    assert_eq!(&bytes[..19], b"\x00\x11\xd1\x01\x0d\x55\x04canokeys.org");
    assert!(bytes[19..].iter().all(|&v| v == 0));
    d.message = Some(vec![1, 2, 3]);
    n.install(false, &mut d).unwrap();
    assert_eq!(&d.message.as_ref().unwrap()[..3], &[1, 2, 3]);
    assert_eq!(d.message.as_ref().unwrap().len(), 1024);
    assert!(d.message.as_ref().unwrap()[3..].iter().all(|&b| b == 0));
    n.install(true, &mut d).unwrap();
    assert_eq!(&d.message.as_ref().unwrap()[..2], &[0, 17]);
}
#[test]
fn selected_files_permissions_and_poweroff() {
    let mut d = Disk::default();
    let mut n = Ndef::new();
    n.install(false, &mut d).unwrap();
    let mut b = [0; 15];
    assert_eq!(n.read(0, &mut b, &mut d), Err(Sw::CONDITIONS_NOT_SATISFIED));
    n.select(0, 0x0c, &[0xe1, 3]).unwrap();
    n.read(0, &mut b, &mut d).unwrap();
    assert_eq!(b, DEFAULT_CC);
    assert_eq!(n.read(1, &mut b, &mut d), Err(Sw::WRONG_LENGTH));
    assert_eq!(
        n.update(0, &[0], false, &mut d),
        Err(Sw::CONDITIONS_NOT_SATISFIED)
    );
    assert_eq!(n.select(0, 0x0c, &[9, 9]), Err(Sw::FILE_NOT_FOUND));
    n.read(0, &mut b, &mut d).unwrap();
    n.select(0, 0x0c, &[0, 1]).unwrap();
    n.set_read_only(1, &mut d).unwrap();
    assert!(n.read_only(&mut d));
    assert_eq!(
        n.update(0, &[0], false, &mut d),
        Err(Sw::SECURITY_STATUS_NOT_SATISFIED)
    );
    n.set_read_only(0, &mut d).unwrap();
    n.update(1023, &[7], false, &mut d).unwrap();
    assert_eq!(
        n.update(1023, &[7, 8], false, &mut d),
        Err(Sw::WRONG_LENGTH)
    );
    n.poweroff();
    assert_eq!(n.read(0, &mut b, &mut d), Err(Sw::CONDITIONS_NOT_SATISFIED));
}
#[test]
fn chained_offsets_reset_on_read_select_and_write_failure() {
    let mut d = Disk::default();
    let mut n = Ndef::new();
    n.install(false, &mut d).unwrap();
    n.select(0, 12, &[0, 1]).unwrap();
    n.update(100, &[1, 2], true, &mut d).unwrap();
    n.update(100, &[3], false, &mut d).unwrap();
    assert_eq!(&d.message.as_ref().unwrap()[100..103], &[1, 2, 3]);
    n.update(100, &[4], true, &mut d).unwrap();
    n.read(0, &mut [0; 2], &mut d).unwrap();
    n.update(10, &[5], false, &mut d).unwrap();
    assert_eq!(d.message.as_ref().unwrap()[10], 5);
    n.update(100, &[6], true, &mut d).unwrap();
    d.fail_write = true;
    assert_eq!(
        n.update(100, &[7], true, &mut d),
        Err(Sw::UNABLE_TO_PROCESS)
    );
    d.fail_write = false;
    n.update(200, &[8], false, &mut d).unwrap();
    assert_eq!(d.message.as_ref().unwrap()[200], 8);
}
#[test]
fn uncertain_permission_commit_reloads_and_failed_load_is_closed() {
    for uncertain in [false, true] {
        let mut d = Disk::default();
        let mut n = Ndef::new();
        n.install(false, &mut d).unwrap();
        d.fail_write = true;
        d.uncertain = uncertain;
        assert_eq!(n.set_read_only(1, &mut d), Err(Sw::UNABLE_TO_PROCESS));
        d.fail_read = true;
        assert!(n.read_only(&mut d));
        d.fail_read = false;
        d.fail_write = false;
        assert_eq!(n.read_only(&mut d), uncertain);
        n.select(0, 12, &[0, 1]).unwrap();
        assert_eq!(n.update(0, &[0], false, &mut d).is_err(), uncertain);
    }
}
#[test]
fn pulled_response_reads_all_1024_bytes_without_an_object_buffer() {
    let mut d = Disk::default();
    let mut n = Ndef::new();
    n.install(false, &mut d).unwrap();
    d.message = Some((0..1024).map(|i| i as u8).collect());
    n.select(0, 12, &[0, 1]).unwrap();
    n.check_read(0, 1024, &mut d).unwrap();
    for offset in (0..1024).step_by(16) {
        let mut b = [0; 16];
        n.read(offset, &mut b, &mut d).unwrap();
        for (i, v) in b.iter().enumerate() {
            assert_eq!(*v, (offset + i) as u8);
        }
    }
    assert_eq!(n.check_read(1, 1024, &mut d), Err(Sw::WRONG_LENGTH));
    assert_eq!(n.check_read(usize::MAX, 2, &mut d), Err(Sw::WRONG_LENGTH));
}

#[test]
fn capability_cache_reload_missing_file_and_recovery() {
    let mut disk = Disk::default();
    let mut ndef = Ndef::new();
    ndef.install(false, &mut disk).unwrap();
    ndef.select(0, 12, &[0xe1, 3]).unwrap();
    let reads = disk.reads;
    let mut cc = [0; 15];
    ndef.read(0, &mut cc, &mut disk).unwrap();
    assert_eq!(cc, DEFAULT_CC);
    assert_eq!(disk.reads, reads);
    assert_eq!(ndef.set_read_only(2, &mut disk), Err(Sw::WRONG_P1P2));
    ndef.set_read_only(1, &mut disk).unwrap();
    disk.fail_write = true;
    assert_eq!(ndef.set_read_only(0, &mut disk), Err(Sw::UNABLE_TO_PROCESS));
    disk.fail_write = false;
    ndef.read(0, &mut cc, &mut disk).unwrap();
    assert_eq!(disk.reads, reads + 1);
    assert_eq!(cc[14], 0xff);
    ndef.read(0, &mut cc, &mut disk).unwrap();
    assert_eq!(disk.reads, reads + 1);
    ndef.select(0, 12, &[0, 1]).unwrap();
    ndef.read(0, &mut [0; 4], &mut disk).unwrap();
    assert_eq!(disk.reads, reads + 2);
    disk.fail_write = true;
    assert_eq!(ndef.set_read_only(0, &mut disk), Err(Sw::UNABLE_TO_PROCESS));
    disk.fail_write = false;
    disk.cc = None;
    assert!(ndef.read_only(&mut disk));
    assert_eq!(ndef.update(0, b"x", false, &mut disk), Err(Sw::UNABLE_TO_PROCESS));
    ndef.install(false, &mut disk).unwrap();
    assert!(!ndef.read_only(&mut disk));
    ndef.select(0, 12, &[0, 1]).unwrap();
    ndef.update(0, b"x", false, &mut disk).unwrap();
    ndef.check_read(512, 256, &mut disk).unwrap();
    assert_eq!(ndef.check_read(768, 300, &mut disk), Err(Sw::WRONG_LENGTH));
    assert_eq!(ndef.check_read(1023, 289, &mut disk), Err(Sw::WRONG_LENGTH));
    ndef.select(0, 12, &[0xe1, 3]).unwrap();
    assert_eq!(ndef.check_read(10, 6, &mut disk), Err(Sw::WRONG_LENGTH));
}

mod apdu {
    use super::*;
    use canokey_rust_core::{Core, Platform, ports::*};
    struct Records(Disk);
    fn file(r: Record) -> File {
        match r {
            Record::NdefCapability => File::Capability,
            Record::NdefMessage => File::Message,
            _ => panic!("foreign record"),
        }
    }
    fn error(e: Failure) -> StorageError {
        if e == Failure::Missing {
            StorageError::Missing
        } else {
            StorageError::Unavailable
        }
    }
    impl Storage for Records {
        fn load(&mut self, r: Record, out: &mut [u8]) -> Result<usize, StorageError> {
            let n = Store::size(&mut self.0, file(r)).map_err(error)?;
            let out = out.get_mut(..n).ok_or(StorageError::Unavailable)?;
            Store::read(&mut self.0, file(r), 0, out).map_err(error)?;
            Ok(n)
        }
        fn replace(&mut self, r: Record, bytes: &[u8]) -> Result<(), StorageError> {
            Store::write(&mut self.0, file(r), 0, bytes, true).map_err(error)
        }
        fn size(&mut self, r: Record) -> Result<u32, StorageError> {
            Store::size(&mut self.0, file(r))
                .map(|n| n as u32)
                .map_err(error)
        }
        fn read_at(&mut self, r: Record, offset: u32, out: &mut [u8]) -> Result<(), StorageError> {
            Store::read(&mut self.0, file(r), offset as usize, out).map_err(error)
        }
        fn replace_at(&mut self, r: Record, offset: u32, bytes: &[u8]) -> Result<(), StorageError> {
            Store::write(&mut self.0, file(r), offset as usize, bytes, false).map_err(error)
        }
        fn resize(&mut self, r: Record, length: u32) -> Result<(), StorageError> {
            Store::resize(&mut self.0, file(r), length as usize).map_err(error)
        }
    }
    struct UnusedCrypto;
    impl Crypto for UnusedCrypto {
        fn mac(&mut self, _: u8, _: &[u8], _: &[u8], _: &mut [u8; 64]) -> Result<(), CryptoError> {
            unreachable!()
        }
        fn random(&mut self, _: &mut [u8]) -> Result<(), CryptoError> {
            unreachable!()
        }
        fn hmac_sha1(&mut self, _: &[u8; 20], _: &[u8], _: &mut [u8; 20]) {
            unreachable!()
        }
    }
    struct DeviceStub;
    impl Device for DeviceStub {
        fn serial(&mut self, _: &mut [u8; 4]) {
            unreachable!()
        }
        fn now(&mut self) -> u32 {
            0
        }
        fn touched(&mut self) -> bool {
            false
        }
        fn progress(&mut self) -> bool {
            true
        }
        fn led(&mut self, _: bool) {}
    }
    struct Wipe;
    impl Memory for Wipe {
        fn wipe(&self, bytes: &mut [u8]) {
            bytes.fill(0);
        }
    }
    fn exchange(core: &mut Core, p: &mut Platform<'_>, bytes: &[u8]) -> Vec<u8> {
        let reply = core.receive(1, bytes, p);
        let mut out = [0; 258];
        let n = core.transmit(reply, &mut out, p).unwrap();
        out[..n].to_vec()
    }
    #[test]
    fn actual_registry_selection_chained_updates_and_streamed_read() {
        let mut records = Records(Disk::default());
        let mut crypto = UnusedCrypto;
        let mut device = DeviceStub;
        let mut p = Platform {
            storage: &mut records,
            crypto: &mut crypto,
            device: &mut device,
            memory: &Wipe,
        };
        canokey_rust_core::applets::ndef::Applet::install(false, &mut p).unwrap();
        let mut core = Core::new();
        let select = [0, 0xa4, 4, 0, 7, 0xd2, 0x76, 0, 0, 0x85, 1, 1];
        assert_eq!(exchange(&mut core, &mut p, &select), [0x90, 0]);
        assert_eq!(
            exchange(&mut core, &mut p, &[0, 0xa4, 0, 12, 2, 0xe1, 3]),
            [0x90, 0]
        );
        let cc = exchange(&mut core, &mut p, &[0, 0xb0, 0, 0, 15]);
        assert_eq!(&cc[..15], &DEFAULT_CC);
        assert_eq!(&cc[15..], &[0x90, 0]);
        assert_eq!(
            exchange(&mut core, &mut p, &[0, 0xa4, 0, 12, 2, 0, 1]),
            [0x90, 0]
        );
        assert_eq!(
            exchange(&mut core, &mut p, &[0x10, 0xd6, 0, 20, 3, 0x11, 0x22, 0x33]),
            [0x90, 0]
        );
        assert_eq!(
            exchange(&mut core, &mut p, &[0, 0xd6, 3, 0xff, 2, 0x44, 0x55]),
            [0x90, 0]
        );
        assert_eq!(
            exchange(&mut core, &mut p, &[0, 0xb0, 0, 20, 5]),
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x90, 0]
        );
        let mut reply = exchange(&mut core, &mut p, &[0, 0xb0, 0, 0, 0, 1, 44]);
        let mut data = Vec::new();
        loop {
            data.extend_from_slice(&reply[..reply.len() - 2]);
            if reply[reply.len() - 2..] == [0x90, 0] { break; }
            assert_eq!(reply[reply.len() - 2], 0x61);
            reply = exchange(&mut core, &mut p, &[0, 0xc0, 0, 0, 0]);
        }
        assert_eq!(data.len(), 300);
        assert_eq!(&data[20..25], &[0x11, 0x22, 0x33, 0x44, 0x55]);
        let mut chunk = exchange(&mut core, &mut p, &[0, 0xb0, 0, 0, 0, 4, 0]);
        assert!(core.can_preempt()); // Large NDEF reads used an abandonable source.
        let mut total = 0;
        loop {
            total += chunk.len() - 2;
            if chunk[chunk.len() - 2] == 0x90 {
                break;
            }
            assert_eq!(&chunk[chunk.len() - 2..], &[0x61, 0xff]);
            chunk = exchange(&mut core, &mut p, &[0, 0xc0, 0, 0, 0]);
        }
        assert_eq!(total, 1024);
        core.reset(&mut p);
        assert_eq!(exchange(&mut core, &mut p, &select), [0x90, 0]);
        assert_eq!(
            exchange(&mut core, &mut p, &[0, 0xb0, 0, 0, 2]),
            [0x69, 0x85]
        );
        p.storage.replace(Record::NdefMessage, &[0; 32]).unwrap();
        canokey_rust_core::applets::ndef::Applet::install(false, &mut p).unwrap();
        assert_eq!(p.storage.size(Record::NdefMessage).unwrap(), 1024);
        assert_eq!(exchange(&mut core, &mut p, &[0, 0xa4, 0, 12, 2, 0, 1]), [0x90, 0]);
        assert_eq!(exchange(&mut core, &mut p, &[0, 0xb0, 0, 31, 2]), [0, 0, 0x90, 0]);
    }
    #[test]
    fn truncated_frame_never_publishes_update() {
        let mut records = Records(Disk::default());
        let mut crypto = UnusedCrypto;
        let mut device = DeviceStub;
        let mut p = Platform {
            storage: &mut records,
            crypto: &mut crypto,
            device: &mut device,
            memory: &Wipe,
        };
        canokey_rust_core::applets::ndef::Applet::install(false, &mut p).unwrap();
        let mut core = Core::new();
        exchange(
            &mut core,
            &mut p,
            &[0, 0xa4, 4, 0, 7, 0xd2, 0x76, 0, 0, 0x85, 1, 1],
        );
        exchange(&mut core, &mut p, &[0, 0xa4, 0, 12, 2, 0, 1]);
        core.begin_frame(1, 8, &mut p).unwrap();
        core.feed_frame(&[0, 0xd6, 0, 0, 3, 0xff, 0xff], &mut p)
            .unwrap();
        let reply = core.end_frame(&mut p);
        let mut out = [0; 2];
        assert_eq!(core.transmit(reply, &mut out, &mut p).unwrap(), 2);
        assert_eq!(out, [0x67, 0]);
        assert_eq!(
            exchange(&mut core, &mut p, &[0, 0xb0, 0, 0, 2]),
            [0, 17, 0x90, 0]
        );
    }
}
