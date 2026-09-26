// SPDX-License-Identifier: Apache-2.0
//! Host-only durable record image. This is not a LittleFS durability oracle.
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
const MAGIC: &[u8; 8] = b"CKRHOST1";
const COUNT: usize = 186;
const MAX_RECORD: usize = 32768;
const CAPACITY: usize = 128 * 1024;
pub struct Storage {
    path: PathBuf,
    records: Vec<Option<Vec<u8>>>,
    config: [u8; 512],
    stage: Option<Vec<u8>>,
    fault: Option<(u8, Vec<u8>)>,
    uncertain: bool,
}
impl Storage {
    pub fn open(path: &Path, reset: bool) -> io::Result<(Self, bool)> {
        let fresh = reset || !path.exists();
        let mut store = Self {
            path: path.into(),
            records: vec![None; COUNT],
            config: [0xff; 512],
            stage: None,
            fault: None,
            uncertain: false,
        };
        if !fresh {
            let mut file = File::open(path)?;
            let mut magic = [0; 8];
            file.read_exact(&mut magic)?;
            if &magic != MAGIC {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported virtual-card image; provision a separate Rust test image",
                ));
            }
            file.read_exact(&mut store.config)?;
            for record in &mut store.records {
                let mut size = [0; 4];
                file.read_exact(&mut size)?;
                let n = u32::from_be_bytes(size);
                if n == u32::MAX {
                    continue;
                }
                if n as usize > MAX_RECORD {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "oversized host record",
                    ));
                }
                let mut data = vec![0; n as usize];
                file.read_exact(&mut data)?;
                *record = Some(data);
            }
            let mut tail = [0];
            if file.read(&mut tail)? != 0 || store.used() > CAPACITY {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid host image length",
                ));
            }
        } else {
            store.persist()?;
        }
        Ok((store, fresh))
    }
    fn used(&self) -> usize {
        4096 + self.records.iter().flatten().map(Vec::len).sum::<usize>()
    }
    pub fn reopen(&self) -> io::Result<Self> {
        Self::open(&self.path, false).map(|(storage, _)| storage)
    }
    fn temporary_path(&self) -> PathBuf {
        let mut path = self.path.as_os_str().to_os_string();
        path.push(format!(".{}.tmp", std::process::id()));
        PathBuf::from(path)
    }
    fn persist(&mut self) -> io::Result<()> {
        // Same-directory rename is the commit point. Sync both data and parent
        // directory; an uncertain host I/O result fails closed until reopening.
        let temp = self.temporary_path();
        let mut created = false;
        let result = (|| {
            let mut out = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)?;
            created = true;
            out.write_all(MAGIC)?;
            out.write_all(&self.config)?;
            for record in &self.records {
                out.write_all(
                    &record
                        .as_ref()
                        .map_or(u32::MAX, |r| r.len() as u32)
                        .to_be_bytes(),
                )?;
                if let Some(record) = record {
                    out.write_all(record)?;
                }
            }
            out.sync_all()?;
            drop(out);
            fs::rename(&temp, &self.path)?;
            File::open(
                self.path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new(".")),
            )?
            .sync_all()
        })();
        if result.is_err() {
            self.uncertain = true;
            if created {
                let _ = fs::remove_file(&temp);
            }
        }
        result
    }
    fn check(&mut self, id: u8, op: u8) -> Result<usize, i32> {
        if self.uncertain || usize::from(id) >= COUNT {
            return Err(-2);
        }
        let path = match id {
            184 => b"E103".to_vec(),
            185 => b"NDEF".to_vec(),
            _ => format!("{id:02x}").into_bytes(),
        };
        if self
            .fault
            .as_ref()
            .is_some_and(|(kind, name)| *kind == op && *name == path)
        {
            self.fault = None;
            return Err(-2);
        }
        Ok(usize::from(id))
    }
    pub fn inject(&mut self, op: u8, sub: u8, path: &[u8]) {
        if op <= 1 && sub == 0 && !path.is_empty() && path.len() < 32 {
            self.fault = Some((op, path.to_vec()));
        }
    }
    pub fn size(&mut self, id: u8) -> Result<usize, i32> {
        let id = self.check(id, 1)?;
        self.records[id].as_ref().map(Vec::len).ok_or(-1)
    }
    pub fn read(
        &mut self,
        id: u8,
        offset: usize,
        out: &mut [u8],
        whole: bool,
    ) -> Result<usize, i32> {
        let id = self.check(id, 1)?;
        let data = self.records[id].as_ref().ok_or(-1)?;
        let count = if whole { data.len() } else { out.len() };
        if count > out.len() || offset > data.len() || count > data.len() - offset {
            return Err(-2);
        }
        out[..count].copy_from_slice(&data[offset..offset + count]);
        Ok(count)
    }
    fn replace(&mut self, id: usize, data: Vec<u8>) -> Result<usize, i32> {
        let len = data.len();
        if len > MAX_RECORD
            || self.used() - self.records[id].as_ref().map_or(0, Vec::len) + len > CAPACITY
        {
            return Err(-2);
        }
        self.records[id] = Some(data);
        self.persist().map_err(|_| -2)?;
        Ok(len)
    }
    pub fn write(&mut self, id: u8, data: &[u8]) -> Result<usize, i32> {
        let id = self.check(id, 0)?;
        self.replace(id, data.to_vec())
    }
    pub fn patch(&mut self, id: u8, offset: usize, data: &[u8]) -> Result<usize, i32> {
        let id = self.check(id, 0)?;
        let mut record = self.records[id].as_ref().ok_or(-1)?.clone();
        if offset > record.len() || offset > MAX_RECORD || data.len() > MAX_RECORD - offset {
            return Err(-2);
        }
        record.resize(record.len().max(offset + data.len()), 0);
        record[offset..offset + data.len()].copy_from_slice(data);
        self.replace(id, record)?;
        Ok(data.len())
    }
    pub fn resize(&mut self, id: u8, len: usize) -> Result<(), i32> {
        let id = self.check(id, 0)?;
        if len > MAX_RECORD {
            return Err(-2);
        }
        let mut record = self.records[id].as_ref().ok_or(-1)?.clone();
        record.resize(len, 0);
        self.replace(id, record)?;
        Ok(())
    }
    pub fn stage(&mut self, op: u8, id: u8, data: &[u8]) -> Result<(), i32> {
        if self.uncertain {
            return Err(-2);
        }
        match op {
            0 => {
                if data.len() > MAX_RECORD {
                    return Err(-2);
                }
                self.stage = Some(data.to_vec());
            }
            1 => {
                let stage = self.stage.as_mut().ok_or(-2)?;
                if data.len() > MAX_RECORD - stage.len() {
                    return Err(-2);
                }
                stage.extend_from_slice(data);
            }
            2 => {
                let id = self.check(id, 0)?;
                let stage = self.stage.take().ok_or(-2)?;
                self.replace(id, stage)?;
            }
            3 => {
                self.stage = None;
            }
            4 => {
                if !data.is_empty() {
                    return Err(-2);
                }
                let id = self.check(id, 0)?;
                self.records[id] = None;
                self.persist().map_err(|_| -2)?;
            }
            5 => {
                if data.len() != 1 {
                    return Err(-2);
                }
                let id = self.check(id, 0)?;
                let target = self.check(data[0], 0)?;
                if self.records[id].is_none() {
                    return Err(-1);
                }
                if id != target {
                    let record = self.records[id].take().ok_or(-1)?;
                    self.records[target] = Some(record);
                    self.persist().map_err(|_| -2)?;
                }
            }
            _ => return Err(-2),
        }
        Ok(())
    }
    pub fn usage(&self) -> Result<(u32, u32), i32> {
        if self.uncertain {
            Err(-2)
        } else {
            Ok((self.used() as u32, CAPACITY as u32))
        }
    }
    pub fn config_write(&mut self, bytes: &[u8]) -> Result<(), i32> {
        if self.uncertain || bytes.len() != 512 {
            return Err(-2);
        }
        self.config.copy_from_slice(bytes);
        self.persist().map_err(|_| -2)
    }
    pub fn config_read(&self, offset: usize, out: &mut [u8]) -> Result<(), i32> {
        if self.uncertain || offset > 512 || out.len() > 512 - offset {
            return Err(-2);
        }
        out.copy_from_slice(&self.config[offset..offset + out.len()]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Image(PathBuf);
    impl Image {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "ck-rust-storage-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> PathBuf {
            self.0.join("image")
        }
        fn open(&self) -> Storage {
            Storage::open(&self.path(), false).unwrap().0
        }
    }
    impl Drop for Image {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    #[test]
    fn mutations_are_durable_and_failed_injection_preserves_previous_data() {
        let image = Image::new();
        let mut store = image.open();
        assert_eq!(store.size(3), Err(-1));
        store.write(3, b"first").unwrap();
        store.inject(0, 0, b"03");
        assert_eq!(store.write(3, b"wrong"), Err(-2));
        store.patch(3, 1, b"inal").unwrap();
        store.resize(3, 7).unwrap();
        store.config_write(&[0x35; 512]).unwrap();
        let mut store = image.open();
        let mut data = [0; 7];
        assert_eq!(store.read(3, 0, &mut data, true), Ok(7));
        assert_eq!(&data, b"final\0\0");
        assert_eq!(store.config, [0x35; 512]);
        store.inject(1, 0, b"03");
        assert_eq!(store.read(3, 0, &mut data, true), Err(-2));
        assert_eq!(store.read(3, 0, &mut data, true), Ok(7));
        assert_eq!(store.read(3, 7, &mut [0], false), Err(-2));
        assert_eq!(store.write(186, b"bad"), Err(-2));
    }
    #[test]
    fn configuration_snapshot_reopens_and_explicit_reset_erases_it() {
        let image = Image::new();
        let mut store = image.open();
        store.config_write(&[0x5a; 512]).unwrap();
        let mut bytes = [0; 512];
        image.open().config_read(0, &mut bytes).unwrap();
        assert_eq!(bytes, [0x5a; 512]);
        let (reset, fresh) = Storage::open(&image.path(), true).unwrap();
        assert!(fresh);
        reset.config_read(0, &mut bytes).unwrap();
        assert_eq!(bytes, [0xff; 512]);
        image.open().config_read(0, &mut bytes).unwrap();
        assert_eq!(bytes, [0xff; 512]);
    }
    #[test]
    fn stage_publishes_only_on_commit_and_rename_is_durable() {
        let image = Image::new();
        let mut store = image.open();
        store.stage(0, 7, b"unpublished").unwrap();
        assert_eq!(image.open().size(7), Err(-1));
        store.stage(1, 7, b" tail").unwrap();
        store.stage(2, 7, &[]).unwrap();
        assert_eq!(image.open().size(7), Ok(16));
        store.stage(5, 7, &[8]).unwrap();
        let mut store = image.open();
        assert_eq!(store.size(7), Err(-1));
        assert_eq!(store.size(8), Ok(16));
        store.stage(4, 8, &[]).unwrap();
        assert_eq!(image.open().size(8), Err(-1));
        assert_eq!(store.stage(5, 8, &[8]), Err(-1));
        assert_eq!(store.stage(0, 7, &vec![0; MAX_RECORD + 1]), Err(-2));
    }
    #[test]
    fn invalid_images_are_rejected_without_overwrite() {
        let image = Image::new();
        for bytes in [b"legacy-lfs".as_slice(), MAGIC.as_slice()] {
            fs::write(image.path(), bytes).unwrap();
            assert!(Storage::open(&image.path(), false).is_err());
            assert_eq!(fs::read(image.path()).unwrap(), bytes);
        }
        let (_, fresh) = Storage::open(&image.path(), true).unwrap();
        assert!(fresh);
        assert!(!Storage::open(&image.path(), false).unwrap().1);
    }
    #[test]
    fn uncertain_commit_fails_closed_until_reopen() {
        let image = Image::new();
        let mut store = image.open();
        store.write(3, b"before").unwrap();
        // Force a host I/O error before rename, without touching the image.
        let temp = store.temporary_path();
        fs::write(&temp, b"occupied").unwrap();
        assert_eq!(store.write(3, b"after"), Err(-2));
        assert_eq!(store.size(3), Err(-2));
        assert_eq!(store.write(4, b"later"), Err(-2));
        assert_eq!(fs::read(&temp).unwrap(), b"occupied");
        let mut reopened = image.open();
        let mut data = [0; 6];
        reopened.read(3, 0, &mut data, true).unwrap();
        assert_eq!(&data, b"before");
    }
}
