//! Direct access to segment files on the local filesystem.
//!
//! A local segment needs no block cache of ours: the OS page cache already is
//! one, and reading a chunk is a single positioned read of exactly its bytes.
//! Going through the foyer cache instead cost a tokio `block_on` per chunk and
//! a 1 MiB block copied out of the page cache to serve each 32 KiB chunk --
//! three times the work of the chunk's own decompression on a random read.

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    sync::Arc,
};

use imagesource::filesource::read_exact_at;

use crate::workersource::WorkerSource;

/// One segment file, for chunk reads.
pub struct LocalSource<'a>(pub &'a File);

impl WorkerSource for LocalSource<'_> {
    fn read(&mut self, off: u64, buf: &mut [u8]) -> Result<(), std::io::Error> {
        read_exact_at(self.0, buf, off)
    }
}

/// `Read + Seek` over a segment file with positioned reads, for the section
/// parser. Its position is its own, so it can share a `File` with chunk reads,
/// and asking for it costs nothing -- which matters, because kaitai asks before
/// every primitive it reads.
pub struct FileReadSeek {
    file: Arc<File>,
    len: u64,
    pos: u64,
}

impl FileReadSeek {
    pub fn new(file: Arc<File>) -> Result<Self, std::io::Error> {
        let len = file.metadata()?.len();
        Ok(Self { file, len, pos: 0 })
    }
}

impl Read for FileReadSeek {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        let n = buf.len().min(self.len.saturating_sub(self.pos) as usize);
        read_exact_at(&self.file, &mut buf[..n], self.pos)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for FileReadSeek {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, std::io::Error> {
        let (base, offset) = match pos {
            SeekFrom::Start(n) => (n, 0),
            SeekFrom::End(n) => (self.len, n),
            SeekFrom::Current(n) => (self.pos, n),
        };
        self.pos = base.checked_add_signed(offset).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid seek to a negative or overflowing position",
            )
        })?;
        Ok(self.pos)
    }

    fn stream_position(&mut self) -> Result<u64, std::io::Error> {
        Ok(self.pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn file_with(bytes: &[u8]) -> (tempfile::NamedTempFile, Arc<File>) {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        let file = Arc::new(File::open(f.path()).unwrap());
        (f, file)
    }

    #[test]
    fn reads_seeks_and_stops_at_the_end() {
        let data: Vec<u8> = (0..=255).collect();
        let (_tmp, file) = file_with(&data);
        let mut r = FileReadSeek::new(file).unwrap();

        let mut buf = [0u8; 16];
        assert_eq!(r.read(&mut buf).unwrap(), 16);
        assert_eq!(&buf, &data[..16]);
        assert_eq!(r.stream_position().unwrap(), 16);

        r.seek(SeekFrom::End(-4)).unwrap();
        assert_eq!(r.read(&mut buf).unwrap(), 4);
        assert_eq!(&buf[..4], &data[252..]);
        assert_eq!(r.read(&mut buf).unwrap(), 0);

        r.seek(SeekFrom::Start(100)).unwrap();
        r.seek(SeekFrom::Current(-50)).unwrap();
        assert_eq!(r.read(&mut buf).unwrap(), 16);
        assert_eq!(&buf, &data[50..66]);

        assert!(r.seek(SeekFrom::Current(-1000)).is_err());
    }

    #[test]
    fn local_source_reads_exactly_or_fails() {
        let data: Vec<u8> = (0..=255).collect();
        let (_tmp, file) = file_with(&data);
        let mut src = LocalSource(&file);

        let mut buf = [0u8; 8];
        src.read(248, &mut buf).unwrap();
        assert_eq!(&buf, &data[248..]);

        // a chunk whose table entry points past the end of the file
        assert!(src.read(250, &mut buf).is_err());
    }
}
