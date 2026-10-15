use std::io::Error;
use std::path::Path;
use std::sync::Arc;

use futures::future::{BoxFuture, FutureExt};
use tracing::trace;

use crate::bytessource::BytesSource;

/// A local file, opened once.
///
/// The handle is retained rather than reopened per fetch: a cache miss used to
/// cost an `open()` syscall, and a 28 GiB image read in 1 MiB blocks is ~29,000
/// of them. Reads are *positioned* (`pread`), so they never move a file cursor
/// and one handle serves concurrent fetches without a lock.
#[derive(Clone, Debug)]
pub struct FileSource {
    path: String,
    file: Arc<std::fs::File>,
    len: u64,
}

impl FileSource {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let path = path.as_ref();
        let file = std::fs::File::open(path)?;
        let len = file.metadata()?.len();

        Ok(Self {
            path: path.display().to_string(),
            file: Arc::new(file),
            len,
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Fill `buf` from `offset` with a positioned read, which neither moves nor
/// depends on the file cursor, so one handle can serve concurrent readers.
#[cfg(unix)]
pub fn read_exact_at(file: &std::fs::File, buf: &mut [u8], offset: u64) -> Result<(), Error> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

/// Windows has no `read_exact_at`. `seek_read` is positioned but may come back
/// short, so fill the buffer the way the unix version does.
#[cfg(windows)]
pub fn read_exact_at(
    file: &std::fs::File,
    mut buf: &mut [u8],
    mut offset: u64,
) -> Result<(), Error> {
    use std::io::ErrorKind;
    use std::os::windows::fs::FileExt;

    while !buf.is_empty() {
        match file.seek_read(buf, offset) {
            Ok(0) => {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "failed to fill whole buffer",
                ));
            }
            Ok(n) => {
                buf = &mut buf[n..];
                offset += n as u64;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

impl BytesSource for FileSource {
    fn read(&self, beg: u64, end: u64) -> BoxFuture<'static, Result<Vec<u8>, Error>> {
        let file = self.file.clone();

        async move {
            let len = end.saturating_sub(beg) as usize;

            // A positioned read is a blocking syscall, so keep it off the async
            // worker threads -- which is what tokio::fs was doing for us before.
            let buf = tokio::task::spawn_blocking(move || {
                let mut buf = vec![0u8; len];
                read_exact_at(&file, &mut buf, beg)?;
                Ok::<_, Error>(buf)
            })
            .await
            .map_err(Error::other)??;

            trace!("read [{beg},{end}) from File");
            Ok(buf)
        }
        .boxed()
    }

    fn end(&self) -> u64 {
        self.len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    fn temp_file(bytes: &[u8]) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.bin");
        std::fs::write(&path, bytes).unwrap();
        (dir, path.to_str().unwrap().to_string())
    }

    #[tokio::test]
    async fn reads_a_range() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let (_dir, path) = temp_file(&data);

        let src = FileSource::open(&path).unwrap();
        assert_eq!(src.end(), 4096);

        let got = src.read(100, 356).await.unwrap();
        assert_eq!(got, &data[100..356]);
    }

    /// One handle now serves every read, so those reads must be positioned. A
    /// seek-then-read against a shared handle would let concurrent fetches
    /// clobber each other's cursor and return bytes from the wrong offset.
    #[tokio::test]
    async fn concurrent_reads_do_not_disturb_each_other() {
        let data: Vec<u8> = (0..16384u32).map(|i| (i % 251) as u8).collect();
        let (_dir, path) = temp_file(&data);

        let src = Arc::new(FileSource::open(&path).unwrap());

        let handles: Vec<_> = (0..16u64)
            .map(|i| {
                let src = src.clone();
                let beg = i * 1024;
                tokio::spawn(async move { (beg, src.read(beg, beg + 1024).await.unwrap()) })
            })
            .collect();

        for h in handles {
            let (beg, got) = h.await.unwrap();
            assert_eq!(
                got,
                &data[beg as usize..beg as usize + 1024],
                "the read at {beg} came back with another read's bytes"
            );
        }
    }

    #[tokio::test]
    async fn a_read_past_the_end_is_an_error() {
        let (_dir, path) = temp_file(&[0u8; 512]);
        let src = FileSource::open(&path).unwrap();

        let err = src.read(256, 1024).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
    }

    #[test]
    fn opening_a_missing_file_is_an_error() {
        assert!(FileSource::open("/nonexistent/nope.bin").is_err());
    }
}
