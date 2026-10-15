use std::{
    io::{Read, Seek, SeekFrom},
    sync::Arc,
};
use tokio::runtime::Runtime;

use crate::cache::Cache;
use crate::io_log::{IoLog, ReadTimer, ReadTrace, chunk_cache_label};

#[derive(Clone)]
pub struct CacheReadSeek {
    cache: Arc<dyn Cache>,
    runtime: Arc<Runtime>,
    idx: usize,
    pos: u64,
    io_log: Option<Arc<IoLog>>,
}

impl CacheReadSeek {
    pub fn new(
        cache: Arc<dyn Cache>,
        runtime: Arc<Runtime>,
        idx: usize,
        io_log: Option<Arc<IoLog>>,
    ) -> Self {
        Self {
            cache,
            runtime,
            idx,
            pos: 0,
            io_log,
        }
    }
}

impl std::fmt::Debug for CacheReadSeek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheReadSeek")
            .field("idx", &self.idx)
            .field("pos", &self.pos)
            .finish()
    }
}

impl Read for CacheReadSeek {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        // check that we don't read past the end of the source
        let send = self.cache.end(self.idx)?;
        let rend = send.min(self.pos + buf.len() as u64);

        let len = (rend - self.pos) as usize;

        if len > 0 {
            let timer = self.io_log.as_ref().map(|_| ReadTimer::start());
            let read_offset = self.pos;
            let mut trace = ReadTrace::default();
            self.runtime.block_on(self.cache.read(
                self.idx,
                self.pos,
                &mut buf[..len],
                &mut trace,
            ))?;
            self.pos = rend;

            // vmdk has no secondary decoded-chunk cache like e01's, so there's
            // no chunk-level hit/miss to report -- only the foyer tier.
            if let Some(log) = &self.io_log {
                let dur_us = timer.as_ref().map(ReadTimer::elapsed_us).unwrap_or(0);
                log.log_read(
                    read_offset,
                    len,
                    dur_us,
                    trace.foyer_label(),
                    chunk_cache_label(None),
                );
            }
        }

        Ok(len)
    }
}

impl Seek for CacheReadSeek {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, std::io::Error> {
        let end = self.cache.end(self.idx)?;

        let (base, offset) = match pos {
            SeekFrom::Start(n) => (n, 0),
            SeekFrom::End(n) => (end, n),
            SeekFrom::Current(n) => (self.pos, n),
        };

        self.pos = match base.checked_add_signed(offset) {
            Some(n) if n <= end => Ok(n),
            Some(_) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid seek past end",
            )),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid seek to a negative or overflowing position",
            )),
        }?;

        Ok(self.pos)
    }

    /// Without this, `stream_position` falls back to `seek(Current(0))`,
    /// which asks the cache for the source's end -- a lock and a refcount
    /// round trip. Kaitai calls it before *every* primitive read (through
    /// `BufReader`, which forwards it here), so on a segment with tens of
    /// thousands of table entries that was most of the cost of opening.
    fn stream_position(&mut self) -> Result<u64, std::io::Error> {
        Ok(self.pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytessource::BytesSource;
    use async_trait::async_trait;

    struct FixedCache {
        data: Vec<u8>,
    }

    #[async_trait]
    impl Cache for FixedCache {
        async fn read(
            &self,
            _idx: usize,
            off: u64,
            buf: &mut [u8],
            _trace: &mut ReadTrace,
        ) -> Result<(), std::io::Error> {
            let off = off as usize;
            buf.copy_from_slice(&self.data[off..off + buf.len()]);
            Ok(())
        }

        fn end(&self, _idx: usize) -> Result<u64, std::io::Error> {
            Ok(self.data.len() as u64)
        }

        fn add_source(&self, _idx: usize, _src: Box<dyn BytesSource + Send + Sync>) {}
    }

    #[test]
    fn read_clamps_to_end_and_reports_real_count() {
        let data: Vec<u8> = (0..100).map(|i| i as u8).collect();
        let cache: Arc<dyn Cache> = Arc::new(FixedCache { data: data.clone() });
        let runtime = Arc::new(tokio::runtime::Runtime::new().unwrap());
        let mut crs = CacheReadSeek::new(cache, runtime, 0, None);

        crs.seek(SeekFrom::Start(90)).unwrap();
        let mut buf = [0xAAu8; 64];
        let n = crs.read(&mut buf).unwrap();
        assert_eq!(n, 10, "read past end must return only the remaining bytes");
        assert_eq!(&buf[..10], &data[90..]);

        let n = crs.read(&mut buf).unwrap();
        assert_eq!(n, 0, "read at end must return 0, not fabricate bytes");
    }
}
