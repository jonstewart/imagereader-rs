use std::sync::Mutex;
use tokio::runtime::Runtime;

use crate::workersource::WorkerSource;
use imagesource::{Cache, ReadTrace};

/// Chunk reads through the foyer block cache, for segments that are not local
/// files. Borrowed rather than owned, so building one per chunk costs no
/// refcount traffic on handles shared by every reader thread.
pub struct CacheWorkerSource<'a> {
    pub cache: &'a dyn Cache,
    pub runtime: &'a Runtime,
    pub idx: usize,
    pub foyer_trace: Option<&'a Mutex<ReadTrace>>,
}

impl WorkerSource for CacheWorkerSource<'_> {
    fn read(&mut self, off: u64, buf: &mut [u8]) -> Result<(), std::io::Error> {
        let mut local = ReadTrace::default();

        self.runtime
            .block_on(self.cache.read(self.idx, off, buf, &mut local))?;
        if local.foyer_miss
            && let Some(shared) = self.foyer_trace
        {
            shared.lock().unwrap().foyer_miss = true;
        }
        Ok(())
    }
}
