use flate2::{Decompress, FlushDecompress, Status};
use std::{
    collections::HashMap,
    hash::{BuildHasherDefault, Hasher},
    sync::{Arc, Mutex},
};
use tracing::{debug, error};

use crate::e01_reader::{CorruptChunkPolicy, ReadErrorKind};
use crate::sec_read::{Chunk, adler32};
use crate::workersource::WorkerSource;

/// Chunk indices are already well-distributed integers; SipHash on them is
/// pure overhead on a lookup made for every chunk read.
#[derive(Default)]
struct ChunkIndexHasher(u64);

impl Hasher for ChunkIndexHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 = (self.0 << 8 | *b as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        }
    }

    fn write_usize(&mut self, n: usize) {
        self.0 = (n as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
}

type ChunkIndexMap<V> = HashMap<usize, V, BuildHasherDefault<ChunkIndexHasher>>;

struct Slot {
    chunk_index: usize,
    data: Arc<[u8]>,
    referenced: bool,
}

/// One shard of the decoded-chunk cache, evicting by CLOCK (second chance):
/// an approximation of LRU whose hits and inserts are O(1). The LRU it
/// replaces kept recency in a `VecDeque` and paid a linear `retain` over the
/// whole cache on every hit.
struct Shard {
    capacity: usize,
    slots: Vec<Slot>,
    index: ChunkIndexMap<usize>,
    hand: usize,
}

impl Shard {
    fn get(&mut self, chunk_index: usize) -> Option<Arc<[u8]>> {
        let slot = &mut self.slots[*self.index.get(&chunk_index)?];
        slot.referenced = true;
        Some(slot.data.clone())
    }

    fn insert(&mut self, chunk_index: usize, data: Arc<[u8]>) {
        if let Some(&i) = self.index.get(&chunk_index) {
            self.slots[i].data = data;
            self.slots[i].referenced = true;
            return;
        }

        if self.slots.len() < self.capacity {
            self.index.insert(chunk_index, self.slots.len());
            self.slots.push(Slot {
                chunk_index,
                data,
                referenced: false,
            });
            return;
        }

        // Sweep for a slot not touched since the hand last passed it.
        loop {
            let slot = &mut self.slots[self.hand];
            if slot.referenced {
                slot.referenced = false;
                self.hand = (self.hand + 1) % self.capacity;
                continue;
            }
            self.index.remove(&slot.chunk_index);
            self.index.insert(chunk_index, self.hand);
            *slot = Slot {
                chunk_index,
                data,
                referenced: false,
            };
            self.hand = (self.hand + 1) % self.capacity;
            return;
        }
    }
}

/// A bounded cache of decompressed chunks, for clients that read a chunk more
/// than once -- a filesystem issuing 4 KiB reads inside a 32 KiB chunk.
///
/// Sharded by chunk index so concurrent readers rarely meet on a lock, where a
/// single cache-wide mutex serialized every chunk read of every thread.
pub struct DecodedChunkCache {
    shards: Box<[Mutex<Shard>]>,
}

impl std::fmt::Debug for DecodedChunkCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodedChunkCache")
            .field("shards", &self.shards.len())
            .finish()
    }
}

const MAX_CACHE_SHARDS: usize = 16;

impl DecodedChunkCache {
    /// Holds about `capacity` chunks; a capacity of zero caches nothing.
    pub fn new(capacity: usize) -> Self {
        let shard_count = capacity.clamp(1, MAX_CACHE_SHARDS);
        let per_shard = capacity.div_ceil(shard_count);
        let shards = (0..shard_count)
            .map(|_| {
                Mutex::new(Shard {
                    capacity: per_shard,
                    slots: Vec::with_capacity(per_shard),
                    index: ChunkIndexMap::default(),
                    hand: 0,
                })
            })
            .collect();
        Self { shards }
    }

    fn shard(&self, chunk_index: usize) -> &Mutex<Shard> {
        &self.shards[chunk_index % self.shards.len()]
    }

    pub fn get(&self, chunk_index: usize) -> Option<Arc<[u8]>> {
        self.shard(chunk_index)
            .lock()
            .expect("decoded chunk cache poisoned")
            .get(chunk_index)
    }

    pub fn insert(&self, chunk_index: usize, chunk: Arc<[u8]>) {
        let mut shard = self
            .shard(chunk_index)
            .lock()
            .expect("decoded chunk cache poisoned");
        if shard.capacity > 0 {
            shard.insert(chunk_index, chunk);
        }
    }
}

/// Decoder state and scratch for reading one chunk at a time.
///
/// Everything a chunk read needs is allocated once, here, and reused: the
/// stored bytes of a chunk, the inflater, and a chunk-sized buffer for
/// decoding chunks that cannot be decoded straight into the caller's buffer.
pub struct ReadWorker {
    chunk_size: usize,
    image_end: u64,
    corrupt_chunk_policy: CorruptChunkPolicy,
    inflater: Decompress,
    /// A chunk as stored: up to `chunk_size` bytes of data plus a checksum.
    stored: Vec<u8>,
    /// A decoded chunk, when only part of it goes to the caller.
    decoded: Vec<u8>,
}

impl std::fmt::Debug for ReadWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadWorker")
            .field("chunk_size", &self.chunk_size)
            .field("image_end", &self.image_end)
            .field("corrupt_chunk_policy", &self.corrupt_chunk_policy)
            .finish()
    }
}

/// Why a stored chunk failed to decode, before the corrupt-chunk policy has
/// had its say.
enum Corruption {
    Inflate(std::io::Error),
    BadChecksum(u32, u32),
    TooShort(usize),
}

/// Inflate `stored` into `out`, which has room for a whole chunk.
///
/// The stream must end -- which is when zlib checks its adler32, the only
/// checksum a compressed chunk carries -- having produced at least
/// `decoded_len` bytes. Room for a whole chunk lets a final chunk compressed
/// at full size decode, while a stream that would overflow a chunk runs out
/// of space before it ends and fails.
///
/// This replaces reading exactly `decoded_len` bytes out of a streaming
/// decoder, which stopped as soon as it had them: whatever the stream held
/// past a chunk's worth went unread, and a chunk that inflated to more than a
/// chunk was served as good data.
fn inflate(
    inflater: &mut Decompress,
    stored: &[u8],
    out: &mut [u8],
    decoded_len: usize,
) -> Result<(), Corruption> {
    inflater.reset(true);
    let status = inflater
        .decompress(stored, out, FlushDecompress::Finish)
        .map_err(|e| Corruption::Inflate(e.into()))?;
    let produced = inflater.total_out() as usize;

    let fail = |kind, msg: String| Err(Corruption::Inflate(std::io::Error::new(kind, msg)));
    match status {
        Status::StreamEnd if produced >= decoded_len => Ok(()),
        Status::StreamEnd => fail(
            std::io::ErrorKind::UnexpectedEof,
            format!("chunk inflated to {produced} bytes, expected {decoded_len}"),
        ),
        _ if inflater.total_in() as usize == stored.len() => fail(
            std::io::ErrorKind::UnexpectedEof,
            "compressed chunk ends before its stream does".into(),
        ),
        _ => fail(
            std::io::ErrorKind::InvalidData,
            format!("chunk inflates past {} bytes", out.len()),
        ),
    }
}

/// Check an uncompressed chunk -- its data followed by the data's adler32 --
/// and return the length of the data. A final chunk may be stored at full
/// size; every chunk must hold at least `decoded_len` bytes.
fn check_uncompressed(stored: &[u8], decoded_len: usize) -> Result<usize, Corruption> {
    let data_len = stored.len() - 4;
    let crc_stored = u32::from_le_bytes(stored[data_len..].try_into().expect("4 bytes"));
    let crc = adler32(&stored[..data_len]);
    if crc != crc_stored {
        return Err(Corruption::BadChecksum(crc, crc_stored));
    }
    if data_len < decoded_len {
        return Err(Corruption::TooShort(stored.len()));
    }
    Ok(data_len)
}

/// Decode a stored chunk into `out` (room for a whole chunk), applying the
/// corrupt-chunk policy to `out[..decoded_len]` if it does not decode cleanly.
fn decode_into(
    compressed: bool,
    chunk_index: usize,
    stored: &[u8],
    out: &mut [u8],
    decoded_len: usize,
    policy: CorruptChunkPolicy,
    inflater: &mut Decompress,
) -> Result<(), ReadErrorKind> {
    let outcome = if compressed {
        inflate(inflater, stored, out, decoded_len)
    } else {
        check_uncompressed(stored, decoded_len).map(|data_len| {
            let n = data_len.min(out.len());
            out[..n].copy_from_slice(&stored[..n]);
        })
    };

    let Err(corruption) = outcome else {
        return Ok(());
    };

    error!("chunk {chunk_index} is corrupt");
    let out = &mut out[..decoded_len];
    match (policy, corruption) {
        (CorruptChunkPolicy::Error, Corruption::Inflate(e)) => {
            Err(ReadErrorKind::DecompressionFailed(chunk_index, e))
        }
        (CorruptChunkPolicy::Error, Corruption::BadChecksum(calc, stored)) => {
            Err(ReadErrorKind::BadChecksum(chunk_index, calc, stored))
        }
        (CorruptChunkPolicy::Error, Corruption::TooShort(len)) => {
            Err(ReadErrorKind::TooShort(chunk_index, len))
        }
        // Uncompressed data is still the data, checksum or no; a compressed
        // chunk that will not inflate has nothing to offer.
        (CorruptChunkPolicy::RawIfPossible, _) if !compressed => {
            let raw = &stored[..stored.len() - 4];
            let n = raw.len().min(out.len());
            out[..n].copy_from_slice(&raw[..n]);
            out[n..].fill(0);
            Ok(())
        }
        _ => {
            out.fill(0);
            Ok(())
        }
    }
}

impl ReadWorker {
    pub fn new(
        chunk_size: usize,
        image_end: u64,
        corrupt_chunk_policy: CorruptChunkPolicy,
    ) -> Self {
        Self {
            chunk_size,
            image_end,
            corrupt_chunk_policy,
            inflater: Decompress::new(true),
            stored: vec![0; chunk_size + 4],
            decoded: vec![0; chunk_size],
        }
    }

    /// Chunk offsets come from the image's table sections and are untrusted:
    /// a corrupt table can invert a chunk's bounds or claim a length past the
    /// worker's chunk_size + 4 buffers.
    fn checked_chunk_len(&self, chunk: &Chunk, chunk_index: usize) -> Result<usize, ReadErrorKind> {
        chunk
            .end_offset
            .checked_sub(chunk.data_offset)
            .filter(|len| *len <= self.chunk_size as u64 + 4)
            .map(|len| len as usize)
            .ok_or(ReadErrorKind::BadChunkBounds {
                chunk: chunk_index,
                data_offset: chunk.data_offset,
                end_offset: chunk.end_offset,
            })
    }

    /// Read `[beg_in_chunk, end_in_chunk)` of chunk `chunk_index` into `buf`.
    ///
    /// With a `cache`, a chunk already in it is served from there, and when
    /// `insert` is set a chunk that has to be decoded is added to it.
    #[allow(clippy::too_many_arguments)]
    pub fn read_chunk<WS: WorkerSource>(
        &mut self,
        chunk: &Chunk,
        src: &mut WS,
        chunk_index: usize,
        buf: &mut [u8],
        beg_in_chunk: usize,
        end_in_chunk: usize,
        cache: Option<&DecodedChunkCache>,
        insert: bool,
    ) -> Result<(), ReadErrorKind> {
        let stored_len = self.checked_chunk_len(chunk, chunk_index)?;

        debug!("reading chunk {chunk_index} [{beg_in_chunk},{end_in_chunk})");

        if let Some(data) = cache.and_then(|c| c.get(chunk_index)) {
            buf.copy_from_slice(&data[beg_in_chunk..end_in_chunk]);
            return Ok(());
        }

        if !chunk.compressed && stored_len < 5 {
            return Err(ReadErrorKind::TooShort(chunk_index, stored_len));
        }

        let chunk_beg = chunk_index as u64 * self.chunk_size as u64;
        let decoded_len = (self.image_end - chunk_beg).min(self.chunk_size as u64) as usize;

        let stored = &mut self.stored[..stored_len];
        src.read(chunk.data_offset, stored)
            .map_err(ReadErrorKind::IoError)?;

        let insert = insert.then_some(cache).flatten();

        // A caller asking for the whole of a full-size chunk gets it decoded
        // straight into its buffer, rather than into scratch and then copied.
        if beg_in_chunk == 0 && end_in_chunk == self.chunk_size {
            decode_into(
                chunk.compressed,
                chunk_index,
                stored,
                buf,
                decoded_len,
                self.corrupt_chunk_policy,
                &mut self.inflater,
            )?;
            if let Some(cache) = insert {
                cache.insert(chunk_index, Arc::from(&*buf));
            }
        } else {
            decode_into(
                chunk.compressed,
                chunk_index,
                stored,
                &mut self.decoded,
                decoded_len,
                self.corrupt_chunk_policy,
                &mut self.inflater,
            )?;
            buf.copy_from_slice(&self.decoded[beg_in_chunk..end_in_chunk]);
            if let Some(cache) = insert {
                cache.insert(chunk_index, Arc::from(&self.decoded[..decoded_len]));
            }
        }

        Ok(())
    }

    #[cfg(test)]
    pub fn read<WS: WorkerSource>(
        &mut self,
        chunk: &Chunk,
        src: &mut WS,
        chunk_index: usize,
        buf: &mut [u8],
        beg_in_chunk: usize,
        end_in_chunk: usize,
    ) -> Result<(), ReadErrorKind> {
        self.read_chunk(
            chunk,
            src,
            chunk_index,
            buf,
            beg_in_chunk,
            end_in_chunk,
            None,
            false,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub fn read_cached<WS: WorkerSource>(
        &mut self,
        chunk: &Chunk,
        src: &mut WS,
        chunk_index: usize,
        buf: &mut [u8],
        beg_in_chunk: usize,
        end_in_chunk: usize,
        cache: &DecodedChunkCache,
    ) -> Result<(), ReadErrorKind> {
        self.read_chunk(
            chunk,
            src,
            chunk_index,
            buf,
            beg_in_chunk,
            end_in_chunk,
            Some(cache),
            true,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workersource::WorkerSource;
    use flate2::{Compression, write::ZlibEncoder};
    use std::io::Write;

    struct VecSource {
        data: Vec<u8>,
        read_count: usize,
    }

    impl WorkerSource for VecSource {
        fn read(&mut self, off: u64, buf: &mut [u8]) -> Result<(), std::io::Error> {
            self.read_count += 1;
            let off = off as usize;
            buf.copy_from_slice(&self.data[off..off + buf.len()]);
            Ok(())
        }
    }

    fn compressed_chunk(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn compressed_partial_read_returns_requested_offset() {
        let chunk_size = 32768;
        let data = (0..chunk_size)
            .map(|i| ((i / 251) ^ i) as u8)
            .collect::<Vec<_>>();
        let compressed = compressed_chunk(&data);
        let chunk = Chunk {
            segment: 0,
            data_offset: 0,
            end_offset: compressed.len() as u64,
            compressed: true,
        };
        let mut src = VecSource {
            data: compressed,
            read_count: 0,
        };
        let mut worker = ReadWorker::new(chunk_size, chunk_size as u64, CorruptChunkPolicy::Error);
        let mut out = vec![0; 4096];

        worker
            .read(&chunk, &mut src, 0, &mut out, 4096, 8192)
            .unwrap();

        assert_eq!(&out, &data[4096..8192]);
    }

    fn uncompressed_chunk_with_trailer(data: &[u8]) -> Vec<u8> {
        let mut raw = data.to_vec();
        let crc = adler32(data);
        raw.extend_from_slice(&crc.to_le_bytes());
        raw
    }

    #[test]
    fn uncompressed_partial_read_reuses_decoded_chunk_cache() {
        let chunk_size = 32768;
        let data = (0..chunk_size)
            .map(|i| ((i / 251) ^ i) as u8)
            .collect::<Vec<_>>();
        let raw = uncompressed_chunk_with_trailer(&data);
        let chunk = Chunk {
            segment: 0,
            data_offset: 0,
            end_offset: raw.len() as u64,
            compressed: false,
        };
        let mut src = VecSource {
            data: raw,
            read_count: 0,
        };
        let mut worker = ReadWorker::new(chunk_size, chunk_size as u64, CorruptChunkPolicy::Error);
        let cache = DecodedChunkCache::new(8);

        let mut first = vec![0; 4096];
        worker
            .read_cached(&chunk, &mut src, 0, &mut first, 0, 4096, &cache)
            .unwrap();
        assert_eq!(&first, &data[0..4096]);
        assert_eq!(src.read_count, 1);

        let mut second = vec![0; 4096];
        worker
            .read_cached(&chunk, &mut src, 0, &mut second, 4096, 8192, &cache)
            .unwrap();
        assert_eq!(&second, &data[4096..8192]);
        assert_eq!(src.read_count, 1);
    }

    #[test]
    fn compressed_partial_read_reuses_decoded_chunk_cache() {
        let chunk_size = 32768;
        let data = (0..chunk_size)
            .map(|i| ((i / 251) ^ i) as u8)
            .collect::<Vec<_>>();
        let compressed = compressed_chunk(&data);
        let chunk = Chunk {
            segment: 0,
            data_offset: 0,
            end_offset: compressed.len() as u64,
            compressed: true,
        };
        let mut src = VecSource {
            data: compressed,
            read_count: 0,
        };
        let mut worker = ReadWorker::new(chunk_size, chunk_size as u64, CorruptChunkPolicy::Error);
        let cache = DecodedChunkCache::new(8);

        let mut first = vec![0; 4096];
        worker
            .read_cached(&chunk, &mut src, 0, &mut first, 0, 4096, &cache)
            .unwrap();
        assert_eq!(&first, &data[0..4096]);
        assert_eq!(src.read_count, 1);

        let mut second = vec![0; 4096];
        worker
            .read_cached(&chunk, &mut src, 0, &mut second, 4096, 8192, &cache)
            .unwrap();
        assert_eq!(&second, &data[4096..8192]);
        assert_eq!(src.read_count, 1);
    }

    #[test]
    fn decoded_chunk_cache_holds_at_most_its_capacity() {
        let cache = DecodedChunkCache::new(32);
        for i in 0..1000usize {
            cache.insert(i, Arc::from(vec![i as u8; 4]));
        }
        let held: Vec<_> = (0..1000).filter_map(|i| Some((i, cache.get(i)?))).collect();
        assert!(!held.is_empty() && held.len() <= 32, "{} held", held.len());
        for (i, data) in held {
            assert_eq!(&data[..], &[i as u8; 4]);
        }
    }

    /// CLOCK gives a chunk used since the hand last passed it a second
    /// chance: the sweep evicts one that has not been.
    #[test]
    fn decoded_chunk_cache_evicts_an_unused_chunk_before_a_used_one() {
        // 16 shards of 2; chunks 0, 16 and 32 share a shard
        let cache = DecodedChunkCache::new(32);
        cache.insert(0, Arc::from(vec![0u8]));
        cache.insert(16, Arc::from(vec![16u8]));
        assert!(cache.get(0).is_some());
        cache.insert(32, Arc::from(vec![32u8]));

        assert!(cache.get(0).is_some());
        assert!(cache.get(16).is_none());
        assert!(cache.get(32).is_some());
    }

    #[test]
    fn decoded_chunk_cache_of_no_capacity_holds_nothing() {
        let cache = DecodedChunkCache::new(0);
        cache.insert(0, Arc::from(vec![0u8]));
        assert!(cache.get(0).is_none());
    }

    /// Read the whole of a compressed chunk whose stored bytes are `stored`,
    /// with the Error policy, through both the cached and uncached paths.
    fn read_compressed_strict(
        stored: Vec<u8>,
        chunk_size: usize,
    ) -> [Result<(), ReadErrorKind>; 2] {
        let chunk = Chunk {
            segment: 0,
            data_offset: 0,
            end_offset: stored.len() as u64,
            compressed: true,
        };
        let mut src = VecSource {
            data: stored,
            read_count: 0,
        };
        let mut worker = ReadWorker::new(chunk_size, chunk_size as u64, CorruptChunkPolicy::Error);
        let mut out = vec![0; chunk_size];
        let uncached = worker.read(&chunk, &mut src, 0, &mut out, 0, chunk_size);
        let cache = DecodedChunkCache::new(8);
        let cached = worker.read_cached(&chunk, &mut src, 0, &mut out, 0, chunk_size, &cache);
        [uncached, cached]
    }

    /// A zlib stream ends with an adler32 of its decompressed bytes; it is the
    /// only checksum a compressed EWF chunk has. Reading exactly the chunk's
    /// worth of output stops the decoder before it reaches the trailer, so a
    /// corrupt checksum went unnoticed and the chunk was served as good data.
    #[test]
    fn compressed_chunk_with_bad_adler32_is_an_error() {
        let chunk_size = 32768;
        let data = (0..chunk_size)
            .map(|i| (i * 7 % 251) as u8)
            .collect::<Vec<_>>();
        let mut stored = compressed_chunk(&data);
        let last = stored.len() - 1;
        stored[last] ^= 0xff;

        for r in read_compressed_strict(stored, chunk_size) {
            assert!(
                matches!(r, Err(ReadErrorKind::DecompressionFailed(..))),
                "got {r:?}"
            );
        }
    }

    /// A stream cut off after the data but before its adler32 trailer has not
    /// been verified at all, and must not pass as a good chunk.
    #[test]
    fn compressed_chunk_missing_its_trailer_is_an_error() {
        let chunk_size = 32768;
        let data = (0..chunk_size)
            .map(|i| (i * 7 % 251) as u8)
            .collect::<Vec<_>>();
        let mut stored = compressed_chunk(&data);
        stored.truncate(stored.len() - 4);

        for r in read_compressed_strict(stored, chunk_size) {
            assert!(
                matches!(r, Err(ReadErrorKind::DecompressionFailed(..))),
                "got {r:?}"
            );
        }
    }

    /// A chunk that inflates to more than a chunk's worth of data is corrupt;
    /// taking the first chunk_size bytes of it would hide that.
    #[test]
    fn compressed_chunk_that_inflates_past_the_chunk_size_is_an_error() {
        let chunk_size = 32768;
        let data = vec![0x5a; chunk_size + 512];
        let stored = compressed_chunk(&data);

        for r in read_compressed_strict(stored, chunk_size) {
            assert!(
                matches!(r, Err(ReadErrorKind::DecompressionFailed(..))),
                "got {r:?}"
            );
        }
    }

    /// Likewise one that inflates to less than a chunk: there is no data for
    /// the rest of the chunk, and inventing zeros for it would be silent.
    #[test]
    fn compressed_chunk_that_inflates_short_is_an_error() {
        let chunk_size = 32768;
        let data = vec![0x5a; chunk_size - 512];
        let stored = compressed_chunk(&data);

        for r in read_compressed_strict(stored, chunk_size) {
            assert!(
                matches!(r, Err(ReadErrorKind::DecompressionFailed(..))),
                "got {r:?}"
            );
        }
    }

    /// Read the whole of an uncompressed chunk of `chunk_size` whose stored
    /// bytes are `stored`, through both the cached and uncached paths.
    fn read_uncompressed(
        stored: Vec<u8>,
        chunk_size: usize,
        policy: CorruptChunkPolicy,
    ) -> [(Result<(), ReadErrorKind>, Vec<u8>); 2] {
        let chunk = Chunk {
            segment: 0,
            data_offset: 0,
            end_offset: stored.len() as u64,
            compressed: false,
        };
        let mut src = VecSource {
            data: stored,
            read_count: 0,
        };
        let mut worker = ReadWorker::new(chunk_size, chunk_size as u64, policy);
        let mut uncached = vec![0xff; chunk_size];
        let r = worker.read(&chunk, &mut src, 0, &mut uncached, 0, chunk_size);
        let cache = DecodedChunkCache::new(8);
        let mut cached = vec![0xff; chunk_size];
        let c = worker.read_cached(&chunk, &mut src, 0, &mut cached, 0, chunk_size, &cache);
        [(r, uncached), (c, cached)]
    }

    /// An uncompressed chunk is its data and an adler32; one whose table entry
    /// gives it fewer bytes than a chunk holds has no data for the rest of
    /// the chunk. That is a corrupt chunk, not a slice index out of range.
    #[test]
    fn short_uncompressed_chunk_is_an_error_not_a_panic() {
        let chunk_size = 32768;
        let data = vec![0x5a; chunk_size - 512];
        let stored = uncompressed_chunk_with_trailer(&data);

        for (r, _) in read_uncompressed(stored, chunk_size, CorruptChunkPolicy::Error) {
            assert!(matches!(r, Err(ReadErrorKind::TooShort(0, _))), "got {r:?}");
        }
    }

    /// The zero policy zeroes a short uncompressed chunk like any other
    /// corrupt one.
    #[test]
    fn short_uncompressed_chunk_is_zeroed_by_the_zero_policy() {
        let chunk_size = 32768;
        let data = vec![0x5a; chunk_size - 512];
        let stored = uncompressed_chunk_with_trailer(&data);

        for (r, out) in read_uncompressed(stored, chunk_size, CorruptChunkPolicy::Zero) {
            r.unwrap();
            assert!(out.iter().all(|&b| b == 0));
        }
    }

    /// Chunk offsets come straight from the image's table sections; a corrupt
    /// table can put a chunk's end before its start. That must surface as a
    /// read error, not an arithmetic panic or a giant allocation.
    #[test]
    fn inverted_chunk_bounds_is_an_error_not_a_panic() {
        let chunk_size = 32768;
        let chunk = Chunk {
            segment: 0,
            data_offset: 0x1000,
            end_offset: 0x800,
            compressed: false,
        };
        let mut src = VecSource {
            data: vec![0; chunk_size],
            read_count: 0,
        };
        let mut worker = ReadWorker::new(chunk_size, chunk_size as u64, CorruptChunkPolicy::Error);
        let mut out = vec![0; 512];

        let err = worker
            .read(&chunk, &mut src, 0, &mut out, 0, 512)
            .unwrap_err();
        assert!(
            matches!(err, ReadErrorKind::BadChunkBounds { .. }),
            "got {err:?}"
        );
    }

    /// A chunk longer than chunk_size + 4 cannot be valid (the payload is at
    /// most a full chunk plus its checksum) and overruns the worker's
    /// fixed-size buffer if trusted.
    #[test]
    fn oversized_chunk_is_an_error_not_a_panic() {
        let chunk_size = 32768;
        let chunk = Chunk {
            segment: 0,
            data_offset: 0,
            end_offset: chunk_size as u64 + 5,
            compressed: true,
        };
        let mut src = VecSource {
            data: vec![0; chunk_size * 2],
            read_count: 0,
        };
        let mut worker = ReadWorker::new(chunk_size, chunk_size as u64, CorruptChunkPolicy::Error);
        let cache = DecodedChunkCache::new(8);
        let mut out = vec![0; 512];

        let err = worker
            .read_cached(&chunk, &mut src, 0, &mut out, 0, 512, &cache)
            .unwrap_err();
        assert!(
            matches!(err, ReadErrorKind::BadChunkBounds { .. }),
            "got {err:?}"
        );
    }
}
