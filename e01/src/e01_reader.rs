use kaitai::{BytesReader, KError, ReadSeek};
use rayon::prelude::*;
use std::{
    cell::Cell,
    collections::HashMap,
    fmt::Debug,
    fs::File,
    path::{Path, PathBuf},
    sync::{
        Arc, LazyLock, Mutex, OnceLock, Weak,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::runtime::Runtime;
use tracing::{debug, warn};

use crate::{
    cacheworkersource::CacheWorkerSource,
    error::{IoError, LibError},
    fanout,
    localsource::{FileReadSeek, LocalSource},
    readworker::{DecodedChunkCache, ReadWorker},
    sec_read::{Chunk, Section, SectionIterator, VolumeSection, table_chunks},
    seg_path::{SegPathError, UnrecognizedExtension, validated_segment_paths},
    segment::SegmentFileHeader,
};
use imagesource::{
    Cache, CacheReadSeek, FoyerCache, IoLog, ReadTimer, ReadTrace, chunk_cache_label,
    exists::{ExistsError, FileChecker, S3Checker},
    s3_creds::{S3Auth, resolve_s3_auth},
    urlsource::{path_or_url_to_url, source_for_url},
};

// Re-exported so existing consumers keep their `e01::e01_reader::…` paths.
pub use imagesource::{CacheMode, InitError};

impl From<SegPathError> for OpenError {
    fn from(e: SegPathError) -> Self {
        match e {
            SegPathError::UnrecognizedExtension(e) => Self::PathGlobError(e),
            SegPathError::Undetermined(e) => Self::SegmentProbeFailed(e),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("{0}")]
    PathGlobError(#[from] UnrecognizedExtension),
    /// A segment probe during globbing gave no definite answer. Distinct from
    /// `NoSegmentFiles`: the sequence may well be complete, we just could not
    /// see it, and silently globbing a shorter one would open a short image.
    #[error("{0}")]
    SegmentProbeFailed(#[from] ExistsError),
    #[error("No segment files given")]
    NoSegmentFiles,
    #[error("Missing volume section in {0}")]
    MissingVolumeSection(PathBuf),
    #[error(
        "Invalid volume geometry: {sectors_per_chunk} sectors per chunk, {bytes_per_sector} bytes per sector"
    )]
    InvalidVolumeGeometry {
        sectors_per_chunk: u32,
        bytes_per_sector: u32,
    },
    #[error("Too many chunks found: actual {0}, expected {1}")]
    TooManyChunks(usize, usize),
    #[error("Too few chunks found: actual {0}, expected {1}")]
    TooFewChunks(usize, usize),
    #[error("Declared image size {image_size} exceeds chunk coverage {chunk_coverage}")]
    DeclaredSizeExceedsChunks {
        image_size: u64,
        chunk_coverage: u64,
    },
    #[error("Error reading {path}: {source}")]
    IoError {
        path: String,
        #[source]
        source: LibError,
    },
    #[error("Bad data in {path}: {source}")]
    BadData {
        path: String,
        #[source]
        source: LibError,
    },
    #[error("Malformed path or URL: {0}")]
    BadPath(String),
    #[error("Unsupported URL scheme: {0}")]
    UnsupportedScheme(String),
    #[error("{0}")]
    InitializationFailed(#[from] InitError),
    #[error("{0}")]
    Source(#[from] imagesource::OpenError),
    #[error("Segment file {path} has segment number {actual}, expected {expected}")]
    SegmentOutOfOrder {
        path: String,
        actual: u16,
        expected: u16,
    },
}

impl From<std::io::Error> for OpenError {
    fn from(e: std::io::Error) -> Self {
        OpenError::from(LibError::from(IoError::from(e)))
    }
}

impl From<LibError> for OpenError {
    fn from(e: LibError) -> Self {
        match e {
            LibError::IoError(_) => Self::IoError {
                path: "".into(), // set using with_path()
                source: e,
            },
            _ => Self::BadData {
                path: "".into(), // set using with_path()
                source: e,
            },
        }
    }
}

impl From<KError> for OpenError {
    fn from(e: KError) -> Self {
        Self::IoError {
            path: "".into(), // set using with_path()
            source: LibError::IoError(IoError::Read(e)),
        }
    }
}

impl OpenError {
    fn with_path<T: AsRef<str>>(self, path: T) -> Self {
        match self {
            Self::IoError { source, .. } => Self::IoError {
                path: path.as_ref().into(),
                source,
            },
            Self::BadData { source, .. } => Self::BadData {
                path: path.as_ref().into(),
                source,
            },
            _ => self,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReadErrorKind {
    #[error("Requested offset {0} is beyond end of image {1}")]
    OffsetBeyondEnd(u64, u64),
    #[error("{0}")]
    IoError(#[from] std::io::Error),
    #[error("Chunk {0} is {1} bytes long, too short for its data and checksum")]
    TooShort(usize, usize),
    #[error("Chunk {0} checksum failed: calculated {1}, expected {2}")]
    BadChecksum(usize, u32, u32),
    #[error("Decompression of chunk {0} failed: {1}")]
    DecompressionFailed(usize, #[source] std::io::Error),
    #[error("Chunk {chunk} has corrupt bounds: data offset {data_offset}, end offset {end_offset}")]
    BadChunkBounds {
        chunk: usize,
        data_offset: u64,
        end_offset: u64,
    },
}

#[derive(Debug, thiserror::Error)]
#[error(
    "{}{}{source}",
    path.as_deref().unwrap_or(Path::new("")).display(),
    path.as_ref().map(|_| ": ").unwrap_or("")
)]
pub struct ReadError {
    path: Option<PathBuf>,
    #[source]
    source: ReadErrorKind,
}

impl ReadError {
    fn with_path<T: AsRef<Path>>(self, path: T) -> Self {
        Self {
            path: Some(path.as_ref().into()),
            source: self.source,
        }
    }
}

impl From<ReadErrorKind> for ReadError {
    fn from(e: ReadErrorKind) -> Self {
        Self {
            path: None,
            source: e,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum E01Error {
    #[error("{0}")]
    OpenError(#[from] OpenError),
    #[error("{0}")]
    ReadError(#[from] ReadError),
}

struct SegmentComponents {
    path: String,
    segment_number: u16,
    volume: Option<VolumeSection>,
    md5: Option<[u8; 16]>,
    sha1: Option<[u8; 20]>,
    chunks: Vec<Chunk>,
    done: bool,
}

fn read_segment<T: AsRef<str>>(
    segment_path: T,
    segment_index: usize,
    io: &BytesReader,
    ignore_checksums: bool,
) -> Result<SegmentComponents, OpenError> {
    debug!("reading sections {}", segment_path.as_ref());

    let header = SegmentFileHeader::new(io)
        .map_err(OpenError::from)
        .map_err(|e| e.with_path(&segment_path))?;

    let mut done = false;

    // A segment's chunk count is known only once all of its tables are read,
    // so the tables are collected first and parsed into one exactly-sized
    // vector after. Growing it table by table instead reallocated and copied
    // it a dozen times over, which was most of the time spent opening.
    let mut tables = vec![];

    let mut end_of_sectors = 0;

    let mut volume = None;
    let mut md5 = None;
    let mut sha1 = None;

    let mut sections = SectionIterator::new(io, ignore_checksums);

    for section in sections.by_ref() {
        let section = section
            .map_err(OpenError::from)
            .map_err(|e| e.with_path(&segment_path))?;

        debug!("found section {section:?}");

        match section {
            Section::Volume(v) => volume = Some(v),
            Section::Table {
                entries,
                base_offset,
                end,
            } if !entries.is_empty() => tables.push((entries, base_offset, end, end_of_sectors)),
            Section::Sectors(eos) => end_of_sectors = eos,
            Section::Hash(h) => md5 = Some(h),
            Section::Digest(d_md5, d_sha1) => {
                md5 = Some(d_md5);
                sha1 = Some(d_sha1);
            }
            Section::Done => {
                done = true;
                break;
            }
            _ => {}
        }
    }

    if done && sections.next().is_some() {
        warn!("more sections after done");
    }

    let mut chunks = Vec::with_capacity(tables.iter().map(|t| t.0.len() / 4).sum());
    for (entries, base_offset, end, end_of_sectors) in tables {
        table_chunks(&entries, base_offset, segment_index, &mut chunks)
            .map_err(OpenError::from)
            .map_err(|e| e.with_path(&segment_path))?;
        let last = chunks.last_mut().expect("a non-empty table adds chunks");
        last.end_offset = last_chunk_end(last.data_offset, end_of_sectors, end);
    }

    Ok(SegmentComponents {
        path: segment_path.as_ref().into(),
        segment_number: header.segment_number(),
        volume,
        md5,
        sha1,
        chunks,
        done,
    })
}

/// Where the last chunk of a table ends, which the table does not record.
///
/// Normally a table's chunks sit in the `sectors` section before it, so the
/// last one ends where that section does. In EnCase 1 images there are no
/// `sectors` sections: the chunks follow the offsets inside the table section
/// itself, and the last one ends with it. Taking the end of a `sectors`
/// section regardless gave such a chunk an end of zero, before its start, and
/// every read of it failed.
fn last_chunk_end(data_offset: u64, end_of_sectors: u64, table_end: u64) -> u64 {
    if data_offset < end_of_sectors || data_offset >= table_end {
        end_of_sectors
    } else {
        table_end
    }
}

fn make_bytes_reader(
    p: &str,
    idx: usize,
    cache: Arc<dyn Cache>,
    runtime: Arc<Runtime>,
    s3_auth: Option<&Arc<S3Auth>>,
    io_log: Option<Arc<IoLog>>,
) -> Result<BytesReader, OpenError> {
    debug!("opening {}", p);

    let url = path_or_url_to_url(p).ok_or(OpenError::BadPath(p.into()))?;

    let src = source_for_url(&url, idx, &runtime, s3_auth, io_log.as_ref())?;

    cache.add_source(idx, src);

    let crs = CacheReadSeek::new(cache, runtime, idx, None);

    // Kaitai's generated struct parser issues reads a few bytes at a time
    // (one per primitive field) while walking segment headers/tables.
    // Buffering coalesces those into far fewer round trips through the
    // cache, which otherwise serializes every tiny read behind a lock.
    let buffered = std::io::BufReader::with_capacity(1024 * 1024, crs);

    let rs = Box::new(buffered) as Box<dyn ReadSeek>;

    BytesReader::try_from(rs)
        .map_err(OpenError::from)
        .map_err(|e| e.with_path(p))
}

/// Buffer for parsing a local segment's sections. Small on purpose: the
/// parser seeks from section to section, and each seek throws the buffer away.
/// A table's offset array is read in one go and bypasses it.
const LOCAL_PARSE_BUFFER: usize = 8 * 1024;

fn make_local_bytes_reader(file: Arc<File>, p: &str) -> Result<BytesReader, OpenError> {
    let rs = FileReadSeek::new(file)
        .map_err(OpenError::from)
        .map_err(|e| e.with_path(p))?;
    let buffered = std::io::BufReader::with_capacity(LOCAL_PARSE_BUFFER, rs);

    BytesReader::try_from(Box::new(buffered) as Box<dyn ReadSeek>)
        .map_err(OpenError::from)
        .map_err(|e| e.with_path(p))
}

struct E01Metadata {
    volume: VolumeSection,
    md5: Option<[u8; 16]>,
    sha1: Option<[u8; 20]>,
    segment_paths: Vec<String>,
    chunks: Vec<Chunk>,
}

fn process_segments(segs: Vec<SegmentComponents>) -> Result<E01Metadata, OpenError> {
    let mut volume = None;
    let mut stored_md5 = None;
    let mut stored_sha1 = None;

    let mut segment_paths = vec![];
    // Sized from the chunks actually parsed, so each is copied once at most --
    // and not at all for a single-segment image, whose vector is taken whole.
    let mut chunks = match segs.len() {
        1 => vec![],
        _ => Vec::with_capacity(segs.iter().map(|s| s.chunks.len()).sum()),
    };

    let mut done = false;

    for (i, seg) in segs.into_iter().enumerate() {
        let expected = (i + 1) as u16; // EWF segment numbers are 1-based
        if seg.segment_number != expected {
            return Err(OpenError::SegmentOutOfOrder {
                path: seg.path.clone(),
                actual: seg.segment_number,
                expected,
            });
        }

        debug!("handling {}", seg.path);

        // take the volume section if it's the first one
        match (seg.volume, &volume) {
            // we have no volume section, and saw one
            (Some(sv), None) => volume = Some(sv),
            // we have a volume section, and didn't see a new one
            (None, Some(_)) => {}
            // we have no volume section, and saw none;
            // this can happen only on the first segment
            (None, None) => return Err(OpenError::MissingVolumeSection((&seg.path).into())),
            // we have a volume section and saw another one!
            (Some(_), Some(_)) => warn!("duplicate volume section"),
        }

        // take the stored MD5 if it's the first one
        match (seg.md5, &stored_md5) {
            (Some(h), None) => stored_md5 = Some(h),
            (Some(new), Some(old)) if new != *old => warn!("duplicate stored MD5s disagree"),
            _ => {}
        }

        // take the stored SHA1 if it's the first one
        match (seg.sha1, &stored_sha1) {
            (Some(h), None) => stored_sha1 = Some(h),
            (Some(new), Some(old)) if new != *old => warn!("duplicate stored SHA1s disagree"),
            _ => {}
        }

        // record the chunks
        if chunks.capacity() == 0 {
            chunks = seg.chunks;
        } else {
            chunks.extend(seg.chunks);
        }

        // record the segment
        segment_paths.push(seg.path);

        if seg.done {
            if done {
                warn!("more segments after finding done section");
            } else {
                done = true;
            }
        }
    }

    if !done {
        warn!("read all segments without finding done section");
    }

    let volume = volume.expect("volume section must have been found");

    Ok(E01Metadata {
        volume,
        md5: stored_md5,
        sha1: stored_sha1,
        segment_paths,
        chunks,
    })
}

/// `sectors_per_chunk` and `bytes_per_sector` are read straight out of the
/// image's volume section, and `read_at_offset` divides by their product. A
/// crafted image declaring either as zero would otherwise panic the reader with
/// a divide-by-zero on the first read.
fn validate_volume(volume: &VolumeSection) -> Result<(), OpenError> {
    if volume.chunk_size() == 0 {
        return Err(OpenError::InvalidVolumeGeometry {
            sectors_per_chunk: volume.sectors_per_chunk,
            bytes_per_sector: volume.bytes_per_sector,
        });
    }
    Ok(())
}

/// The declared image size (`total_sector_count * bytes_per_sector`) and the
/// chunk table are independent fields of the image. `read_at_offset` indexes
/// `self.chunks` by `offset / chunk_size`, so a declared size larger than the
/// chunks actually cover would let a read near the end index past the chunk
/// array and panic. Reject that at open.
fn validate_chunk_coverage(
    image_size: u64,
    chunk_count: usize,
    chunk_size: usize,
) -> Result<(), OpenError> {
    let chunk_coverage = (chunk_count as u64).saturating_mul(chunk_size as u64);
    if image_size > chunk_coverage {
        return Err(OpenError::DeclaredSizeExceedsChunks {
            image_size,
            chunk_coverage,
        });
    }
    Ok(())
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum CorruptSectionPolicy {
    #[default]
    Error,
    DamnTheTorpedoes,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum CorruptChunkPolicy {
    Error,
    #[default]
    Zero,
    RawIfPossible,
}

/// Default concurrent S3 segment fetches (foyer cache misses).
pub const DEFAULT_S3_CONCURRENCY: usize = 8;

/// Threads for the chunk-decompression pool.
///
/// Measured by sweeping `e01verify --parallel-threads N` over a 28 GiB image on
/// a 32-core machine (wall / total CPU):
///
/// ```text
///   32 (one per core)   64.4s / 484s      2 threads   63.5s / 152s
///   16                  62.6s / 303s      serial      81.9s / 148s
///    8                  61.0s / 193s
///    4                  60.7s / 162s   <-- fastest, and 3x less CPU than 32
/// ```
///
/// Four threads beat thirty-two on wall clock *and* used a third of the CPU. A
/// 1 MiB read is only ~1-2ms of inflate; splitting it 32 ways gives each worker
/// ~30us of work, and waking and parking them costs more than the work does
/// (sys time: 2m58 at 32 threads, 13s at 4).
pub const DEFAULT_PARALLEL_CHUNK_THREADS: usize = 4;

/// Default foyer memory cache capacity, in MiB.
pub const DEFAULT_CACHE_MEM_MIB: usize = 1024;

/// Default size of a foyer block: one byte range fetched from the backing store.
///
/// This is the unit of *fetch*, not of decompression -- an e01 chunk is ~32 KiB,
/// and a block holds many of them. It is worth tuning against the backing store,
/// because it decides how many round trips a workload costs. Measured against an
/// S3-backed image, a range GET's cost is almost entirely fixed latency: 1 MiB
/// took 221 ms and 16 MiB took 153 ms, so the bytes are nearly free and it is the
/// *number* of GETs that sets the runtime. Larger blocks fetch more and wait less.
///
/// It stays 1 MiB by default because that is only true of a high-latency store.
/// Against a local file, a larger block is wasted bandwidth on scattered reads.
pub const DEFAULT_CACHE_BLOCK_SIZE: usize = 1024 * 1024;

/// Default bytes pulled from the backing store per cache miss.
///
/// Distinct from the block size on purpose. Fetching wants to be big -- an S3
/// range GET is almost pure fixed latency, so the runtime tracks round trips, not
/// bytes. Caching wants to stay small -- on a large image the metadata working
/// set already fills the cache, and a coarse block evicts useful blocks to hold
/// bytes nobody asked for. When this exceeds the block size, one GET fills
/// several blocks, and the unused ones are separate entries an LRU drops first.
///
/// Equal to the block size by default: coalescing pays only against a
/// high-latency store, and against a local file it is wasted bandwidth.
pub const DEFAULT_CACHE_FETCH_SIZE: usize = DEFAULT_CACHE_BLOCK_SIZE;

#[derive(Debug, Clone)]
pub struct E01ReaderOptions {
    pub corrupt_section_policy: CorruptSectionPolicy,
    pub corrupt_chunk_policy: CorruptChunkPolicy,
    /// Foyer backing-cache readahead in blocks (S3/file segment fetch). 0 disables.
    pub foyer_readahead: usize,
    /// Max concurrent in-flight S3 segment byte-range fetches. 0 = serial.
    pub s3_concurrency: usize,
    /// Foyer in-memory cache capacity in MiB (see [`DEFAULT_CACHE_MEM_MIB`]).
    /// Divided by the block size to get foyer's entry count.
    pub cache_mem_mib: usize,
    /// Cache/eviction granularity, in bytes (see [`DEFAULT_CACHE_BLOCK_SIZE`]).
    pub cache_block_size: usize,
    /// Bytes read from the backing store per miss (see [`DEFAULT_CACHE_FETCH_SIZE`]).
    /// When larger than `cache_block_size`, one fetch fills several blocks.
    pub cache_fetch_size: usize,
    /// Cache structure for this session (single vs dedicated-metadata).
    pub cache_mode: CacheMode,
    /// Base directory for foyer's on-disk cache (created as a random subdir
    /// under this path). `None` uses the OS default temp directory.
    pub cache_dir: Option<PathBuf>,
    /// When set, generate JSONL I/O logging (see [`IoLog`]). This will hose performance; only enable it as a diagnostic.
    pub io_log: Option<Arc<IoLog>>,
    /// Threads to use for `parallel_chunk_reads`. 0 uses rayon's global pool
    /// (one thread per core).
    ///
    /// A 1 MiB read is 32 chunks of ~1-2ms of total decompression. Handing that
    /// to one thread per core gives each ~30us of work and then parks them all
    /// again; the park/unpark futexes cost more than the inflate does. See
    /// [`DEFAULT_PARALLEL_CHUNK_THREADS`] for the sweep.
    ///
    /// Capped by `available_parallelism()`, so a pinned or cgroup-limited
    /// process doesn't oversubscribe its cores. The pool is shared between
    /// readers asking for the same count, so opening many images doesn't spawn
    /// many pools.
    pub parallel_chunk_threads: usize,

    /// Keep a secondary LRU of *decompressed* chunks, in front of the foyer
    /// block cache.
    ///
    /// It only pays when a chunk is read more than once -- e.g. a filesystem
    /// issuing 4 KiB reads inside a 32 KiB chunk. On a sequential whole-image
    /// scan every chunk is touched exactly once, so the hit rate is zero and it
    /// is pure overhead: an Arc<Vec<u8>> allocation, an insert and an eviction
    /// per chunk, for a lookup that never comes.
    pub decoded_chunk_cache: bool,

    /// Read segments that are local files directly, with positioned reads,
    /// instead of through the foyer block cache.
    ///
    /// The OS page cache already caches a local file, so the block cache only
    /// adds work: a tokio `block_on` per chunk, and a whole block copied out of
    /// the page cache for every 32 KiB chunk. With this on (the default) the
    /// cache options apply only to segments that are not local files, and
    /// opening an all-local image starts no tokio runtime and builds no cache.
    pub direct_file_io: bool,

    /// Decompress a multi-chunk read's chunks in parallel, over rayon.
    ///
    /// With [`DEFAULT_PARALLEL_CHUNK_THREADS`], a whole-image verify of a 28 GiB
    /// image takes 60.7s using 162s of CPU, against 81.9s and 148s serially --
    /// 26% off the wall clock for 9% more CPU. (Before the pool was bounded this
    /// was 3.3x the CPU, nearly all of it kernel time spent waking and parking
    /// 32 threads to do 30us of work each.)
    pub parallel_chunk_reads: bool,
}

impl Default for E01ReaderOptions {
    fn default() -> Self {
        Self {
            corrupt_section_policy: CorruptSectionPolicy::default(),
            corrupt_chunk_policy: CorruptChunkPolicy::default(),
            foyer_readahead: 0,
            s3_concurrency: DEFAULT_S3_CONCURRENCY,
            cache_mem_mib: DEFAULT_CACHE_MEM_MIB,
            cache_block_size: DEFAULT_CACHE_BLOCK_SIZE,
            cache_fetch_size: DEFAULT_CACHE_FETCH_SIZE,
            cache_mode: CacheMode::default(),
            cache_dir: None,
            io_log: None,
            parallel_chunk_reads: true,
            parallel_chunk_threads: DEFAULT_PARALLEL_CHUNK_THREADS,
            decoded_chunk_cache: true,
            direct_file_io: true,
        }
    }
}

/// Where chunk bytes come from.
enum ChunkStore {
    /// Local segment files, read directly; see `localsource`.
    Local(Vec<Arc<File>>),
    /// Segments read through the foyer block cache: S3, or local files with
    /// `direct_file_io` off.
    Cached {
        cache: Arc<dyn Cache>,
        runtime: Arc<Runtime>,
    },
}

/// Number of independently locked worker lists. Each thread draws from one,
/// so concurrent readers rarely contend for a worker.
const WORKER_POOL_SHARDS: usize = 16;

static NEXT_WORKER_SHARD: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static WORKER_SHARD: Cell<usize> =
        Cell::new(NEXT_WORKER_SHARD.fetch_add(1, Ordering::Relaxed) % WORKER_POOL_SHARDS);
}

/// Decoder scratch, checked out per chunk.
///
/// A ReadWorker is an inflater plus two chunk-sized buffers (~64 KiB), so
/// pooling them costs a little memory per concurrent read and nothing else.
/// A lock is held only to pop and push, never across a read, and threads are
/// spread over shards so that even that rarely contends.
struct WorkerPool {
    shards: Box<[Mutex<Vec<ReadWorker>>]>,
}

impl WorkerPool {
    fn new() -> Self {
        Self {
            shards: (0..WORKER_POOL_SHARDS).map(|_| Mutex::default()).collect(),
        }
    }

    fn shard(&self) -> &Mutex<Vec<ReadWorker>> {
        &self.shards[WORKER_SHARD.with(Cell::get)]
    }

    fn checkout(&self, new: impl FnOnce() -> ReadWorker) -> ReadWorker {
        let pooled = self.shard().lock().expect("worker pool poisoned").pop();
        pooled.unwrap_or_else(new)
    }

    fn give_back(&self, worker: ReadWorker) {
        self.shard()
            .lock()
            .expect("worker pool poisoned")
            .push(worker);
    }
}

pub struct E01Reader {
    chunks: Vec<Chunk>,

    pub chunk_size: usize,
    pub chunk_count: usize,
    pub sector_size: usize,
    pub sector_count: usize,
    pub image_size: u64,

    pub stored_md5: Option<[u8; 16]>,
    pub stored_sha1: Option<[u8; 20]>,

    /// Segment files in sequence order; `Chunk::segment` indexes this.
    pub segment_paths: Vec<PathBuf>,

    corrupt_chunk_policy: CorruptChunkPolicy,

    /// Decoder scratch. `read_at_offset` takes `&self`, so a reader serves
    /// concurrent reads without a lock around it: the workers are the only
    /// mutable state a read needs, and each read checks out its own.
    ///
    /// (`read_at_offset` used to take `&mut self` for exactly this, which
    /// forced a server to put the whole reader behind one lock: 8 concurrent
    /// clients got *less* throughput than one, with a p99 of 28ms against
    /// 0.35ms.)
    worker_pool: WorkerPool,
    store: ChunkStore,
    /// `None` disables the decoded-chunk cache entirely -- there is then no
    /// lock to take and no chunk to insert, rather than a cache that is merely
    /// never asked for anything.
    decoded_chunk_cache: Option<DecodedChunkCache>,
    io_log: Option<Arc<IoLog>>,
    parallel_chunk_reads: bool,
    parallel_chunk_threads: usize,
    /// Built on the first read that fans out, so opening an image -- or
    /// reading it a chunk at a time -- spawns no threads. Inner `None` uses
    /// rayon's global pool.
    chunk_pool: OnceLock<Option<Arc<rayon::ThreadPool>>>,
}

const DECODED_CHUNK_CACHE_CHUNKS: usize = 1024;

/// One chunk's worth of a read: which chunk, which part of it, and where in
/// the caller's buffer it goes.
struct ChunkTask<'a> {
    chunk_index: usize,
    buf: &'a mut [u8],
    beg_in_chunk: usize,
    end_in_chunk: usize,
}

/// Fewest chunks in a read worth fanning out over the decompression pool.
/// Below this, waking a helper costs about what it would save.
const FAN_OUT_MIN_CHUNKS: usize = 3;

/// Threads this process may actually use.
///
/// Respects `sched_setaffinity` (`taskset`) and cgroup CPU quotas, which is the
/// whole point: a fixed thread count oversubscribes a pinned or containerized
/// process and thrashes. Pinned to 2 CPUs, a 4-thread pool made e01's benches
/// 5x slower.
fn available_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Chunk-decompression pools, shared across readers and keyed by thread count.
///
/// A thread pool is a process-level resource, so building one per `E01Reader`
/// spawns N OS threads on every open and holds them idle for the reader's life.
/// A server that opens an image per client would pay that every time. Held by
/// `Weak`, so a pool goes away once the last reader using it does.
static CHUNK_POOLS: LazyLock<Mutex<HashMap<usize, Weak<rayon::ThreadPool>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The shared pool for `requested` threads, or `None` to use rayon's global one.
fn chunk_pool(requested: usize) -> Result<Option<Arc<rayon::ThreadPool>>, OpenError> {
    if requested == 0 {
        return Ok(None);
    }

    let threads = requested.min(available_parallelism()).max(1);

    let mut pools = CHUNK_POOLS.lock().expect("chunk pool registry poisoned");

    if let Some(pool) = pools.get(&threads).and_then(Weak::upgrade) {
        return Ok(Some(pool));
    }

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .thread_name(|i| format!("e01-chunk-{i}"))
        .build()
        .map(Arc::new)
        .map_err(|e| OpenError::from(std::io::Error::other(e)))?;

    pools.insert(threads, Arc::downgrade(&pool));
    Ok(Some(pool))
}

impl E01Reader {
    /// Read one chunk's part of a read.
    fn read_task(
        &self,
        task: &mut ChunkTask<'_>,
        foyer_trace: Option<&Mutex<ReadTrace>>,
    ) -> Result<(), ReadError> {
        let chunk = &self.chunks[task.chunk_index];
        let mut worker = self.worker_pool.checkout(|| {
            ReadWorker::new(self.chunk_size, self.image_size, self.corrupt_chunk_policy)
        });
        let cache = self.decoded_chunk_cache.as_ref();

        let result = match &self.store {
            ChunkStore::Local(files) => worker.read_chunk(
                chunk,
                &mut LocalSource(&files[chunk.segment]),
                task.chunk_index,
                task.buf,
                task.beg_in_chunk,
                task.end_in_chunk,
                cache,
                true,
            ),
            ChunkStore::Cached { cache: c, runtime } => worker.read_chunk(
                chunk,
                &mut CacheWorkerSource {
                    cache: c.as_ref(),
                    runtime,
                    idx: chunk.segment,
                    foyer_trace,
                },
                task.chunk_index,
                task.buf,
                task.beg_in_chunk,
                task.end_in_chunk,
                cache,
                true,
            ),
        };

        // Back to the pool even if the chunk failed, or a bad image would
        // drain it.
        self.worker_pool.give_back(worker);
        result
            .map_err(ReadError::from)
            .map_err(|e| e.with_path(&self.segment_paths[chunk.segment]))
    }
}

impl Debug for E01Reader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("E01Reader")
            .field("chunks", &self.chunks)
            .field("chunk_size", &self.chunk_size)
            .field("chunk_count", &self.chunk_count)
            .field("sector_size", &self.sector_size)
            .field("sector_count", &self.sector_count)
            .field("image_size", &self.image_size)
            .field("stored_md5", &self.stored_md5)
            .field("stored_sha1", &self.stored_sha1)
            .field("segment_paths", &self.segment_paths)
            .field("corrupt_chunk_policy", &self.corrupt_chunk_policy)
            .finish()
    }
}

fn new_runtime() -> Result<Arc<Runtime>, OpenError> {
    Ok(Arc::new(
        tokio::runtime::Runtime::new().map_err(InitError::TokioRuntimeFailed)?,
    ))
}

impl E01Reader {
    pub fn open_glob<T: AsRef<str>>(
        example_segment_path: T,
        options: &E01ReaderOptions,
    ) -> Result<Self, OpenError> {
        let url = path_or_url_to_url(&example_segment_path)
            .ok_or(OpenError::BadPath(example_segment_path.as_ref().into()))?;

        match url.scheme() {
            "file" => Self::open_impl(
                validated_segment_paths(example_segment_path, FileChecker)?,
                options,
                None,
                None,
            ),
            "s3" => {
                let runtime = new_runtime()?;
                let s3_auth = resolve_s3_auth(&runtime).map_err(OpenError::from)?;
                let auth = Arc::new(s3_auth);
                Self::open_impl(
                    validated_segment_paths(
                        example_segment_path,
                        S3Checker::new(&url, runtime.clone(), auth.clone())?,
                    )?,
                    options,
                    Some(runtime),
                    Some(auth),
                )
            }
            _ => Err(OpenError::UnsupportedScheme(url.to_string())),
        }
    }

    pub fn open<T: IntoIterator<Item: AsRef<str>>>(
        segment_paths: T,
        options: &E01ReaderOptions,
    ) -> Result<Self, OpenError> {
        let paths: Vec<String> = segment_paths
            .into_iter()
            .map(|p| p.as_ref().to_string())
            .collect();
        let (runtime, s3_auth) = if paths.iter().any(|p| p.starts_with("s3://")) {
            let runtime = new_runtime()?;
            let auth = resolve_s3_auth(&runtime).map_err(OpenError::from)?;
            (Some(runtime), Some(Arc::new(auth)))
        } else {
            (None, None)
        };

        Self::open_impl(paths, options, runtime, s3_auth)
    }

    /// The segment files themselves, when every segment is a local file and
    /// direct I/O is on; `None` means go through the block cache.
    fn local_segment_files(
        segment_paths: &[String],
        options: &E01ReaderOptions,
    ) -> Result<Option<Vec<Arc<File>>>, OpenError> {
        if !options.direct_file_io {
            return Ok(None);
        }

        let mut file_paths = Vec::with_capacity(segment_paths.len());
        for p in segment_paths {
            let url = path_or_url_to_url(p).ok_or(OpenError::BadPath(p.clone()))?;
            if url.scheme() != "file" {
                return Ok(None);
            }
            file_paths.push(
                url.to_file_path()
                    .map_err(|_| OpenError::BadPath(p.clone()))?,
            );
        }

        segment_paths
            .iter()
            .zip(file_paths)
            .map(|(p, fp)| {
                File::open(fp)
                    .map(Arc::new)
                    .map_err(|e| OpenError::Source(imagesource::OpenError::from(e).with_path(p)))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }

    /// Build the block cache that segments are read through when they are not
    /// read directly.
    fn build_cache(
        options: &E01ReaderOptions,
        runtime: &Runtime,
    ) -> Result<Arc<dyn Cache>, OpenError> {
        // Not clamped to 1: a zero here means "unset", and the cache's own
        // fallback is the 1 MiB default. `.max(1)` produced a *1-byte* block size
        // instead -- a memory budget of a billion entries, and one cache entry per
        // byte of every read -- while vmdk and rawdisk, which pass the value
        // straight through, got the sane fallback.
        let cache_chunk_size = options.cache_block_size;
        let cache_fetch_size = options.cache_fetch_size.max(cache_chunk_size);
        let cache_mem_size = options.cache_mem_mib;
        let foyer_readahead = options.foyer_readahead;
        let s3_concurrency = options.s3_concurrency;
        let c = match options.cache_mode.clone() {
            CacheMode::SingleMemory => runtime
                .block_on(FoyerCache::single_memory(
                    cache_chunk_size,
                    cache_fetch_size,
                    cache_mem_size,
                    foyer_readahead,
                    s3_concurrency,
                    options.cache_dir.as_deref(),
                ))
                .map_err(InitError::CacheSetupFailed)?,
            CacheMode::DualHybrid {
                content_disk_mib,
                metadata_mem_mib,
                metadata_disk_mib,
                regular_phase,
            } => runtime
                .block_on(FoyerCache::dual_hybrid(
                    cache_chunk_size,
                    cache_fetch_size,
                    cache_mem_size,
                    content_disk_mib,
                    metadata_mem_mib,
                    metadata_disk_mib,
                    foyer_readahead,
                    s3_concurrency,
                    regular_phase,
                    options.cache_dir.as_deref(),
                ))
                .map_err(InitError::CacheSetupFailed)?,
        };

        Ok(Arc::new(c.with_io_log(options.io_log.clone())))
    }

    fn open_impl(
        segment_paths: Vec<String>,
        options: &E01ReaderOptions,
        runtime: Option<Arc<Runtime>>,
        s3_auth: Option<Arc<S3Auth>>,
    ) -> Result<Self, OpenError> {
        if segment_paths.is_empty() {
            return Err(OpenError::NoSegmentFiles);
        }

        let ignore_checksums =
            options.corrupt_section_policy == CorruptSectionPolicy::DamnTheTorpedoes;

        // read the segment metadata
        let (segs, store) = match Self::local_segment_files(&segment_paths, options)? {
            Some(files) => {
                let read_one = |(idx, (sp, file)): (usize, (String, &Arc<File>))| {
                    let io = make_local_bytes_reader(file.clone(), &sp)?;
                    read_segment(sp, idx, &io, ignore_checksums)
                };
                let work: Vec<_> = segment_paths.into_iter().zip(&files).enumerate().collect();
                // Parsing a local segment takes about a millisecond, so a
                // thread each for a handful of them beats waking rayon's
                // global pool, which spawns a thread per core the first time.
                let segs =
                    if work.len() == 1 {
                        work.into_iter()
                            .map(read_one)
                            .collect::<Result<Vec<_>, _>>()?
                    } else {
                        std::thread::scope(|scope| {
                            let per_thread = work.len().div_ceil(available_parallelism().min(8));
                            let mut work = work.into_iter().peekable();
                            let mut handles = vec![];
                            while work.peek().is_some() {
                                let mine: Vec<_> = work.by_ref().take(per_thread).collect();
                                handles.push(scope.spawn(move || {
                                    mine.into_iter().map(read_one).collect::<Vec<_>>()
                                }));
                            }
                            handles
                                .into_iter()
                                .flat_map(|h| h.join().expect("segment parser panicked"))
                                .collect::<Result<Vec<_>, _>>()
                        })?
                    };
                (segs, ChunkStore::Local(files))
            }
            None => {
                let runtime = match runtime {
                    Some(r) => r,
                    None => new_runtime()?,
                };
                let cache = Self::build_cache(options, &runtime)?;
                let io_log = options.io_log.clone();
                let segs = segment_paths
                    .into_par_iter()
                    .enumerate()
                    .map(|(idx, sp)| {
                        let io = make_bytes_reader(
                            &sp,
                            idx,
                            cache.clone(),
                            runtime.clone(),
                            s3_auth.as_ref(),
                            io_log.clone(),
                        )?;
                        read_segment(sp, idx, &io, ignore_checksums)
                    })
                    .collect::<Result<Vec<SegmentComponents>, _>>()?;
                (segs, ChunkStore::Cached { cache, runtime })
            }
        };

        // process segment metadata
        let meta = process_segments(segs)?;

        validate_volume(&meta.volume)?;

        let exp_chunk_count = meta.volume.chunk_count as usize;
        let chunk_count = meta.chunks.len();

        if chunk_count > exp_chunk_count {
            return Err(OpenError::TooManyChunks(chunk_count, exp_chunk_count));
        } else if chunk_count < exp_chunk_count {
            return Err(OpenError::TooFewChunks(chunk_count, exp_chunk_count));
        }

        let chunk_size = meta.volume.chunk_size();
        let sector_count = meta.volume.total_sector_count as usize;
        let sector_size = meta.volume.bytes_per_sector as usize;
        let image_size = meta.volume.max_offset() as u64;

        validate_chunk_coverage(image_size, chunk_count, chunk_size)?;

        Ok(Self {
            chunks: meta.chunks,
            chunk_count,
            chunk_size,
            sector_count,
            sector_size,
            image_size,
            stored_md5: meta.md5,
            stored_sha1: meta.sha1,
            segment_paths: meta.segment_paths.into_iter().map(PathBuf::from).collect(),
            corrupt_chunk_policy: options.corrupt_chunk_policy,
            worker_pool: WorkerPool::new(),
            store,
            decoded_chunk_cache: options
                .decoded_chunk_cache
                .then(|| DecodedChunkCache::new(DECODED_CHUNK_CACHE_CHUNKS)),
            io_log: options.io_log.clone(),
            parallel_chunk_reads: options.parallel_chunk_reads,
            parallel_chunk_threads: options.parallel_chunk_threads,
            chunk_pool: OnceLock::new(),
        })
    }

    /// The pool a read fans out over, built on first use. A pool that cannot
    /// be built degrades to rayon's global one rather than failing reads.
    fn chunk_pool(&self) -> Option<&rayon::ThreadPool> {
        self.chunk_pool
            .get_or_init(|| chunk_pool(self.parallel_chunk_threads).unwrap_or(None))
            .as_deref()
    }

    /// Takes `&self`: a reader can serve concurrent reads without a lock around
    /// it. See `worker_pool` for what used to require `&mut`.
    pub fn read_at_offset(&self, offset: u64, mut buf: &mut [u8]) -> Result<usize, ReadError> {
        let timer = self.io_log.as_ref().map(|_| ReadTimer::start());
        // don't start reading past the end
        let image_end = self.image_size;
        if offset > image_end {
            return Err(ReadErrorKind::OffsetBeyondEnd(offset, image_end).into());
        }

        // limit the buffer to the image end
        if offset + buf.len() as u64 > image_end {
            buf = &mut buf[..(image_end - offset) as usize];
        }

        let buf_beg = offset;
        let buf_end = offset + buf.len() as u64;
        let read_len = buf.len();

        let chunk_size = self.chunk_size as u64;

        let beg_chunk_index = (buf_beg / chunk_size) as usize;
        // A read of nothing touches no chunk -- not even the one it starts in,
        // which rounding its end up would otherwise decode for nothing.
        let end_chunk_index = match read_len {
            0 => beg_chunk_index,
            _ => buf_end.div_ceil(chunk_size) as usize,
        };
        let n_chunks = end_chunk_index.saturating_sub(beg_chunk_index);

        let tracing = self.io_log.is_some();

        let chunk_hit = if tracing {
            self.decoded_chunk_cache
                .as_ref()
                .map(|cache| (beg_chunk_index..end_chunk_index).all(|idx| cache.get(idx).is_some()))
        } else {
            None
        };

        // Only a read through the block cache has a foyer verdict to report.
        let foyer_trace = (tracing && matches!(self.store, ChunkStore::Cached { .. }))
            .then(|| Mutex::new(ReadTrace::default()));

        let trace = foyer_trace.as_ref();

        if n_chunks == 1 {
            // The common case for a small read, with no task list to build.
            let beg_in_chunk = (buf_beg - beg_chunk_index as u64 * chunk_size) as usize;
            let mut task = ChunkTask {
                chunk_index: beg_chunk_index,
                buf,
                beg_in_chunk,
                end_in_chunk: beg_in_chunk + read_len,
            };
            self.read_task(&mut task, trace)?;
        } else if n_chunks > 1 {
            self.read_chunks(buf, buf_beg, beg_chunk_index, end_chunk_index, trace)?;
        }

        if let Some(log) = &self.io_log {
            let dur_us = timer.as_ref().map(ReadTimer::elapsed_us).unwrap_or(0);
            let foyer = foyer_trace
                .as_ref()
                .map_or("n/a", |t| t.lock().unwrap().foyer_label());
            log.log_read(
                buf_beg,
                read_len,
                dur_us,
                foyer,
                chunk_cache_label(chunk_hit),
            );
        }

        Ok(read_len)
    }

    /// Read a span of several chunks, `[beg_chunk_index, end_chunk_index)`,
    /// into `buf`, which starts at image offset `buf_beg`.
    fn read_chunks(
        &self,
        mut buf: &mut [u8],
        buf_beg: u64,
        beg_chunk_index: usize,
        end_chunk_index: usize,
        trace: Option<&Mutex<ReadTrace>>,
    ) -> Result<(), ReadError> {
        let chunk_size = self.chunk_size as u64;
        let image_end = self.image_size;
        let buf_end = buf_beg + buf.len() as u64;

        let mut tasks = Vec::with_capacity(end_chunk_index - beg_chunk_index);
        let mut chunk_beg = beg_chunk_index as u64 * chunk_size;
        let mut pos = buf_beg;
        for chunk_index in beg_chunk_index..end_chunk_index {
            let chunk_end = (chunk_beg + chunk_size).min(image_end);
            let beg_in_chunk = (pos - chunk_beg) as usize;
            let end_in_chunk = (chunk_end.min(buf_end) - chunk_beg) as usize;

            let (here, rest) = std::mem::take(&mut buf).split_at_mut(end_in_chunk - beg_in_chunk);
            buf = rest;

            tasks.push(ChunkTask {
                chunk_index,
                buf: here,
                beg_in_chunk,
                end_in_chunk,
            });

            pos = chunk_beg + end_in_chunk as u64;
            chunk_beg += chunk_size;
        }

        let run = |task: &mut ChunkTask<'_>| self.read_task(task, trace);

        if self.parallel_chunk_reads && tasks.len() >= FAN_OUT_MIN_CHUNKS {
            let pool = self.chunk_pool();
            let threads = pool.map_or_else(rayon::current_num_threads, |p| p.current_num_threads());
            fanout::run(pool, threads, &mut tasks, &run)
        } else {
            tasks.iter_mut().try_for_each(run)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// A zero block size means "unset", and has to land on the cache's 1 MiB
    /// fallback the way vmdk and rawdisk do. Clamping it to 1 instead gave a
    /// 1-byte block size: a memory budget of ~10^9 entries, and one cache entry
    /// per byte of every read. The read below would not finish in any useful time.
    #[test]
    fn zero_block_size_uses_the_default_not_a_one_byte_block() {
        let options = E01ReaderOptions {
            cache_block_size: 0,
            cache_fetch_size: 0,
            ..Default::default()
        };
        let reader =
            E01Reader::open_glob(crate::test_data::IMAGE_E01.segment_paths[0], &options).unwrap();

        let mut buf = vec![0u8; 4096];
        reader.read_at_offset(0, &mut buf).unwrap();
    }

    /// The per-read residency probe and the shared `ReadTrace` are built only
    /// when tracing is on, and their sole consumer is this trace line. Nothing
    /// else in the tree exercises the tracing-on path, so if the gating were
    /// wrong the fields would silently degrade to "n/a" and no test would notice.
    #[test]
    fn read_trace_reports_decoded_chunk_and_foyer_verdicts() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("io.jsonl");
        let io_log = IoLog::open(&log_path).unwrap();
        io_log.begin_serving().unwrap();

        let options = E01ReaderOptions {
            io_log: Some(io_log.clone()),
            // the foyer verdict exists only on the block-cache path
            direct_file_io: false,
            ..Default::default()
        };
        let reader =
            E01Reader::open_glob(crate::test_data::IMAGE_E01.segment_paths[0], &options).unwrap();

        let mut buf = vec![0u8; 4096];
        // First read decodes the chunk; the second must be served from the
        // decoded-chunk cache.
        reader.read_at_offset(0, &mut buf).unwrap();
        reader.read_at_offset(0, &mut buf).unwrap();

        drop(reader);
        drop(io_log);

        let body = std::fs::read_to_string(&log_path).unwrap();
        let reads: Vec<&str> = body
            .lines()
            .filter(|l| l.contains(r#""kind":"read""#))
            .collect();
        assert_eq!(reads.len(), 2, "one record per read: {body}");
        assert!(
            reads[0].contains(r#""chunk":"miss""#),
            "the first read has to decode: {}",
            reads[0]
        );
        assert!(
            reads[1].contains(r#""chunk":"hit""#),
            "the second read comes from the decoded-chunk cache: {}",
            reads[1]
        );
        assert!(
            !reads[1].contains(r#""foyer":"n/a""#),
            "the foyer verdict must be a real hit/miss, not the unset fallback: {}",
            reads[1]
        );
    }

    /// A declared size that fits within the chunks is fine; one larger than
    /// the chunks cover would index past self.chunks on a read near the end,
    /// so it must be rejected at open.
    #[test]
    fn chunk_coverage_rejects_oversized_declared_size() {
        // 4 chunks * 32 KiB = 128 KiB of coverage.
        let chunk_size = 32 * 1024;
        let chunk_count = 4;
        let coverage = (chunk_count * chunk_size) as u64;

        // exactly covered, and one byte short, are both fine
        assert!(validate_chunk_coverage(coverage, chunk_count, chunk_size).is_ok());
        assert!(validate_chunk_coverage(coverage - 1, chunk_count, chunk_size).is_ok());

        // one byte past the coverage indexes a non-existent chunk
        let err = validate_chunk_coverage(coverage + 1, chunk_count, chunk_size).unwrap_err();
        assert!(
            matches!(err, OpenError::DeclaredSizeExceedsChunks { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn repeated_partial_reads_match_single_read() {
        let options = E01ReaderOptions {
            corrupt_section_policy: CorruptSectionPolicy::Error,
            corrupt_chunk_policy: CorruptChunkPolicy::Error,
            foyer_readahead: 0,
            s3_concurrency: DEFAULT_S3_CONCURRENCY,
            cache_mem_mib: DEFAULT_CACHE_MEM_MIB,
            cache_block_size: DEFAULT_CACHE_BLOCK_SIZE,
            cache_fetch_size: DEFAULT_CACHE_FETCH_SIZE,
            cache_mode: CacheMode::default(),
            cache_dir: None,
            io_log: None,
            parallel_chunk_reads: true,
            parallel_chunk_threads: DEFAULT_PARALLEL_CHUNK_THREADS,
            decoded_chunk_cache: true,
            direct_file_io: true,
        };
        let reader =
            E01Reader::open_glob(crate::test_data::IMAGE_E01.segment_paths[0], &options).unwrap();
        let chunk_size = reader.chunk_size as u64;
        let base = chunk_size * 3;
        let span = 4096usize;

        let mut first = vec![0u8; span];
        let mut second = vec![0u8; span];
        reader.read_at_offset(base + 100, &mut first).unwrap();
        reader
            .read_at_offset(base + 100 + span as u64, &mut second)
            .unwrap();

        let mut combined = vec![0u8; span * 2];
        reader.read_at_offset(base + 100, &mut combined).unwrap();

        assert_eq!(&combined[..span], &first[..]);
        assert_eq!(&combined[span..], &second[..]);
    }

    #[test]
    fn parallel_then_serial_reads_same_chunk_stay_consistent() {
        let options = E01ReaderOptions {
            corrupt_section_policy: CorruptSectionPolicy::Error,
            corrupt_chunk_policy: CorruptChunkPolicy::Error,
            foyer_readahead: 0,
            s3_concurrency: DEFAULT_S3_CONCURRENCY,
            cache_mem_mib: DEFAULT_CACHE_MEM_MIB,
            cache_block_size: DEFAULT_CACHE_BLOCK_SIZE,
            cache_fetch_size: DEFAULT_CACHE_FETCH_SIZE,
            cache_mode: CacheMode::default(),
            cache_dir: None,
            io_log: None,
            parallel_chunk_reads: true,
            parallel_chunk_threads: DEFAULT_PARALLEL_CHUNK_THREADS,
            decoded_chunk_cache: true,
            direct_file_io: true,
        };
        let reader =
            E01Reader::open_glob(crate::test_data::IMAGE_E01.segment_paths[0], &options).unwrap();
        let chunk_size = reader.chunk_size as u64;
        let base = chunk_size * 2;

        let mut cross = vec![0u8; (chunk_size * 2) as usize];
        reader.read_at_offset(base, &mut cross).unwrap();

        let mut again = vec![0u8; 4096];
        reader.read_at_offset(base + 8192, &mut again).unwrap();

        assert_eq!(&again[..], &cross[8192..8192 + 4096]);
    }

    /// A pool is a process-level resource. Building one per reader spawns N OS
    /// threads on every open -- which is why the cold benches, which construct a
    /// fresh reader per iteration, regressed 66-193% when the pool was added.
    /// The whole point of `read_at_offset(&self)`: a server can share one reader
    /// across clients with no lock. If this stops compiling, the API has
    /// regressed to forcing a Mutex around the reader.
    #[test]
    fn reader_is_shareable_across_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<E01Reader>();
    }

    /// Concurrent reads through a shared `&self` reader must return the same
    /// bytes a serial read would -- the worker pool is the only mutable state,
    /// and handing the same worker to two threads would corrupt both.
    #[test]
    fn concurrent_reads_through_one_reader_agree_with_serial_reads() {
        let options = E01ReaderOptions::default();
        let reader = Arc::new(
            E01Reader::open_glob(crate::test_data::IMAGE_E01.segment_paths[0], &options).unwrap(),
        );

        let offsets: Vec<u64> = (0..16).map(|i| i * 4096).collect();

        // What each offset should read, serially.
        let expected: Vec<Vec<u8>> = offsets
            .iter()
            .map(|&off| {
                let mut buf = vec![0u8; 4096];
                let n = reader.read_at_offset(off, &mut buf).unwrap();
                buf.truncate(n);
                buf
            })
            .collect();

        // The same reads, all at once, through one shared reader.
        let handles: Vec<_> = offsets
            .iter()
            .map(|&off| {
                let reader = reader.clone();
                std::thread::spawn(move || {
                    let mut buf = vec![0u8; 4096];
                    let n = reader.read_at_offset(off, &mut buf).unwrap();
                    buf.truncate(n);
                    buf
                })
            })
            .collect();

        for (i, h) in handles.into_iter().enumerate() {
            let got = h.join().expect("reader thread panicked");
            assert_eq!(
                got, expected[i],
                "concurrent read at {} differed",
                offsets[i]
            );
        }
    }

    #[test]
    fn readers_asking_for_the_same_thread_count_share_a_pool() {
        let a = chunk_pool(2).unwrap().expect("a pool");
        let b = chunk_pool(2).unwrap().expect("a pool");

        assert!(Arc::ptr_eq(&a, &b), "each reader built its own pool");
    }

    /// A fixed thread count oversubscribes a pinned or cgroup-limited process:
    /// 4 threads on the 2 CPUs of `taskset -c 2,3` made the benches 5x slower.
    #[test]
    fn the_pool_never_exceeds_available_parallelism() {
        let pool = chunk_pool(1024).unwrap().expect("a pool");

        assert!(
            pool.current_num_threads() <= available_parallelism(),
            "{} threads on {} available CPUs",
            pool.current_num_threads(),
            available_parallelism(),
        );
    }

    #[test]
    fn zero_threads_means_rayons_global_pool() {
        assert!(chunk_pool(0).unwrap().is_none());
    }

    #[test]
    fn open_rejects_zero_volume_geometry() {
        // read_at_offset divides by chunk_size (sectors_per_chunk * bytes_per_sector),
        // so a volume section declaring either as zero must be rejected at open
        // rather than dividing by zero on the first read.
        for (sectors_per_chunk, bytes_per_sector) in [(0, 512), (64, 0), (0, 0)] {
            let volume = VolumeSection {
                chunk_count: 1,
                sectors_per_chunk,
                bytes_per_sector,
                total_sector_count: 1,
            };

            match validate_volume(&volume) {
                Err(OpenError::InvalidVolumeGeometry { .. }) => {}
                other => panic!("expected InvalidVolumeGeometry, got {other:?}"),
            }
        }
    }

    #[test]
    fn validate_volume_accepts_a_sane_geometry() {
        let volume = VolumeSection {
            chunk_count: 1,
            sectors_per_chunk: 64,
            bytes_per_sector: 512,
            total_sector_count: 64,
        };
        assert!(validate_volume(&volume).is_ok());
    }

    /// Read directly from a local file there is no block cache, so no foyer
    /// verdict: the trace must say so rather than report a "hit" that never
    /// happened. The decoded-chunk verdicts are unaffected.
    #[test]
    fn read_trace_on_direct_io_has_no_foyer_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("io.jsonl");
        let io_log = IoLog::open(&log_path).unwrap();
        io_log.begin_serving().unwrap();

        let options = E01ReaderOptions {
            io_log: Some(io_log.clone()),
            ..Default::default()
        };
        assert!(options.direct_file_io);
        let reader =
            E01Reader::open_glob(crate::test_data::IMAGE_E01.segment_paths[0], &options).unwrap();

        let mut buf = vec![0u8; 4096];
        reader.read_at_offset(0, &mut buf).unwrap();
        reader.read_at_offset(0, &mut buf).unwrap();

        drop(reader);
        drop(io_log);

        let body = std::fs::read_to_string(&log_path).unwrap();
        let reads: Vec<&str> = body
            .lines()
            .filter(|l| l.contains(r#""kind":"read""#))
            .collect();
        assert_eq!(reads.len(), 2, "one record per read: {body}");
        assert!(reads[0].contains(r#""chunk":"miss""#), "{}", reads[0]);
        assert!(reads[1].contains(r#""chunk":"hit""#), "{}", reads[1]);
        for r in reads {
            assert!(r.contains(r#""foyer":"n/a""#), "{r}");
        }
    }

    #[test]
    fn last_chunk_ends_with_its_sectors_section() {
        // sectors section [0x100, 0x9000), table after it
        assert_eq!(last_chunk_end(0x8000, 0x9000, 0x9500), 0x9000);
    }

    #[test]
    fn last_chunk_inside_the_table_section_ends_with_it() {
        // no sectors section; the chunk data follows the offsets in the table
        assert_eq!(last_chunk_end(0x2000, 0, 0x9500), 0x9500);
    }

    #[test]
    fn last_chunk_past_both_keeps_bounds_that_fail_the_read() {
        // neither section contains the chunk: leave it inverted, which a read
        // rejects as corrupt bounds rather than guessing a length
        assert!(last_chunk_end(0xa000, 0x9000, 0x9500) < 0xa000);
    }

    /// A section descriptor: 16-byte type, next offset, size, padding and
    /// an unchecked checksum, 76 bytes in all.
    fn section_desc(section_type: &str, next_offset: usize, size: usize) -> Vec<u8> {
        let mut b = vec![0u8; 76];
        b[..section_type.len()].copy_from_slice(section_type.as_bytes());
        b[16..24].copy_from_slice(&(next_offset as u64).to_le_bytes());
        b[24..32].copy_from_slice(&(size as u64).to_le_bytes());
        b
    }

    /// EnCase 1 segments have no `sectors` section: a table section holds
    /// its offsets and then the chunks themselves. The table does not record
    /// where its last chunk ends; here that is the end of the table section.
    #[test]
    fn last_chunk_of_a_table_holding_its_chunks_ends_with_the_table() {
        let n = 3;
        let chunk_len = 64;
        let table_off = 13; // just past the file header
        let entries_off = table_off + 76 + 24;
        let data_off = entries_off + 4 * n + 4;
        let table_end = data_off + n * chunk_len;

        // file header: signature, then segment number 1
        let mut seg = b"EVF\x09\x0d\x0a\xff\x00\x01\x01\x00\x00\x00".to_vec();
        seg.extend(section_desc("table", table_end, table_end - table_off));
        let mut header = vec![];
        header.extend((n as u32).to_le_bytes()); // entry count
        header.extend([0u8; 4]);
        header.extend(0u64.to_le_bytes()); // base offset
        header.extend([0u8; 4]);
        header.extend(crate::sec_read::adler32(&header).to_le_bytes());
        seg.extend(header);
        let entries: Vec<u8> = (0..n)
            .flat_map(|i| ((data_off + i * chunk_len) as u32).to_le_bytes())
            .collect();
        seg.extend(&entries);
        seg.extend(crate::sec_read::adler32(&entries).to_le_bytes());
        seg.extend(vec![0u8; n * chunk_len]);
        seg.extend(section_desc("done", table_end, 76));

        let segment = read_segment("encase1.E01", 0, &BytesReader::from(seg), false).unwrap();
        let bounds: Vec<_> = segment
            .chunks
            .iter()
            .map(|c| (c.data_offset as usize, c.end_offset as usize))
            .collect();
        assert_eq!(
            bounds,
            [
                (data_off, data_off + chunk_len),
                (data_off + chunk_len, data_off + 2 * chunk_len),
                (data_off + 2 * chunk_len, table_end),
            ]
        );
    }

    #[test]
    fn open_rejects_out_of_order_segments() {
        let options = E01ReaderOptions::default();
        let err = E01Reader::open(["data/mimage.E02", "data/mimage.E01"], &options).unwrap_err();
        match err {
            OpenError::SegmentOutOfOrder {
                actual, expected, ..
            } => {
                assert_eq!(actual, 2);
                assert_eq!(expected, 1);
            }
            e => panic!("expected SegmentOutOfOrder, got {e:?}"),
        }
    }
}
