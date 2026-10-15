pub mod e01_reader;

#[cfg(feature = "capi")]
pub mod capi;

#[cfg(test)]
mod test_data;

#[cfg(test)]
mod test_helper;

mod cacheworkersource;
mod error;
mod fanout;
mod generated;
pub mod hasher;
mod localsource;
mod readworker;
mod sec_read;
mod seg_path;
mod segment;
mod workersource;

pub use imagesource::{
    IoLog, ReadTimer, ReadTrace, aligned_fetch_size, chunk_cache_label, init_tracing,
};

#[cfg(test)]
mod test {
    use crate::{
        e01_reader::{
            CacheMode, CorruptChunkPolicy, CorruptSectionPolicy, DEFAULT_CACHE_BLOCK_SIZE,
            DEFAULT_CACHE_FETCH_SIZE, DEFAULT_CACHE_MEM_MIB, DEFAULT_DECODED_CHUNK_CACHE_MIB,
            DEFAULT_PARALLEL_CHUNK_THREADS, DEFAULT_S3_CONCURRENCY, E01Reader, E01ReaderOptions,
        },
        hasher::HashType,
        test_data::*,
        test_helper::do_hash,
    };

    #[track_caller]
    fn assert_eq_test_data(exp: &TestData, options: &E01ReaderOptions) {
        let reader = E01Reader::open_glob(exp.segment_paths[0], options).unwrap();
        assert_eq_reader(&reader, exp);
    }

    #[track_caller]
    fn assert_eq_test_data_nonglob(exp: &TestData, options: &E01ReaderOptions) {
        let reader = E01Reader::open(exp.segment_paths, options).unwrap();
        assert_eq_reader(&reader, exp);
    }

    #[track_caller]
    fn assert_eq_reader(reader: &E01Reader, exp: &TestData) {
        let image_size = reader.image_size;

        let hashes = do_hash(
            |offset, buf: &mut [u8]| reader.read_at_offset(offset, buf).unwrap(),
            image_size,
        );

        let stored_md5 = reader.stored_md5.map(hex::encode);
        let stored_sha1 = reader.stored_sha1.map(hex::encode);

        let segment_paths = reader
            .segment_paths
            .iter()
            .map(|p| p.to_str())
            .collect::<Option<Vec<_>>>()
            .unwrap();

        let act = TestData {
            segment_paths: &segment_paths[..],
            chunk_size: reader.chunk_size,
            chunk_count: reader.chunk_count,
            sector_size: reader.sector_size,
            sector_count: reader.sector_count,
            image_size: reader.image_size,
            stored_md5: stored_md5.as_deref(),
            stored_sha1: stored_sha1.as_deref(),
            md5: hashes.get(&HashType::MD5).map(String::as_str),
            sha1: hashes.get(&HashType::SHA1).map(String::as_str),
            sha256: hashes.get(&HashType::SHA256).map(String::as_str),
        };

        assert_eq!(&act, exp);
    }

    fn error_error() -> E01ReaderOptions {
        E01ReaderOptions {
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
            decoded_chunk_cache_mib: DEFAULT_DECODED_CHUNK_CACHE_MIB,
            sequential_readahead: true,
        }
    }

    fn error_zero() -> E01ReaderOptions {
        E01ReaderOptions {
            corrupt_section_policy: CorruptSectionPolicy::Error,
            corrupt_chunk_policy: CorruptChunkPolicy::Zero,
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
            decoded_chunk_cache_mib: DEFAULT_DECODED_CHUNK_CACHE_MIB,
            sequential_readahead: true,
        }
    }

    #[test]
    fn test_image_e01() {
        assert_eq_test_data(&IMAGE_E01, &error_error());
    }

    #[test]
    fn test_mimage_e01() {
        assert_eq_test_data(&MIMAGE_E01, &error_error());
    }

    #[test]
    fn test_mimage_e01_nonglob() {
        assert_eq_test_data_nonglob(&MIMAGE_E01, &error_error());
    }

    #[test]
    fn test_mimage_e01_zero_bad_chunks() {
        assert_eq_test_data(&MIMAGE_E01, &error_zero());
    }

    #[test]
    #[should_panic]
    fn test_bad_chunk_e01() {
        assert_eq_test_data(&BAD_CHUNK_E01, &error_error());
    }

    #[test]
    fn test_bad_chunk_e01_zero_bad_chunks() {
        assert_eq_test_data(&BAD_CHUNK_E01_ZEROED, &error_zero());
    }

    /// Local files are read directly by default; the same images must read
    /// identically through the block cache, which is what S3 segments use.
    fn through_block_cache(options: E01ReaderOptions) -> E01ReaderOptions {
        E01ReaderOptions {
            direct_file_io: false,
            ..options
        }
    }

    #[test]
    fn test_image_e01_through_block_cache() {
        assert_eq_test_data(&IMAGE_E01, &through_block_cache(error_error()));
    }

    #[test]
    fn test_mimage_e01_through_block_cache() {
        assert_eq_test_data(&MIMAGE_E01, &through_block_cache(error_error()));
    }

    #[test]
    fn test_bad_chunk_e01_zero_bad_chunks_through_block_cache() {
        assert_eq_test_data(&BAD_CHUNK_E01_ZEROED, &through_block_cache(error_zero()));
    }

    #[test]
    #[should_panic]
    fn test_bad_chunk_e01_through_block_cache() {
        assert_eq_test_data(&BAD_CHUNK_E01, &through_block_cache(error_error()));
    }

    /// Every way of carving the image into reads -- sizes that split chunks,
    /// span several, and fan out over the decompression pool -- must produce
    /// the same bytes as one whole-image read, with and without the
    /// decoded-chunk cache and the fan-out.
    #[test]
    fn read_sizes_and_strategies_agree() {
        for path in [IMAGE_E01.segment_paths[0], MIMAGE_E01.segment_paths[0]] {
            let reference = {
                let reader = E01Reader::open_glob(path, &error_error()).unwrap();
                let mut all = vec![0u8; reader.image_size as usize];
                assert_eq!(reader.read_at_offset(0, &mut all).unwrap(), all.len());
                all
            };

            for (cache, fan_out) in [(true, true), (false, true), (true, false), (false, false)] {
                let options = E01ReaderOptions {
                    decoded_chunk_cache: cache,
                    parallel_chunk_reads: fan_out,
                    ..error_error()
                };
                let reader = E01Reader::open_glob(path, &options).unwrap();
                // single bytes, sampled: a byte at a time over the whole image
                // is a chunk decode per byte without the cache
                for off in (0..reference.len()).step_by(4093) {
                    let mut b = [0u8; 1];
                    assert_eq!(reader.read_at_offset(off as u64, &mut b).unwrap(), 1);
                    assert_eq!(b[0], reference[off], "{path}: byte {off}");
                }
                for size in [511, 4096, 32768, 32769, 65536 + 17, 300_000] {
                    let mut buf = vec![0u8; size];
                    // an unaligned start, then contiguous reads to the end
                    let mut off = 7u64;
                    while (off as usize) < reference.len() {
                        let n = reader.read_at_offset(off, &mut buf).unwrap();
                        assert!(n > 0);
                        assert_eq!(
                            &buf[..n],
                            &reference[off as usize..off as usize + n],
                            "{path}: size {size} at {off}, cache {cache}, fan-out {fan_out}"
                        );
                        off += n as u64;
                    }
                }
                // reads at and past the end, and of nothing
                let end = reader.image_size;
                assert_eq!(reader.read_at_offset(end, &mut [0u8; 16]).unwrap(), 0);
                assert!(reader.read_at_offset(end + 1, &mut [0u8; 16]).is_err());
                assert_eq!(reader.read_at_offset(3, &mut []).unwrap(), 0);
            }
        }
    }
}
