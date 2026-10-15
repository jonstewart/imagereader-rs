use std::{
    any::Any,
    ffi::{CStr, CString, c_char, c_int},
    mem::ManuallyDrop,
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    slice,
};

use crate::e01_reader::{self, E01Reader};

#[repr(C)]
pub struct E01Error {
    message: *mut c_char,
}

impl Drop for E01Error {
    fn drop(&mut self) {
        unsafe {
            if !self.message.is_null() {
                drop(CString::from_raw(self.message));
            }
        }
    }
}

fn panic_message(p: Box<dyn Any + Send>) -> String {
    let what = p
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| p.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown cause".into());

    format!("Panic while reading image: {what}")
}

/// Rust aborts the process when a panic unwinds across an `extern "C"` boundary,
/// so every entry point runs its body here. Malformed images can panic deep in
/// the parser; a C caller must get an error back instead of losing the process.
fn guard<T>(err: *mut *mut E01Error, fallback: T, f: impl FnOnce() -> T) -> T {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(p) => {
            fill_error(panic_message(p), err);
            fallback
        }
    }
}

/// Free an error returned through the `err` out-parameter of another entry
/// point.
///
/// # Safety
/// `err` must be null or an `E01Error` written by one of the other entry
/// points and not yet freed. It is dangling once this returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn e01_free_error(err: *mut E01Error) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !err.is_null() {
            unsafe {
                drop(Box::from_raw(err));
            }
        }
    }));
}

// The variant names of these two enums are part of the C API: they appear as
// enum constants in the generated header, so camel-casing them to satisfy
// `non_camel_case_types` would break every C caller.
#[repr(C)]
#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum CorruptSectionPolicy {
    CSP_ERROR,
    CSP_DAMN_THE_TORPEDOES,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum CorruptChunkPolicy {
    CCP_ERROR,
    CCP_ZERO,
    CCP_RAW_IF_POSSIBLE,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct E01ReaderOptions {
    corrupt_section_policy: CorruptSectionPolicy,
    corrupt_chunk_policy: CorruptChunkPolicy,
}

/// Build the Rust reader options from the C caller's struct, validating the
/// policy fields.
///
/// The `corrupt_*_policy` fields are declared as `#[repr(C)]` enums, but C is
/// free to store any integer there. Materializing an out-of-range value as a
/// Rust enum — which `*options` or a by-value `.into()` would do — is undefined
/// behavior before any `match` can reject it. Reading the discriminant as a
/// `c_int` through the field pointer is always valid, so validation runs on a
/// plain integer.
///
/// # Safety
/// `options` must point to a valid, aligned `E01ReaderOptions`.
unsafe fn rust_options(
    options: *const E01ReaderOptions,
) -> Result<e01_reader::E01ReaderOptions, String> {
    let section_raw = unsafe {
        std::ptr::addr_of!((*options).corrupt_section_policy)
            .cast::<c_int>()
            .read()
    };
    let chunk_raw = unsafe {
        std::ptr::addr_of!((*options).corrupt_chunk_policy)
            .cast::<c_int>()
            .read()
    };

    let corrupt_section_policy = match section_raw {
        0 => e01_reader::CorruptSectionPolicy::Error,
        1 => e01_reader::CorruptSectionPolicy::DamnTheTorpedoes,
        n => return Err(format!("invalid corrupt_section_policy value {n}")),
    };
    let corrupt_chunk_policy = match chunk_raw {
        0 => e01_reader::CorruptChunkPolicy::Error,
        1 => e01_reader::CorruptChunkPolicy::Zero,
        2 => e01_reader::CorruptChunkPolicy::RawIfPossible,
        n => return Err(format!("invalid corrupt_chunk_policy value {n}")),
    };

    Ok(e01_reader::E01ReaderOptions {
        corrupt_section_policy,
        corrupt_chunk_policy,
        foyer_readahead: 0,
        s3_concurrency: e01_reader::DEFAULT_S3_CONCURRENCY,
        cache_mem_mib: e01_reader::DEFAULT_CACHE_MEM_MIB,
        cache_block_size: e01_reader::DEFAULT_CACHE_BLOCK_SIZE,
        cache_fetch_size: e01_reader::DEFAULT_CACHE_FETCH_SIZE,
        cache_mode: e01_reader::CacheMode::default(),
        cache_dir: None,
        io_log: None,
        parallel_chunk_reads: true,
        parallel_chunk_threads: e01_reader::DEFAULT_PARALLEL_CHUNK_THREADS,
        decoded_chunk_cache: true,
        direct_file_io: true,
        decoded_chunk_cache_mib: e01_reader::DEFAULT_DECODED_CHUNK_CACHE_MIB,
        sequential_readahead: true,
    })
}

fn fill_error<E: ToString>(e: E, err: *mut *mut E01Error) {
    if !err.is_null() {
        // CString::new doesn't like internal nulls; the error message should
        // not have any, but we must deal with it nonetheless
        let message = CString::new(e.to_string())
            .unwrap_or_else(|_|
                CString::new(
                    format!(
                        "{}. Additionally, the original error message somehow contained an internal null, which should never happen.",
                        e.to_string().replace("\0", "\u{FFFD}")
                    )
                ).expect("inconceivable!")
            )
            .into_raw();

        unsafe {
            *err = Box::into_raw(Box::new(E01Error { message }));
        }
    }
}

#[repr(C)]
pub struct E01Handle {
    reader: *mut E01Reader,
    pub segment_paths: *const *const c_char,
    pub segment_paths_count: usize,
    pub chunk_size: usize,
    pub chunk_count: usize,
    pub sector_count: usize,
    pub sector_size: usize,
    pub image_size: u64,
    pub stored_md5: *const u8,
    pub stored_sha1: *const u8,
}

unsafe fn free_c_str_array(ptr: *mut *mut c_char, len: usize) {
    // Vec should have been shrunk to fit so length == capacity
    let v = unsafe { Vec::from_raw_parts(ptr, len, len) };

    for s in v {
        drop(unsafe { CString::from_raw(s) });
    }
}

fn paths_to_cstring_vec<'a, P, T>(paths: T) -> Result<Vec<CString>, String>
where
    P: AsRef<Path> + 'a,
    T: IntoIterator<Item = &'a P>,
{
    paths
        .into_iter()
        .enumerate()
        .map(|(i, p)| {
            p.as_ref()
                .to_str()
                .ok_or_else(|| format!("path {i} is not UTF-8"))
                .and_then(|s| {
                    CString::new(s).map_err(|_| format!("path {i} contains an internal null"))
                })
        })
        .collect::<Result<Vec<_>, _>>()
}

fn opt_array_to_ptr<const N: usize>(a: Option<[u8; N]>) -> *const u8 {
    match a {
        None => std::ptr::null_mut(),
        Some(a) => {
            let mut v = a.to_vec();
            v.shrink_to_fit();
            ManuallyDrop::new(v).as_ptr()
        }
    }
}

impl E01Handle {
    fn new(reader: E01Reader) -> Result<Self, String> {
        // convert paths into CStrings, which will be dropped on error
        let segment_paths = paths_to_cstring_vec(&reader.segment_paths)?;

        // convert CStrings into *const c_char, which must be freed by
        // calling e01_close on the handle
        let mut segment_paths = segment_paths
            .into_iter()
            .map(|sp| sp.into_raw() as *const c_char)
            .collect::<Vec<_>>();

        // ensure that capacity == len, so we don't need to store both
        segment_paths.shrink_to_fit();

        let segment_paths = ManuallyDrop::new(segment_paths).as_ptr();

        Ok(Self {
            segment_paths,
            segment_paths_count: reader.segment_paths.len(),
            chunk_size: reader.chunk_size,
            chunk_count: reader.chunk_count,
            sector_count: reader.sector_count,
            sector_size: reader.sector_size,
            image_size: reader.image_size,
            stored_md5: opt_array_to_ptr(reader.stored_md5),
            stored_sha1: opt_array_to_ptr(reader.stored_sha1),
            reader: Box::into_raw(Box::new(reader)),
        })
    }
}

impl Drop for E01Handle {
    fn drop(&mut self) {
        unsafe {
            free_c_str_array(
                self.segment_paths as *mut *mut c_char,
                self.segment_paths_count,
            );
        }

        if !self.stored_md5.is_null() {
            drop(unsafe { Vec::from_raw_parts(self.stored_md5 as *mut u8, 16, 16) });
        }

        if !self.stored_sha1.is_null() {
            drop(unsafe { Vec::from_raw_parts(self.stored_sha1 as *mut u8, 20, 20) });
        }

        drop(unsafe { Box::from_raw(self.reader) });
    }
}

/// Open an E01 image from an explicit list of segment paths. Returns null on
/// failure, having written an error to `err`; the returned handle must be freed
/// with `e01_close`.
///
/// # Safety
/// `segment_paths` must be null or point to `segment_paths_count` valid
/// NUL-terminated C strings. `options` must be null or point to a valid,
/// aligned `E01ReaderOptions`. `err` must be null or point to a writable,
/// aligned `*mut E01Error`; anything already stored there is overwritten, not
/// freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn e01_open(
    segment_paths: *const *const c_char,
    segment_paths_count: usize,
    options: *const E01ReaderOptions,
    err: *mut *mut E01Error,
) -> *mut E01Handle {
    guard(err, std::ptr::null_mut(), || {
        // convert options
        if options.is_null() {
            fill_error("options is null", err);
            return std::ptr::null_mut();
        }

        let options = match unsafe { rust_options(options) } {
            Ok(o) => o,
            Err(e) => {
                fill_error(e, err);
                return std::ptr::null_mut();
            }
        };

        // convert paths
        if segment_paths.is_null() {
            fill_error("segment_paths is null", err);
            return std::ptr::null_mut();
        }

        if segment_paths_count == 0 {
            fill_error("segment_paths_count is zero", err);
            return std::ptr::null_mut();
        }

        let sl = unsafe { slice::from_raw_parts(segment_paths, segment_paths_count) };
        let mut segment_paths = Vec::with_capacity(sl.len());

        for (i, p) in sl.iter().enumerate() {
            if p.is_null() {
                fill_error(format!("segment_paths[{i}] is null"), err);
                return std::ptr::null_mut();
            }

            let p = unsafe { CStr::from_ptr(*p) };

            let Ok(sp) = p.to_str() else {
                fill_error(format!("segment_paths[{i}] is not UTF-8"), err);
                return std::ptr::null_mut();
            };

            segment_paths.push(sp);
        }

        // do the open
        match E01Reader::open(segment_paths, &options) {
            Ok(reader) => match E01Handle::new(reader) {
                Ok(handle) => Box::into_raw(Box::new(handle)),
                Err(e) => {
                    fill_error(e, err);
                    std::ptr::null_mut()
                }
            },
            Err(e) => {
                fill_error(e, err);
                std::ptr::null_mut()
            }
        }
    })
}

/// Open an E01 image, discovering its segments from the path of any one of
/// them. Returns null on failure, having written an error to `err`; the
/// returned handle must be freed with `e01_close`.
///
/// # Safety
/// `example_segment_path` must be null or a valid NUL-terminated C string.
/// `options` must be null or point to a valid, aligned `E01ReaderOptions`.
/// `err` must be null or point to a writable, aligned `*mut E01Error`; anything
/// already stored there is overwritten, not freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn e01_open_glob(
    example_segment_path: *const c_char,
    options: *const E01ReaderOptions,
    err: *mut *mut E01Error,
) -> *mut E01Handle {
    guard(err, std::ptr::null_mut(), || {
        // convert options
        if options.is_null() {
            fill_error("options is null", err);
            return std::ptr::null_mut();
        }

        let options = match unsafe { rust_options(options) } {
            Ok(o) => o,
            Err(e) => {
                fill_error(e, err);
                return std::ptr::null_mut();
            }
        };

        // convert path
        if example_segment_path.is_null() {
            fill_error("example_segment_path is null", err);
            return std::ptr::null_mut();
        }

        let p = unsafe { CStr::from_ptr(example_segment_path) };

        let Ok(sp) = p.to_str() else {
            fill_error("example_segment_path is not UTF-8", err);
            return std::ptr::null_mut();
        };

        // do the open
        match E01Reader::open_glob(sp, &options) {
            Ok(reader) => match E01Handle::new(reader) {
                Ok(handle) => Box::into_raw(Box::new(handle)),
                Err(e) => {
                    fill_error(e, err);
                    std::ptr::null_mut()
                }
            },
            Err(e) => {
                fill_error(e, err);
                std::ptr::null_mut()
            }
        }
    })
}

/// Close a handle from `e01_open` or `e01_open_glob`.
///
/// # Safety
/// `reader` must be null or a handle from `e01_open` or `e01_open_glob` which
/// has not yet been closed. It is dangling once this returns, as are the
/// `segment_paths`, `stored_md5`, and `stored_sha1` pointers it exposed and any
/// outstanding reads through it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn e01_close(reader: *mut E01Handle) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !reader.is_null() {
            drop(unsafe { Box::from_raw(reader) });
        }
    }));
}

/// Read up to `buflen` bytes from `offset`. Returns the number of bytes read,
/// which is zero on failure, with an error written to `err`.
///
/// # Safety
/// `handle` must be null or an open handle from `e01_open` or `e01_open_glob`.
/// `buf` must be null or point to at least `buflen` writable bytes. `err` must
/// be null or point to a writable, aligned `*mut E01Error`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn e01_read(
    handle: *mut E01Handle,
    offset: u64,
    buf: *mut c_char,
    buflen: usize,
    err: *mut *mut E01Error,
) -> usize {
    guard(err, 0, || {
        if handle.is_null() {
            fill_error("handle is null", err);
            return 0;
        }

        if buf.is_null() {
            fill_error("buf is null", err);
            return 0;
        }

        let buf = unsafe { slice::from_raw_parts_mut(buf as *mut u8, buflen) };
        unsafe { &*(*handle).reader }
            .read_at_offset(offset, buf)
            .unwrap_or_else(|e| {
                fill_error(e, err);
                0
            })
    })
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{hasher::HashType, test_data::*, test_helper::do_hash};

    const ERROR_OPTS: E01ReaderOptions = E01ReaderOptions {
        corrupt_section_policy: CorruptSectionPolicy::CSP_ERROR,
        corrupt_chunk_policy: CorruptChunkPolicy::CCP_ERROR,
    };

    /// A C caller can put any integer in the `#[repr(C)]` policy enum fields.
    /// rust_options must reject an out-of-range discriminant with an error
    /// rather than reading it as an enum (which would be undefined behavior).
    #[test]
    fn rust_options_rejects_out_of_range_policy() {
        // Same layout as E01ReaderOptions: two c_int-sized policy fields.
        #[repr(C)]
        struct RawOpts {
            section: c_int,
            chunk: c_int,
        }

        let bad = RawOpts {
            section: 99,
            chunk: 0,
        };
        let err = unsafe { rust_options((&bad as *const RawOpts).cast()) }.unwrap_err();
        assert!(err.contains("corrupt_section_policy"), "got {err}");

        let bad = RawOpts {
            section: 0,
            chunk: 7,
        };
        let err = unsafe { rust_options((&bad as *const RawOpts).cast()) }.unwrap_err();
        assert!(err.contains("corrupt_chunk_policy"), "got {err}");

        // valid discriminants still map through
        let good = RawOpts {
            section: 1,
            chunk: 2,
        };
        let opts = unsafe { rust_options((&good as *const RawOpts).cast()) }.unwrap();
        assert!(matches!(
            opts.corrupt_section_policy,
            e01_reader::CorruptSectionPolicy::DamnTheTorpedoes
        ));
        assert!(matches!(
            opts.corrupt_chunk_policy,
            e01_reader::CorruptChunkPolicy::RawIfPossible
        ));
    }

    struct Holder<T> {
        ptr: *mut T,
    }

    impl<T> Holder<T> {
        fn new(ptr: *mut T) -> Self {
            Self { ptr }
        }

        fn into_box(mut self) -> Box<T> {
            let ptr = self.ptr;
            self.ptr = std::ptr::null_mut();
            unsafe { Box::from_raw(ptr) }
        }
    }

    impl<T> Drop for Holder<T> {
        fn drop(&mut self) {
            if !self.ptr.is_null() {
                unsafe { drop(Box::from_raw(self.ptr)) }
            }
        }
    }

    #[track_caller]
    fn assert_err(err: *mut E01Error, message: &CStr) {
        assert!(!err.is_null());
        let err = unsafe { Box::from_raw(err) };

        assert!(!err.message.is_null());
        assert_eq!(unsafe { CStr::from_ptr(&*err.message) }, message);
    }

    #[track_caller]
    fn assert_err_starts_with(err: *mut E01Error, prefix: &CStr) {
        assert!(!err.is_null());
        let err = unsafe { Box::from_raw(err) };

        assert!(!err.message.is_null());

        let message = unsafe { CStr::from_ptr(&*err.message) };

        let msg_b = message.to_bytes();
        let pre_b = prefix.to_bytes();

        assert!(
            msg_b.starts_with(pre_b),
            "{message:?} does not start with {prefix:?}"
        );
    }

    #[track_caller]
    fn assert_err_contains(err: *mut E01Error, substr: &CStr) {
        assert!(!err.is_null());
        let err = unsafe { Box::from_raw(err) };

        assert!(!err.message.is_null());

        let message = unsafe { CStr::from_ptr(&*err.message) };

        let msg_b = message.to_bytes();
        let sub_b = substr.to_bytes();

        // This is a naive way to find a substring; we would want something
        // faster like memchr in production, but it's fine for a test.
        assert!(
            msg_b.windows(sub_b.len()).any(|w| w == sub_b),
            "{message:?} does not contain with {substr:?}"
        );
    }

    #[track_caller]
    fn assert_err_null(err: *mut E01Error) {
        let err = Holder::new(err);
        assert!(err.ptr.is_null());
    }

    #[test]
    fn panic_in_ffi_body_becomes_an_error() {
        let mut err = std::ptr::null_mut();
        let r = guard(&mut err, 0usize, || panic!("boom"));

        assert_eq!(r, 0);
        assert_err_starts_with(err, c"Panic while reading image: boom");
    }

    #[test]
    fn panic_with_null_err_does_not_abort() {
        let r = guard(std::ptr::null_mut(), 0usize, || panic!("boom"));
        assert_eq!(r, 0);
    }

    #[test]
    fn free_error_releases_the_message() {
        let mut err = std::ptr::null_mut();
        fill_error("kaboom", &mut err);
        assert!(!err.is_null());

        // The message is a CString::into_raw pointer; freeing it as a Box
        // deallocates with the wrong layout. Run under Miri/ASan to catch it.
        unsafe { e01_free_error(err) };
    }

    fn ptr_to_opt_hash<const N: usize>(ptr: *const u8) -> Option<String> {
        match ptr.is_null() {
            true => None,
            false => Some(hex::encode(unsafe { slice::from_raw_parts(ptr, N) })),
        }
    }

    #[track_caller]
    fn assert_eq_test_data(h: *mut E01Handle, exp: &TestData) {
        let handle = unsafe { &*h };

        let sl = unsafe { slice::from_raw_parts(handle.segment_paths, handle.segment_paths_count) };

        let segment_paths = sl
            .iter()
            .map(|p| unsafe { CStr::from_ptr(*p) })
            .map(|p| p.to_str())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let stored_md5 = ptr_to_opt_hash::<16>(handle.stored_md5);
        let stored_sha1 = ptr_to_opt_hash::<20>(handle.stored_sha1);

        let hashes = do_hash(
            |offset, buf: &mut [u8]| {
                let mut err = std::ptr::null_mut();
                let read = unsafe {
                    e01_read(
                        h,
                        offset,
                        buf.as_mut_ptr() as *mut c_char,
                        buf.len(),
                        &mut err,
                    )
                };

                assert_err_null(err);
                read
            },
            handle.image_size,
        );

        let act = TestData {
            segment_paths: &segment_paths[..],
            chunk_size: handle.chunk_size,
            chunk_count: handle.chunk_count,
            sector_size: handle.sector_size,
            sector_count: handle.sector_count,
            image_size: handle.image_size,
            stored_md5: stored_md5.as_deref(),
            stored_sha1: stored_sha1.as_deref(),
            md5: hashes.get(&HashType::MD5).map(String::as_str),
            sha1: hashes.get(&HashType::SHA1).map(String::as_str),
            sha256: hashes.get(&HashType::SHA256).map(String::as_str),
        };

        assert_eq!(&act, exp);
    }

    #[track_caller]
    fn assert_eq_test_data_no_hashing(handle: &E01Handle, exp: &TestData) {
        let sl = unsafe { slice::from_raw_parts(handle.segment_paths, handle.segment_paths_count) };

        let segment_paths = sl
            .iter()
            .map(|p| unsafe { CStr::from_ptr(*p) })
            .map(|p| p.to_str())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let stored_md5 = ptr_to_opt_hash::<16>(handle.stored_md5);
        let stored_sha1 = ptr_to_opt_hash::<20>(handle.stored_sha1);

        let act = TestData {
            segment_paths: &segment_paths[..],
            chunk_size: handle.chunk_size,
            chunk_count: handle.chunk_count,
            sector_size: handle.sector_size,
            sector_count: handle.sector_count,
            image_size: handle.image_size,
            stored_md5: stored_md5.as_deref(),
            stored_sha1: stored_sha1.as_deref(),
            md5: exp.md5,
            sha1: exp.sha1,
            sha256: exp.sha256,
        };

        assert_eq!(&act, exp);
    }

    #[test]
    fn test_e01_open_null_paths_null_err() {
        let options = &ERROR_OPTS;

        let h =
            Holder::new(unsafe { e01_open(std::ptr::null(), 1, options, std::ptr::null_mut()) });

        assert!(h.ptr.is_null());
    }

    #[test]
    fn test_e01_open_null_options_null_err() {
        let paths = [c"whatever".as_ptr()];

        let h = Holder::new(unsafe {
            e01_open(
                paths.as_ptr(),
                paths.len(),
                std::ptr::null(),
                std::ptr::null_mut(),
            )
        });

        assert!(h.ptr.is_null());
    }

    #[test]
    fn test_e01_open_zero_paths_null_err() {
        let paths = [c"whatever".as_ptr()];
        let options = &ERROR_OPTS;

        let h = Holder::new(unsafe { e01_open(paths.as_ptr(), 0, options, std::ptr::null_mut()) });

        assert!(h.ptr.is_null());
    }

    #[test]
    fn test_e01_open_nonexistent_paths_null_err() {
        let paths = [c"bogus".as_ptr()];
        let options = &ERROR_OPTS;

        let h = Holder::new(unsafe {
            e01_open(paths.as_ptr(), paths.len(), options, std::ptr::null_mut())
        });

        assert!(h.ptr.is_null());
    }

    #[test]
    fn test_e01_open_null_paths() {
        let options = &ERROR_OPTS;
        let mut err = std::ptr::null_mut();

        let h = Holder::new(unsafe { e01_open(std::ptr::null(), 1, options, &mut err) });

        assert_err(err, c"segment_paths is null");
        assert!(h.ptr.is_null());
    }

    #[test]
    fn test_e01_open_null_options() {
        let paths = [c"whatever".as_ptr()];
        let mut err = std::ptr::null_mut();

        let h = Holder::new(unsafe {
            e01_open(paths.as_ptr(), paths.len(), std::ptr::null(), &mut err)
        });

        assert_err(err, c"options is null");
        assert!(h.ptr.is_null());
    }

    #[test]
    fn test_e01_open_zero_paths() {
        let paths = [c"whatever".as_ptr()];
        let options = &ERROR_OPTS;
        let mut err = std::ptr::null_mut();

        let h = Holder::new(unsafe { e01_open(paths.as_ptr(), 0, options, &mut err) });

        assert_err(err, c"segment_paths_count is zero");
        assert!(h.ptr.is_null());
    }

    #[test]
    fn test_e01_open_nonexistent_paths() {
        let paths = [c"bogus".as_ptr()];
        let options = &ERROR_OPTS;
        let mut err = std::ptr::null_mut();

        let h = Holder::new(unsafe { e01_open(paths.as_ptr(), paths.len(), options, &mut err) });

        assert_err_starts_with(err, c"Malformed path or URL: ");
        assert!(h.ptr.is_null());
    }

    #[test]
    fn test_e01_open_glob_null_path_null_err() {
        let options = &ERROR_OPTS;

        let h =
            Holder::new(unsafe { e01_open_glob(std::ptr::null(), options, std::ptr::null_mut()) });

        assert!(h.ptr.is_null());
    }

    #[test]
    fn test_e01_open_glob_null_options_null_err() {
        let path = c"whatever".as_ptr();

        let h = Holder::new(unsafe { e01_open_glob(path, std::ptr::null(), std::ptr::null_mut()) });

        assert!(h.ptr.is_null());
    }

    #[test]
    fn test_e01_open_glob_nonexistent_path_null_err() {
        let path = c"bogus".as_ptr();
        let options = &ERROR_OPTS;

        let h = Holder::new(unsafe { e01_open_glob(path, options, std::ptr::null_mut()) });

        assert!(h.ptr.is_null());
    }

    #[test]
    fn test_e01_open_glob_null_path() {
        let options = &ERROR_OPTS;
        let mut err = std::ptr::null_mut();

        let h = Holder::new(unsafe { e01_open_glob(std::ptr::null(), options, &mut err) });

        assert_err(err, c"example_segment_path is null");
        assert!(h.ptr.is_null());
    }

    #[test]
    fn test_e01_open_glob_null_options() {
        let path = c"whatever".as_ptr();
        let mut err = std::ptr::null_mut();

        let h = Holder::new(unsafe { e01_open_glob(path, std::ptr::null(), &mut err) });

        assert_err(err, c"options is null");
        assert!(h.ptr.is_null());
    }

    #[test]
    fn test_e01_open_glob_nonexistent_path() {
        let path = c"bogus".as_ptr();
        let options = &ERROR_OPTS;
        let mut err = std::ptr::null_mut();

        let h = Holder::new(unsafe { e01_open_glob(path, options, &mut err) });

        // error message differs between Linux and Windows
        assert_err_contains(err, c"bogus");
        assert!(h.ptr.is_null());
    }

    #[test]
    fn test_e01_open_one_segment() {
        let paths = [c"data/image.E01".as_ptr()];

        let options = &ERROR_OPTS;
        let mut err = std::ptr::null_mut();

        let h = Holder::new(unsafe { e01_open(paths.as_ptr(), paths.len(), options, &mut err) });

        assert_err_null(err);
        assert!(!h.ptr.is_null());

        let handle = h.into_box();
        assert_eq_test_data_no_hashing(&handle, &IMAGE_E01);

        let handle = Box::into_raw(handle);
        unsafe {
            e01_close(handle);
        }
    }

    #[test]
    fn test_e01_open_one_segment_null_err() {
        let paths = [c"data/image.E01".as_ptr()];

        let options = &ERROR_OPTS;

        let h = Holder::new(unsafe {
            e01_open(paths.as_ptr(), paths.len(), options, std::ptr::null_mut())
        });

        assert!(!h.ptr.is_null());

        let handle = h.into_box();
        assert_eq_test_data_no_hashing(&handle, &IMAGE_E01);

        let handle = Box::into_raw(handle);
        unsafe {
            e01_close(handle);
        }
    }

    #[test]
    fn test_e01_open_two_segments() {
        let paths = [c"data/mimage.E01".as_ptr(), c"data/mimage.E02".as_ptr()];

        let options = &ERROR_OPTS;
        let mut err = std::ptr::null_mut();

        let h = Holder::new(unsafe { e01_open(paths.as_ptr(), paths.len(), options, &mut err) });

        assert_err_null(err);
        assert!(!h.ptr.is_null());

        let handle = h.into_box();
        assert_eq_test_data_no_hashing(&handle, &MIMAGE_E01);

        let handle = Box::into_raw(handle);
        unsafe {
            e01_close(handle);
        }
    }

    #[test]
    fn test_e01_open_two_segments_null_err() {
        let paths = [c"data/mimage.E01".as_ptr(), c"data/mimage.E02".as_ptr()];

        let options = &ERROR_OPTS;

        let h = Holder::new(unsafe {
            e01_open(paths.as_ptr(), paths.len(), options, std::ptr::null_mut())
        });

        assert!(!h.ptr.is_null());

        let handle = h.into_box();
        assert_eq_test_data_no_hashing(&handle, &MIMAGE_E01);

        let handle = Box::into_raw(handle);
        unsafe {
            e01_close(handle);
        }
    }

    #[test]
    fn test_e01_close_null() {
        // nothing to test here other than that it doesn't crash
        unsafe { e01_close(std::ptr::null_mut()) };
    }

    #[test]
    fn test_e01_read_null_handle_null_err() {
        let mut buf: [c_char; 1] = [0];

        let r = unsafe {
            e01_read(
                std::ptr::null_mut(),
                0,
                buf.as_mut_ptr(),
                buf.len(),
                std::ptr::null_mut(),
            )
        };

        assert_eq!(r, 0);
    }

    #[test]
    fn test_e01_read_null_buffer_null_err() {
        let paths = [c"data/image.E01".as_ptr()];

        let options = &ERROR_OPTS;

        let h = Holder::new(unsafe {
            e01_open(paths.as_ptr(), paths.len(), options, std::ptr::null_mut())
        });

        assert!(!h.ptr.is_null());

        let r = unsafe { e01_read(h.ptr, 0, std::ptr::null_mut(), 1, std::ptr::null_mut()) };

        assert_eq!(r, 0);
    }

    #[test]
    fn test_e01_read_null_handle() {
        let mut buf: [c_char; 1] = [0];
        let mut err = std::ptr::null_mut();

        let r = unsafe {
            e01_read(
                std::ptr::null_mut(),
                0,
                buf.as_mut_ptr(),
                buf.len(),
                &mut err,
            )
        };

        assert_err(err, c"handle is null");
        assert_eq!(r, 0);
    }

    #[test]
    fn test_e01_read_null_buffer() {
        let paths = [c"data/image.E01".as_ptr()];

        let options = &ERROR_OPTS;
        let mut err = std::ptr::null_mut();

        let h = Holder::new(unsafe { e01_open(paths.as_ptr(), paths.len(), options, &mut err) });

        assert_err_null(err);
        assert!(!h.ptr.is_null());

        let r = unsafe { e01_read(h.ptr, 0, std::ptr::null_mut(), 1, &mut err) };

        assert_err(err, c"buf is null");
        assert_eq!(r, 0);
    }

    #[test]
    fn test_e01_read_offset_past_end() {
        let paths = [c"data/image.E01".as_ptr()];

        let options = &ERROR_OPTS;
        let mut err = std::ptr::null_mut();

        let h = Holder::new(unsafe { e01_open(paths.as_ptr(), paths.len(), options, &mut err) });

        assert_err_null(err);
        assert!(!h.ptr.is_null());

        let mut buf: [c_char; 1] = [0];

        let r = unsafe { e01_read(h.ptr, u64::MAX, buf.as_mut_ptr(), buf.len(), &mut err) };

        assert_err_starts_with(
            err,
            c"Requested offset 18446744073709551615 is beyond end of image",
        );
        assert_eq!(r, 0);
    }

    #[test]
    fn test_e01_read_offset_bad_chunk_checksum() {
        let paths = [c"data/bad_chunk.E01".as_ptr()];

        let options = &ERROR_OPTS;
        let mut err = std::ptr::null_mut();

        let h = Holder::new(unsafe { e01_open(paths.as_ptr(), paths.len(), options, &mut err) });

        assert_err_null(err);
        assert!(!h.ptr.is_null());

        let mut buf: [c_char; 1] = [0];

        let r = unsafe { e01_read(h.ptr, 0, buf.as_mut_ptr(), buf.len(), &mut err) };

        let _handle = h.into_box();

        assert_eq!(r, 0);
        assert_err_contains(err, c"Chunk 0 checksum failed");
    }

    #[test]
    fn test_e01_read_and_hash() {
        let paths = [c"data/image.E01".as_ptr()];

        let options = &ERROR_OPTS;
        let mut err = std::ptr::null_mut();

        let h = Holder::new(unsafe { e01_open(paths.as_ptr(), paths.len(), options, &mut err) });

        assert_err_null(err);
        assert!(!h.ptr.is_null());

        let mut handle = h.into_box();
        assert_eq_test_data(&mut *handle, &IMAGE_E01);

        let handle = Box::into_raw(handle);
        unsafe {
            e01_close(handle);
        }
    }
}
