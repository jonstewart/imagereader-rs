# e01-rs

`e01-rs` is a Rust library to read data from Expert Witness Format (E01) files.

# [Expert Witness Compression Format (EWF)](https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%20(EWF).asciidoc)

### Supported file formats

* EWF
* EWF-E01
* EWF-S01

### Supported features

* multiple segments (files)
* chunk decompression (zlib)
* checking all checksums

## TODO

* [EWF2](https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%202%20(EWF2).asciidoc)

### Usage example

Read from an E01 in Rust. `open_glob` takes any one segment and discovers the
rest (`.E01`, `.E02`, ... `.EAA`, ...); `open` takes an explicit list of segment
paths.

```rust
    use e01::e01_reader::{E01Reader, E01ReaderOptions};

    fn read_e01(e01_path: &str) {
        let options = E01ReaderOptions::default();
        let e01_reader = E01Reader::open_glob(e01_path, &options).unwrap();

        let mut buf: Vec<u8> = vec![0; 1048576];
        let mut offset = 0;
        while offset < e01_reader.image_size {
            let read = e01_reader.read_at_offset(offset, &mut buf).unwrap();
            if read == 0 {
                break;
            }

            // process buf[..read]

            offset += read as u64;
        }
    }
```

`E01ReaderOptions` also selects what to do with sections and chunks that fail
their checksums, and configures caching, readahead, S3 concurrency and I/O
logging.

### Performance

Segments that are local files are read directly, with positioned reads; the
OS page cache does the caching, and the foyer cache options apply only to S3
segments (set `direct_file_io: false` to route local files through it too).
`read_at_offset` takes `&self`, so one reader serves concurrent threads with
no lock around it. Multi-chunk reads decompress on the calling thread and a
small pool together, and small sequential reads have the chunks ahead of them
decoded on that pool.

[`compare/`](compare/README.md) benchmarks e01-rs against libewf, directly and
under The Sleuth Kit, and checks that both return the same bytes.

### Binaries

* `e01verify` hashes an image and compares the result with the stored digests.
* To serve an E01 over NBD, use [`diskimage-nbd`](../diskimage-nbd), which
  handles all three image formats.

## S3 credentials

Segment paths may use `s3://bucket/key` URLs. Credentials are resolved via the
AWS SDK Rust [`DefaultCredentialsChain`](https://docs.rs/aws-config/latest/aws_config/default_provider/credentials/struct.DefaultCredentialsChain.html)
(profile files, environment variables, SSO, ECS, EC2 instance role).

**Resolution policy:** the chain is always attempted for `s3://` opens (environment variables, `AWS_CONFIG_FILE`,
`AWS_SHARED_CREDENTIALS_FILE`, or `~/.aws/credentials` / `~/.aws/config`). If
resolution fails and AWS auth is expected, open fails with an explicit error. 
If no auth is configured, the reader falls back to anonymous access (public buckets).

**EC2 instance role:** works without local AWS config files via IMDS in the chain.

**Public buckets:** when no AWS config is present, the chain may probe
IMDS before falling back to anonymous (~1–5s on first open). For faster anonymous
access, set `AWS_EC2_METADATA_DISABLED=true`.

**Refresh:** temporary credentials (SSO, STS) are re-provisioned via aws-config
before S3 reads when they expire. SSO profiles require a prior `aws sso login`.

When `AWS_REGION` / `AWS_DEFAULT_REGION` are unset, the region from the active
AWS profile (including SSO profiles) is used. If no region is configured, the
library queries the bucket location before reading rather than assuming one.


### Copyright

Copyright 2025–2026, LevelBlue, LLC. `e01-rs` is licensed under the Apache License, Version 2.0.
