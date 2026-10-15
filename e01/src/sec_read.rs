use crate::error::{IoError, LibError, MAX_TABLE_ENTRIES};
use crate::generated::{
    ewf_digest_section::EwfDigestSection, ewf_hash_section::EwfHashSection,
    ewf_section_descriptor_v1::EwfSectionDescriptorV1, ewf_table_header::EwfTableHeader,
    ewf_volume::EwfVolume, ewf_volume_smart::EwfVolumeSmart,
};
//use crate::generated::ewf_section_descriptor_v2::*;

use kaitai::{BytesReader, KStream, KStruct};

#[derive(Debug)]
pub struct Chunk {
    pub segment: usize,
    pub data_offset: u64,
    pub end_offset: u64,
    pub compressed: bool,
}

#[derive(Debug)]
pub enum Section {
    Volume(VolumeSection),
    /// A table: its raw, checksum-verified offset array (see
    /// [`table_chunks`]) and its base offset.
    Table {
        entries: Vec<u8>,
        base_offset: u64,
    },
    Sectors(u64),
    Hash([u8; 16]),
    Digest([u8; 16], [u8; 20]),
    Done,
    Other,
}

/// The Adler-32 of `data`, which is what EWF stores to check every section
/// and every uncompressed chunk.
pub(crate) fn adler32(data: &[u8]) -> u32 {
    let mut h = simd_adler32::Adler32::new();
    h.write(data);
    h.finish()
}

fn checksum_reader(reader: &BytesReader, len: usize) -> Result<u32, IoError> {
    Ok(adler32(&reader.read_bytes(len).map_err(IoError::Read)?))
}

fn checksum_ok(
    section_type: &str,
    io: &BytesReader,
    section_io: &BytesReader,
    crc_stored: u32,
) -> Result<(), LibError> {
    let crc = checksum_reader(section_io, io.pos() - section_io.pos() - 4)?;
    match crc == crc_stored {
        true => Ok(()),
        false => Err(LibError::BadChecksum(section_type.into(), crc, crc_stored)),
    }
}

fn read_section(io: &BytesReader, ignore_checksums: bool) -> Result<(usize, Section), LibError> {
    let sd = EwfSectionDescriptorV1::read_into::<_, EwfSectionDescriptorV1>(io, None, None)
        .map_err(|e| LibError::DeserializationFailed("EwfSectionDescriptorV1", e))?;

    let section_size = if *sd.size() > 0x4c {
        // header size
        *sd.size() - 0x4c
    } else {
        0
    };

    let section_type_full = sd.type_string();
    let section_type = section_type_full.trim_matches(char::from(0));

    let section = match section_type {
        "disk" | "volume" => {
            Section::Volume(VolumeSection::new(io, section_size, ignore_checksums)?)
        }
        "table" => {
            let (entries, base_offset) = read_table(io, section_size, ignore_checksums)?;
            Section::Table {
                entries,
                base_offset,
            }
        }
        "sectors" => Section::Sectors(io.pos() as u64 + section_size),
        "hash" => Section::Hash(read_hash_section(io, ignore_checksums)?),
        "digest" => {
            let (md5, sha1) = read_digest_section(io, ignore_checksums)?;
            Section::Digest(md5, sha1)
        }
        "done" => Section::Done,
        _ => Section::Other,
    };

    let section_offset = *sd.next_offset() as usize;

    Ok((section_offset, section))
}

fn read_hash_section(io: &BytesReader, ignore_checksums: bool) -> Result<[u8; 16], LibError> {
    let hash_section = EwfHashSection::read_into::<_, EwfHashSection>(io, None, None)
        .map_err(|e| LibError::DeserializationFailed("EwfHashSection", e))?;

    if !ignore_checksums {
        checksum_ok(
            "Hash section",
            io,
            &hash_section._io(),
            *hash_section.checksum(),
        )?;
    }

    let md5 = hash_section
        .md5()
        .as_slice()
        .try_into()
        .expect("MD5 must deserialize to 16 bytes");

    Ok(md5)
}

fn read_digest_section(
    io: &BytesReader,
    ignore_checksums: bool,
) -> Result<([u8; 16], [u8; 20]), LibError> {
    let digest_section = EwfHashSection::read_into::<_, EwfDigestSection>(io, None, None)
        .map_err(|e| LibError::DeserializationFailed("EwfDigestSection", e))?;

    if !ignore_checksums {
        checksum_ok(
            "Digest section",
            io,
            &digest_section._io(),
            *digest_section.checksum(),
        )?;
    }

    let md5 = digest_section
        .md5()
        .as_slice()
        .try_into()
        .expect("MD5 must deserialize to 16 bytes");

    let sha1 = digest_section
        .sha1()
        .as_slice()
        .try_into()
        .expect("SHA1 must deserialize to 20 bytes");

    Ok((md5, sha1))
}

/// Turn a table's raw offset array into chunks.
///
/// Each entry's low 31 bits are the chunk's offset from the table's base
/// offset, and its high bit says whether the chunk is compressed.
///
/// Offsets must rise monotonically: each entry is the end of the
/// chunk before it, so going backwards would give that chunk a negative length.
///
/// The chunks are appended to `chunks` -- one vector for the whole segment, so
/// a large image's million-odd chunks are written once rather than built per
/// table and copied.
pub fn table_chunks(
    raw_entries: &[u8],
    table_offset: u64,
    segment: usize,
    chunks: &mut Vec<Chunk>,
) -> Result<(), LibError> {
    chunks.reserve(raw_entries.len() / 4);
    let mut prev_rel = 0u64;

    for (i, raw) in raw_entries.chunks_exact(4).enumerate() {
        let stored = u32::from_le_bytes(raw.try_into().expect("table entries are 4 bytes")) as u64;

        let (rel, compressed) = (stored & 0x7fffffff, stored & 0x80000000 != 0);

        if i > 0 {
            let prev = chunks.last_mut().expect("entry i - 1 was pushed");
            if rel < prev_rel {
                return Err(LibError::CorruptChunkTable(format!(
                    "entry {} offset {} precedes entry {} offset {}",
                    i,
                    table_offset + rel,
                    i - 1,
                    prev.data_offset,
                )));
            }
            prev.end_offset = table_offset + rel;
        }

        chunks.push(Chunk {
            segment,
            data_offset: table_offset + rel,
            end_offset: 0,
            compressed,
        });
        prev_rel = rel;
    }

    Ok(())
}

/// Read a table section's header and offset array, checking both checksums.
/// Returns the raw offset array and the table's base offset.
pub fn read_table(
    io: &BytesReader,
    _size: u64,
    ignore_checksums: bool,
) -> Result<(Vec<u8>, u64), LibError> {
    let table_section = EwfTableHeader::read_into::<_, EwfTableHeader>(io, None, None)
        .map_err(|e| LibError::DeserializationFailed("EwfTableHeader", e))?;

    if !ignore_checksums {
        checksum_ok(
            "Table section",
            io,
            &table_section._io(),
            *table_section.checksum(),
        )?;
    }

    let raw_entry_count = *table_section.entry_count();
    if raw_entry_count > MAX_TABLE_ENTRIES {
        return Err(LibError::TooManyTableEntries(raw_entry_count));
    }

    let entry_count = raw_entry_count as usize;
    let base_offset = *table_section.table_base_offset();
    if entry_count == 0 {
        // weird, but possible?
        return Ok((vec![], base_offset));
    }

    // The whole offset array in one read. Reading it an entry at a time
    // costs a kaitai round trip -- an allocation and a stream sync -- per
    // chunk, which on a large image was most of the time spent opening it.
    let raw_entries = io.read_bytes(entry_count * 4).map_err(IoError::Read)?;

    if !ignore_checksums {
        // table footer
        let crc_stored = io.read_u4le().map_err(IoError::Read)?;

        let crc = adler32(&raw_entries);

        if crc != crc_stored {
            return Err(LibError::BadChecksum(
                "Table offset array".into(),
                crc,
                crc_stored,
            ));
        }
    }

    Ok((raw_entries, base_offset))
}

#[derive(Debug, Default)]
pub struct VolumeSection {
    pub chunk_count: u32,
    pub sectors_per_chunk: u32,
    pub bytes_per_sector: u32,
    pub total_sector_count: u64,
}

impl VolumeSection {
    pub fn new(io: &BytesReader, size: u64, ignore_checksums: bool) -> Result<Self, LibError> {
        // read volume section
        if size == 1052 {
            let vol_section = EwfVolume::read_into::<_, EwfVolume>(io, None, None)
                .map_err(|e| LibError::DeserializationFailed("EwfVolume", e))?;

            if !ignore_checksums {
                checksum_ok(
                    "Volume section",
                    io,
                    &vol_section._io(),
                    *vol_section.checksum(),
                )?;
            }

            let vs = VolumeSection {
                chunk_count: *vol_section.number_of_chunks(),
                sectors_per_chunk: *vol_section.sectors_per_chunk(),
                bytes_per_sector: *vol_section.bytes_per_sector(),
                total_sector_count: *vol_section.number_of_sectors(),
            };
            Ok(vs)
        } else if size == 94 {
            let vol_section = EwfVolumeSmart::read_into::<_, EwfVolumeSmart>(io, None, None)
                .map_err(|e| LibError::DeserializationFailed("EwfVolumeSmart", e))?;

            if !ignore_checksums {
                checksum_ok(
                    "Volume section",
                    io,
                    &vol_section._io(),
                    *vol_section.checksum(),
                )?;
            }

            let vs = VolumeSection {
                chunk_count: *vol_section.number_of_chunks(),
                sectors_per_chunk: *vol_section.sectors_per_chunk(),
                bytes_per_sector: *vol_section.bytes_per_sector(),
                total_sector_count: *vol_section.number_of_sectors() as u64,
            };
            Ok(vs)
        } else {
            Err(LibError::UnexpectedVolumeSize(size))
        }
    }

    pub fn chunk_size(&self) -> usize {
        self.sectors_per_chunk as usize * self.bytes_per_sector as usize
    }

    pub fn max_offset(&self) -> usize {
        self.total_sector_count as usize * self.bytes_per_sector as usize
    }
}

pub struct SectionIterator<'a> {
    io: &'a BytesReader,
    current_offset: usize,
    ignore_checksums: bool,
}

impl<'a> SectionIterator<'a> {
    pub fn new(io: &'a BytesReader, ignore_checksums: bool) -> Self {
        Self {
            io,
            current_offset: io.pos(),
            ignore_checksums,
        }
    }
}

impl Iterator for SectionIterator<'_> {
    type Item = Result<Section, LibError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_offset < self.io.size() {
            if let Err(e) = self.io.seek(self.current_offset) {
                return Some(Err(LibError::IoError(IoError::Seek(
                    self.current_offset,
                    e,
                ))));
            }

            match read_section(self.io, self.ignore_checksums) {
                Ok((section_offset, section)) => {
                    // Sections advance forward through the file; the final
                    // section's next_offset points at itself. A next_offset
                    // that does not move forward — a self-pointer or a
                    // backward cycle from a corrupt image — ends iteration.
                    // Requiring strict forward progress prevents a two-section
                    // A->B->A cycle from looping forever.
                    self.current_offset = if section_offset > self.current_offset {
                        section_offset
                    } else {
                        // ensure that the next() next is None
                        self.io.size()
                    };

                    Some(Ok(section))
                }
                Err(e) => Some(Err(e)),
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// table header (24 bytes) followed by 4-byte offset entries
    fn table_bytes(entry_count: u32, entries: &[u32]) -> Vec<u8> {
        let mut b = vec![];
        b.extend_from_slice(&entry_count.to_le_bytes());
        b.extend_from_slice(&[0u8; 4]); // padding1
        b.extend_from_slice(&0u64.to_le_bytes()); // table_base_offset
        b.extend_from_slice(&[0u8; 4]); // padding2
        b.extend_from_slice(&0u32.to_le_bytes()); // checksum
        for e in entries {
            b.extend_from_slice(&e.to_le_bytes());
        }
        b
    }

    fn table_chunks(raw: &[u8], base: u64) -> Result<Vec<Chunk>, LibError> {
        let mut chunks = vec![];
        super::table_chunks(raw, base, 0, &mut chunks).map(|_| chunks)
    }

    /// Chunk data offsets must be monotonic — each entry is the previous
    /// chunk's end. A table where they go backwards would give a chunk a
    /// negative length downstream.
    #[test]
    fn non_monotonic_table_entries_are_an_error() {
        let io = BytesReader::from(table_bytes(2, &[0x100, 0x80]));
        let (raw, base) = read_table(&io, 0, true).unwrap();
        let err = table_chunks(&raw, base).unwrap_err();
        assert!(matches!(err, LibError::CorruptChunkTable(_)), "got {err:?}");
    }

    /// Tables append to one vector per segment; a table's monotonicity check
    /// must not compare its first entry with the last chunk of the table
    /// before it, which belongs to an unrelated run of offsets.
    #[test]
    fn a_table_does_not_check_against_the_previous_table() {
        let mut chunks = vec![];
        super::table_chunks(&entries(&[0x9000, 0xa000]), 0, 2, &mut chunks).unwrap();
        super::table_chunks(&entries(&[0x100, 0x200]), 0, 2, &mut chunks).unwrap();
        assert_eq!(chunks.len(), 4);
        assert!(chunks.iter().all(|c| c.segment == 2));
        // the first table's last chunk is left for the caller to end
        assert_eq!(chunks[1].end_offset, 0);
    }

    fn entries(raw: &[u32]) -> Vec<u8> {
        raw.iter().flat_map(|e| e.to_le_bytes()).collect()
    }

    #[test]
    fn table_entries_carry_offset_and_compression() {
        let chunks = table_chunks(&entries(&[0x80000100, 0x200, 0x80000300]), 0x1000).unwrap();
        let got: Vec<_> = chunks
            .iter()
            .map(|c| (c.data_offset, c.end_offset, c.compressed))
            .collect();
        assert_eq!(
            got,
            [
                (0x1100, 0x1200, true),
                (0x1200, 0x1300, false),
                (0x1300, 0, true)
            ]
        );
    }

    /// entry_count is a raw u32 from the image; EWF caps table entries at
    /// 65534. An absurd count must be rejected before it drives a
    /// multi-gigabyte allocation.
    #[test]
    fn huge_table_entry_count_is_rejected_before_allocation() {
        let io = BytesReader::from(table_bytes(u32::MAX, &[]));
        let err = read_table(&io, 0, true).unwrap_err();
        assert!(
            matches!(err, LibError::TooManyTableEntries(_)),
            "got {err:?}"
        );
    }

    /// A section descriptor v1 record: 16-byte type, u64 next_offset, u64
    /// size, 40 bytes padding, u32 checksum (76 bytes total). An unknown
    /// type parses as Section::Other with no checksum validation.
    fn section_desc(type_str: &str, next_offset: u64, size: u64) -> Vec<u8> {
        let mut b = vec![0u8; 76];
        let t = type_str.as_bytes();
        let n = t.len().min(16);
        b[..n].copy_from_slice(&t[..n]);
        b[16..24].copy_from_slice(&next_offset.to_le_bytes());
        b[24..32].copy_from_slice(&size.to_le_bytes());
        b
    }

    /// next_offset comes from the image. Valid sections advance forward and
    /// the terminator points at itself; a corrupt image can point section B
    /// back at section A. That must terminate iteration, not hang forever.
    #[test]
    fn cyclic_section_offsets_terminate_instead_of_looping() {
        let mut bytes = section_desc("junk", 76, 76); // section at 0 -> 76
        bytes.extend(section_desc("junk", 0, 76)); // section at 76 -> 0
        let io = BytesReader::from(bytes);

        // Without forward-progress enforcement this never returns.
        let sections: Vec<_> = SectionIterator::new(&io, true).collect();
        assert_eq!(sections.len(), 2);
        assert!(sections.iter().all(|s| s.is_ok()), "got {sections:?}");
    }
}
