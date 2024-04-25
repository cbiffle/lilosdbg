use std::{io::{Read, Seek}, ops::RangeInclusive, collections::BTreeMap};

use rangemap::RangeInclusiveMap;
use regex::Regex;
use thiserror::Error;
use zip::ZipArchive;

pub fn load_snapshot<F: Read + Seek>(
    source: F,
) -> Result<Snapshot<F>, SnapshotError> {
    let segname = Regex::new(r#"^([0-9a-fA-F]+)@([0-9a-fA-F]+)\.bin$"#).unwrap();
    let comment_pattern = Regex::new(r#"^lilosdbg snapshot v([0-9]+)$"#).unwrap();
    let mut archive = zip::ZipArchive::new(source)?;
    let comment = std::str::from_utf8(archive.comment())
        .map_err(|_| SnapshotError::NotASnapshot)?;
    let comment_parts = comment_pattern.captures(comment)
        .ok_or(SnapshotError::NotASnapshot)?;

    let format_version = comment_parts[1].parse::<u64>()
        .map_err(|_| SnapshotError::NotASnapshot)?;
    match format_version {
        1 => (),
        _ => return Err(SnapshotError::UnsupportedVersion(format_version)),
    }


    let mut elf_files = vec![];
    let mut segment_files = vec![];

    let mut registers = BTreeMap::new();

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file.name();
        if let Some((root, rest)) = name.split_once('/') {
            if root == "seg" {
                if let Some(c) = segname.captures(rest) {
                    let hex_address = &c[1];
                    let order = &c[2];
                    if let Ok(address) = u64::from_str_radix(hex_address, 16) {
                        if let Ok(order) = u64::from_str_radix(order, 16) {
                            if let Some(size_m1) = file.size().checked_sub(1) {
                                let segrange = address..=address + size_m1;
                                segment_files.push((segrange, order, i, name.to_string()));
                            }
                        }
                    }
                }
            } else if root == "elf" && !rest.is_empty() {
                elf_files.push((i, name.to_string()));
            }
        } else if name == "registers.toml" {
            let mut contents = vec![];
            file.read_to_end(&mut contents)?;
            let contents = std::str::from_utf8(&contents).map_err(SnapshotError::Reg)?;
            let r: BTreeMap<String, u64> = toml::de::from_str(contents).map_err(SnapshotError::RegToml)?;
            registers = r.into_iter().map(|(r, v)| {
                let r = r.parse::<u16>().map_err(SnapshotError::RegTomlKey)?;
                Ok::<_, SnapshotError>((r, v))
            }).collect::<Result<_, _>>()?;
        }
    }

    elf_files.sort_by(|a, b| a.1.cmp(&b.1));

    segment_files.sort_unstable_by_key(|(addrs, order, index, name)| (*addrs.start(), *order, *index, name.clone())); // sigh

    let mut segment_files_by_address = RangeInclusiveMap::new();
    for (addrs, order, index, name) in segment_files {
        segment_files_by_address.insert(addrs.clone(), FileInfo {
            index,
            range: addrs,
            order,
            name: name.to_string(),
        });
    }

    Ok(Snapshot {
        format_version,
        archive,
        elf_files,
        segment_files_by_address,
        registers,
    })
}

#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("this file is a ZIP file, but is not a snapshot")]
    NotASnapshot,
    #[error("snapshot is format version {0}, which we don't understand")]
    UnsupportedVersion(u64),
    #[error("ZIP file access or format error")]
    Zip(#[from] zip::result::ZipError),
    #[error("could not load register file as UTF-8")]
    Reg(#[source] std::str::Utf8Error),
    #[error("could not parse register file as TOML")]
    RegToml(#[source] toml::de::Error),
    #[error("could not parse register name as integer")]
    RegTomlKey(#[source] std::num::ParseIntError),
    #[error("problem accessing file within ZIP archive")]
    Io(#[from] std::io::Error),
}

pub struct Snapshot<F> {
    format_version: u64,
    archive: ZipArchive<F>,
    elf_files: Vec<(usize, String)>,
    segment_files_by_address: RangeInclusiveMap<u64, FileInfo>,
    registers: BTreeMap<u16, u64>,
}

impl<F> Snapshot<F> {
    pub fn format_version(&self) -> u64 {
        self.format_version
    }

    pub fn ranges(&self) -> impl Iterator<Item = (RangeInclusive<u64>, &FileInfo)> {
        self.segment_files_by_address.iter().map(|(r, f)| (r.clone(), f))
    }

    pub fn has_elf_files(&self) -> bool {
        !self.elf_files.is_empty()
    }

    pub fn elf_files(&self) -> impl Iterator<Item = (usize, &str)> {
        self.elf_files.iter()
            .map(|(i, name)| (*i, name.as_str()))
    }

    pub fn has_registers(&self) -> bool {
        !self.registers.is_empty()
    }

    pub fn registers(&self) -> impl Iterator<Item = (u16, u64)> + '_ {
        self.registers.iter().map(|(r, v)| (*r, *v))
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FileInfo {
    pub index: usize,
    pub range: RangeInclusive<u64>,
    pub order: u64,
    pub name: String,
}

impl<F: Read + Seek> Snapshot<F> {
    pub fn read(&mut self, address: u64, dest: &mut [u8]) -> Result<usize, SnapshotError> {
        let len = u64::try_from(dest.len()).unwrap();
        if len == 0 {
            return Ok(0);
        }

        let requested_range = address..=address + (len - 1);
        // Check if there are any gaps in the overlap, and truncate the read at
        // that point.
        let end = if let Some(gap) = self.segment_files_by_address.gaps(&requested_range).next() {
            *gap.start()
        } else {
            *requested_range.end()
        };
        let available_size = end - address + 1;
        let read_size = usize::min(
            dest.len(),
            usize::try_from(available_size).unwrap_or(usize::MAX),
        );

        let mut address = address;
        let mut dest = dest;
        // We can be confident there are no gaps now.
        for (overlap_range, info) in self.segment_files_by_address.overlapping(&(address..=end)) {
            // overlap_range is a subset of file_range because of how
            // RangeInclusiveMap works.
            //
            // file_range includes address because we've already checked for
            // gaps.
           
            // We want to transfer at most dest.len() bytes from this segment,
            // starting at `address`. We can compute our offset into the backing
            // segment file, which is _not the same_ as our offset into the
            // overlapping range from the iterator (because a larger segment may
            // be split by a smaller one):
            let segment_offset = address - info.range.start();
            // Compute the number of bytes available in this overlap (which may
            // differ from the file range if something overlaps us):
            let range_len = usize::try_from(overlap_range.end() - address + 1).unwrap_or(usize::MAX);
            // And compute how much we can actually read:
            let chunk_len = usize::min(range_len, dest.len());
            let (next, rest) = dest.split_at_mut(chunk_len);

            let mut file = self.archive.by_index(info.index)?;
            // ZipFile doesn't impl Seek. So, we need to skip to our segment
            // offset the hard way. TODO: this will probably become a
            // performance issue.
            skip(&mut file, segment_offset)?;
            file.read_exact(next)?;

            address += u64::try_from(chunk_len).unwrap();
            dest = rest;
        }

        Ok(read_size)
    }

    pub fn file_by_index(&mut self, i: usize) -> impl Read + '_ {
        self.archive.by_index(i).unwrap()
    }
}

fn skip(file: &mut impl Read, mut amount: u64) -> Result<(), std::io::Error> {
    let mut discard = vec![0; 1024];
    while amount > 0 {
        let chunk = usize::min(
            discard.len(),
            usize::try_from(amount).unwrap_or(usize::MAX),
        );
        let discard = &mut discard[..chunk];
        file.read_exact(discard)?;
        amount -= u64::try_from(chunk).unwrap();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
}
