use std::{io::{Read, Seek}, ops::RangeInclusive};

use rangemap::{RangeMap, RangeInclusiveMap};
use regex::Regex;
use thiserror::Error;
use zip::ZipArchive;

pub fn load_snapshot<F: Read + Seek>(
    source: F,
) -> Result<Snapshot<F>, SnapshotError> {
    let segname = Regex::new(r#"^([0-9a-fA-F]+)@([0-9a-fA-F]+)\.bin$"#).unwrap();
    let mut archive = zip::ZipArchive::new(source)?;
    let mut segment_files = vec![];

    for i in 0..archive.len() {
        let file = archive.by_index(i)?;
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
            }
        }
    }

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
        archive,
        segment_files_by_address,
    })
}

#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("ZIP file access or format error")]
    Zip(#[from] zip::result::ZipError),
    #[error("problem accessing file within ZIP archive")]
    Io(#[from] std::io::Error),
}

pub struct Snapshot<F> {
    archive: ZipArchive<F>,
    segment_files_by_address: RangeInclusiveMap<u64, FileInfo>,
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

    pub fn ranges(&self) -> impl Iterator<Item = (&RangeInclusive<u64>, &FileInfo)> {
        self.segment_files_by_address.iter()
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
