//! ZIP metadata and decompression bounds. Files are never extracted to source paths.
use super::{Files, MAX_EXPANDED_BYTES};
use std::io::{Cursor, Read};
/// Bound the entire decompressed stream before TAR inspects any metadata. Raw
/// entries avoid hidden GNU/PAX allocations; the v5 exporter uses ordinary TAR.
pub(super) fn tar_gz(input: &[u8]) -> Result<Files, String> {
    let mut expanded = Vec::new();
    flate2::read::MultiGzDecoder::new(input)
        .take(MAX_EXPANDED_BYTES as u64 + 1)
        .read_to_end(&mut expanded)
        .map_err(|_| "Invalid gzip stream or checksum")?;
    if expanded.len() > MAX_EXPANDED_BYTES {
        return Err("TAR stream expands beyond 64 MiB".into());
    }
    let mut archive = tar::Archive::new(Cursor::new(expanded));
    let mut files = Files::new();
    for (index, entry) in archive
        .entries()
        .map_err(|_| "Invalid TAR archive")?
        .raw(true)
        .enumerate()
    {
        if index >= 64 {
            return Err("TAR must contain at most 64 entries".into());
        }
        let mut entry = entry.map_err(|_| "Invalid TAR header/checksum")?;
        let path = entry.path_bytes();
        let name = std::str::from_utf8(&path)
            .map_err(|_| "TAR paths must be UTF-8")?
            .to_owned();
        if name.is_empty()
            || name.len() > 1024
            || name.starts_with('/')
            || name.contains('\\')
            || name.contains(':')
            || name.split('/').any(|part| part == ".." || part == ".")
        {
            return Err("Unsafe TAR entry path".into());
        }
        if entry.header().entry_type().is_dir() {
            continue;
        }
        if !entry.header().entry_type().is_file() {
            return Err("TAR entries must be ordinary files; links, sparse and extended headers are rejected".into());
        }
        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .map_err(|_| "Truncated TAR entry")?;
        if bytes.len() as u64 != entry.size() {
            return Err("Truncated TAR entry".into());
        }
        if files.insert(name, bytes).is_some() {
            return Err("Duplicate TAR entry".into());
        }
    }
    let cursor = archive.into_inner();
    let end = usize::try_from(cursor.position()).map_err(|_| "Invalid TAR position")?;
    if files.is_empty()
        || cursor.get_ref().get(end..).is_none_or(|tail| {
            tail.len() < 512 || tail.len() % 512 != 0 || tail.iter().any(|byte| *byte != 0)
        })
    {
        return Err("Empty TAR, missing complete end markers or nonzero trailing data".into());
    }
    Ok(files)
}
pub(super) fn zip(input: &[u8]) -> Result<Files, String> {
    // Reject ZIP64/multi-disk and excessive central-directory metadata before
    // ZipArchive allocates per-entry state. Only the structural EOCD envelope is
    // inspected here; the library owns archive/CRC/compression validation.
    let offset = (input.len().saturating_sub(65557)..input.len().saturating_sub(21))
        .rev()
        .find(|&offset| {
            input.get(offset..offset + 4) == Some(&b"PK\x05\x06"[..])
                && input.get(offset + 20..offset + 22).is_some_and(|bytes| {
                    offset + 22 + usize::from(u16::from_le_bytes([bytes[0], bytes[1]]))
                        == input.len()
                })
        })
        .ok_or("ZIP end record missing")?;
    let u16_at = |n| u16::from_le_bytes([input[offset + n], input[offset + n + 1]]);
    let u32_at = |n| {
        u32::from_le_bytes(
            input[offset + n..offset + n + 4]
                .try_into()
                .unwrap_or([0; 4]),
        )
    };
    let entries = u16_at(10);
    if offset >= 20 && input.get(offset - 20..offset - 16) == Some(&b"PK\x06\x07"[..]) {
        return Err("ZIP64 archives are not accepted".into());
    }
    if u16_at(4) != 0
        || u16_at(6) != 0
        || u16_at(8) != entries
        || entries == 0
        || entries > 64
        || u32_at(12) > 256 * 1024
    {
        return Err(
            "ZIP must contain 1..64 single-disk entries without ZIP64 and at most 256 KiB metadata"
                .into(),
        );
    }
    let mut archive =
        zip::ZipArchive::new(Cursor::new(input)).map_err(|_| "Invalid ZIP archive")?;
    if archive.len() > 64 {
        return Err("ZIP has too many entries".into());
    }
    let mut files = Files::new();
    let mut total = 0usize;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|_| "Invalid/encrypted/unsupported ZIP entry")?;
        let name = entry
            .name()
            .map_err(|_| "Invalid ZIP filename")?
            .into_owned();
        if name.len() > 1024 || entry.enclosed_name().is_none() || name.contains('\\') {
            return Err("Unsafe ZIP entry path".into());
        }
        if entry.is_dir() {
            continue;
        }
        if entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 != 0 && mode & 0o170000 != 0o100000)
        {
            return Err("ZIP entries must be ordinary files".into());
        }
        let remaining = MAX_EXPANDED_BYTES.saturating_sub(total);
        if entry.size() > remaining as u64 {
            return Err("ZIP expands beyond 64 MiB".into());
        }
        let mut bytes = Vec::new();
        entry
            .by_ref()
            .take(remaining as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "ZIP decoding or checksum failed")?;
        if bytes.len() > remaining {
            return Err("ZIP expands beyond 64 MiB".into());
        }
        total += bytes.len();
        if files.insert(name, bytes).is_some() {
            return Err("Duplicate ZIP entry".into());
        }
    }
    Ok(files)
}
