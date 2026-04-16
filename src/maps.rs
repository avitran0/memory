use std::{collections::HashMap, path::PathBuf};

/// Contains all loaded memory sections, read from `/proc/{pid}/maps`
pub struct ProcessMap {
    entries: Vec<MapsEntry>,
}

impl ProcessMap {
    pub fn read(pid: i32) -> std::io::Result<Self> {
        let maps_path = format!("/proc/{pid}/maps");
        let content = std::fs::read_to_string(maps_path)?;

        let mut entries = Vec::with_capacity(16);
        for line in content.lines() {
            let Some(entry) = MapsEntry::parse(line) else {
                continue;
            };
            entries.push(entry);
        }

        Self::deduplicate(&mut entries);

        Ok(Self { entries })
    }

    fn deduplicate(entries: &mut Vec<MapsEntry>) {
        let mut merged: HashMap<EntryKind, (usize, usize)> = HashMap::new();

        for entry in entries.drain(..) {
            let key = entry.kind.clone();

            if let Some((start, end)) = merged.get_mut(&key) {
                *start = (*start).min(entry.start);
                *end = (*end).max(entry.end);
            } else {
                merged.insert(key, (entry.start, entry.end));
            }
        }

        *entries = merged
            .into_iter()
            .map(|(kind, (start, end))| MapsEntry { start, end, kind })
            .collect();
    }

    pub fn find_library(&self, library: &str) -> Option<&MapsEntry> {
        self.entries.iter().find(|entry| {
            let EntryKind::File(file) = &entry.kind else {
                return false;
            };
            file.ends_with(library)
        })
    }
}

/// Single entry in `/proc/{pid}/maps`
#[derive(Debug, Clone)]
pub struct MapsEntry {
    pub start: usize,
    pub end: usize,
    pub kind: EntryKind,
}

impl MapsEntry {
    pub fn parse(entry: &str) -> Option<Self> {
        let parts: Vec<&str> = entry.split_ascii_whitespace().collect();
        if parts.len() < 5 {
            return None;
        }

        let address_range = parts[0].split_once('-')?;
        let start = usize::from_str_radix(address_range.0, 16).unwrap_or_default();
        let end = usize::from_str_radix(address_range.1, 16).unwrap_or_default();

        let kind = match parts.get(5) {
            Some(pathname) => match *pathname {
                "[stack]" => EntryKind::Stack,
                "[heap]" => EntryKind::Heap,
                other => EntryKind::File(PathBuf::from(other)),
            },
            None => EntryKind::Anonymous,
        };

        Some(Self { start, end, kind })
    }
}

/// Corresponds to `pathname` in maps.
///
/// `vdso`, `vvar` and some others are purposefully omitted,
/// since they are not needed.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum EntryKind {
    Anonymous,
    Stack,
    Heap,
    File(PathBuf),
}

impl std::fmt::Display for EntryKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Anonymous => "[anonymous]",
                Self::Stack => "[stack]",
                Self::Heap => "[heap]",
                Self::File(path) => path.to_str().unwrap_or_default(),
            }
        )
    }
}
