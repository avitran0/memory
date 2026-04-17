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
        let mut merged: HashMap<PathBuf, (usize, usize)> = HashMap::new();

        for entry in entries.drain(..) {
            let key = entry.path.clone();

            if let Some((start, end)) = merged.get_mut(&key) {
                *start = (*start).min(entry.start);
                *end = (*end).max(entry.end);
            } else {
                merged.insert(key, (entry.start, entry.end));
            }
        }

        *entries = merged
            .into_iter()
            .map(|(kind, (start, end))| MapsEntry {
                start,
                end,
                path: kind,
            })
            .collect();
    }

    pub fn find_library(&self, library: &str) -> Option<&MapsEntry> {
        self.entries.iter().find(|entry| {
            let Some(file_name) = entry.path.file_name() else {
                return false;
            };
            let Some(file_name) = file_name.to_str() else {
                return false;
            };
            file_name.contains(library)
        })
    }
}

/// Single entry in `/proc/{pid}/maps`
#[derive(Debug, Clone)]
pub struct MapsEntry {
    pub start: usize,
    pub end: usize,
    pub path: PathBuf,
}

impl MapsEntry {
    pub fn parse(entry: &str) -> Option<Self> {
        let parts: Vec<&str> = entry.split_ascii_whitespace().collect();
        if parts.len() < 6 {
            return None;
        }

        let address_range = parts[0].split_once('-')?;
        let Ok(start) = usize::from_str_radix(address_range.0, 16) else {
            return None;
        };
        let Ok(end) = usize::from_str_radix(address_range.1, 16) else {
            return None;
        };

        let path = PathBuf::from(parts[5]);

        Some(Self { start, end, path })
    }
}
