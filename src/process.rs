use std::{
    cell::RefCell,
    collections::HashMap,
    fs::File,
    io::{BufReader, Error, ErrorKind, Read, Seek, SeekFrom},
};

use bytemuck::{AnyBitPattern, NoUninit};

use crate::{
    maps::{Library, ProcessMap},
    proc::find_pid,
};

pub struct Process {
    name: ProcessName,
    pid: i32,
    map: ProcessMap,
    string_cache: RefCell<HashMap<usize, String>>,
}

impl Process {
    pub fn open(name: ProcessName) -> std::io::Result<Self> {
        let pid = match name.kind {
            ProcessKind::Native => find_pid(|exe, _| exe == name.name),
            ProcessKind::Proton => {
                find_pid(|exe, cmdline| exe == "wine64-preloader" && cmdline.ends_with(name.name))
            }
        }
        .ok_or_else(|| {
            Error::new(
                ErrorKind::NotFound,
                format!("Process {} was not found", name),
            )
        })?;

        Self::open_pid(pid, Some(name))
    }

    pub fn open_pid(pid: i32, name: Option<ProcessName>) -> std::io::Result<Self> {
        let map = ProcessMap::read(pid)?;
        let string_cache = RefCell::new(HashMap::new());
        let name = name.unwrap_or(ProcessName {
            name: "",
            kind: ProcessKind::Native,
        });

        Ok(Self {
            name,
            pid,
            map,
            string_cache,
        })
    }

    pub fn read<T: Default + AnyBitPattern + NoUninit>(&self, address: usize) -> T {
        let mut value = T::default();
        let buffer = bytemuck::bytes_of_mut(&mut value);

        self.read_impl(address, buffer);

        value
    }

    pub fn read_vec<T: Default + AnyBitPattern>(
        &self,
        address: usize,
        stride: usize,
        count: usize,
    ) -> Vec<T> {
        let size = size_of::<T>();
        assert!(stride >= size);

        let mut buffer = vec![0u8; stride * count];

        self.read_impl(address, &mut buffer);

        let mut result = vec![T::default(); count];
        let result_ptr = result.as_mut_ptr().cast::<u8>();

        for i in 0..count {
            unsafe {
                let src = buffer.as_ptr().add(i * stride);
                let dst = result_ptr.add(i * size);
                std::ptr::copy_nonoverlapping(src, dst, size);
            }
        }

        result
    }

    pub fn read_bytes<const BYTES: usize>(&self, address: usize) -> [u8; BYTES] {
        let mut value = [0; BYTES];

        self.read_impl(address, &mut value);

        value
    }

    pub fn write<T: AnyBitPattern + NoUninit>(&self, address: usize, mut value: T) {
        let buffer = bytemuck::bytes_of_mut(&mut value);

        let local_iov = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: buffer.len(),
        };
        let remote_iov = libc::iovec {
            iov_base: address as *mut libc::c_void,
            iov_len: buffer.len(),
        };

        let result = unsafe {
            libc::process_vm_writev(
                self.pid,
                &raw const local_iov,
                1,
                &raw const remote_iov,
                1,
                0,
            )
        };

        Self::handle_error(result, size_of::<T>().cast_signed());
    }

    pub fn read_string(&self, address: usize) -> String {
        if let Some(cached) = self.string_cache.borrow().get(&address).cloned() {
            return cached;
        }

        let string = self.read_string_uncached(address);
        self.string_cache
            .borrow_mut()
            .insert(address, string.clone());
        string
    }

    pub fn read_string_uncached(&self, address: usize) -> String {
        const BATCH_SIZE: usize = 64;
        let mut bytes = Vec::with_capacity(BATCH_SIZE);
        let mut buffer = [0u8; BATCH_SIZE];
        let mut current_address = address;

        loop {
            let chunk = self.read_bytes::<BATCH_SIZE>(current_address);
            buffer.copy_from_slice(&chunk);

            if let Some(null_pos) = buffer.iter().position(|&b| b == 0) {
                bytes.extend_from_slice(&buffer[..null_pos]);
                break;
            }

            bytes.extend_from_slice(&buffer);
            current_address += BATCH_SIZE;
        }

        String::from_utf8(bytes).unwrap_or_default()
    }

    fn read_impl(&self, address: usize, buffer: &mut [u8]) {
        let local_iov = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: buffer.len(),
        };
        let remote_iov = libc::iovec {
            iov_base: address as *mut libc::c_void,
            iov_len: buffer.len(),
        };

        let result = unsafe {
            libc::process_vm_readv(
                self.pid,
                &raw const local_iov,
                1,
                &raw const remote_iov,
                1,
                0,
            )
        };

        Self::handle_error(result, buffer.len().cast_signed());
    }

    fn handle_error(result: isize, expected: isize) {
        if result == -1 {
            panic!("{}", Error::last_os_error());
        }

        if result < expected {
            panic!("Partial transfer: {result} out of {expected} bytes");
        }
    }

    fn dump_library(&self, library: &Library) -> Option<Vec<u8>> {
        let file = format!("/proc/{}/mem", self.pid);
        let file = File::open(file).ok()?;
        let mut reader = BufReader::new(file);

        reader.seek(SeekFrom::Start(library.start as u64)).ok()?;
        let mut buf = vec![0; library.end - library.start];
        reader.read_exact(&mut buf).ok()?;
        Some(buf)
    }

    pub fn scan(&self, pattern: &str, library: &Library) -> Option<usize> {
        let mut bytes = Vec::with_capacity(8);
        let mut mask = Vec::with_capacity(8);

        for token in pattern.split_whitespace() {
            if token == "?" || token == "??" {
                bytes.push(0x00);
                mask.push(0x00);
            } else if token.len() == 2 {
                match u8::from_str_radix(token, 16) {
                    Ok(b) => {
                        bytes.push(b);
                        mask.push(0xFF);
                    }
                    Err(_) => {
                        utils::warn!("unrecognized pattern token \"{token}\" in pattern {pattern}");
                    }
                }
            } else {
                utils::warn!("unrecognized pattern token \"{token}\" in pattern {pattern}");
            }
        }

        let module = self.dump_library(library)?;
        if module.len() < 500 {
            return None;
        }

        let scan_func = if bytes.len() <= 32 && is_x86_feature_detected!("avx2") {
            scan_simd
        } else {
            scan_normal
        };

        if let Some(address) =
            scan_func(&bytes, &mask, &module).map(|address| library.start + address)
        {
            return Some(address);
        }

        utils::info!("pattern {pattern} not found, might be outdated");
        None
    }

    pub fn find_export(&self, entry: &Library, name: &str) -> std::io::Result<usize> {
        let data = std::fs::read(&entry.path)?;
        match self.name.kind {
            ProcessKind::Native => {
                let elf = goblin::elf::Elf::parse(&data).map_err(Error::other)?;

                for sym in &elf.dynsyms {
                    let Some(sym_name) = elf.dynstrtab.get_at(sym.st_name) else {
                        continue;
                    };
                    if sym_name == name {
                        return Ok(entry.start + sym.st_value as usize);
                    }
                }

                Err(Error::new(
                    ErrorKind::NotFound,
                    format!("Export '{}' not found in ELF", name),
                ))
            }
            ProcessKind::Proton => {
                let pe = goblin::pe::PE::parse(&data).map_err(Error::other)?;

                for export in &pe.exports {
                    let Some(export_name) = export.name else {
                        continue;
                    };
                    if export_name == name {
                        let export_rva = export.rva;
                        return Ok(entry.start + export_rva);
                    }
                }

                Err(Error::new(
                    ErrorKind::NotFound,
                    format!("Export '{}' not found in PE", name),
                ))
            }
        }
    }

    pub fn get_relative_address(
        &self,
        instruction: usize,
        offset: usize,
        instruction_size: usize,
    ) -> usize {
        let rip_address: i32 = self.read(instruction + offset);
        instruction
            .wrapping_add(instruction_size)
            .wrapping_add_signed(rip_address as isize)
    }

    pub fn map(&self) -> &ProcessMap {
        &self.map
    }
}

fn scan_normal(bytes: &[u8], mask: &[u8], library: &[u8]) -> Option<usize> {
    let pattern_length = bytes.len();
    if pattern_length == 0 || library.len() < pattern_length {
        return None;
    }
    let stop_index = library.len() - pattern_length;
    'outer: for i in 0..=stop_index {
        for j in 0..pattern_length {
            if mask[j] == 0xFF && library[i + j] != bytes[j] {
                continue 'outer;
            }
        }
        return Some(i);
    }
    None
}

fn scan_simd(bytes: &[u8], mask: &[u8], library: &[u8]) -> Option<usize> {
    use std::arch::x86_64::{
        __m256i, _mm256_and_si256, _mm256_loadu_si256, _mm256_testz_si256, _mm256_xor_si256,
    };

    let pattern_length = bytes.len();
    assert!(pattern_length <= 32);
    assert_eq!(mask.len(), pattern_length);
    assert_eq!(mask[0], 0xFF);

    if library.len() < 32 {
        return None;
    }

    let stop_index = library.len() - 32;

    let mut pattern_padded = [0u8; 32];
    let mut mask_padded = [0u8; 32];
    pattern_padded[..pattern_length].copy_from_slice(bytes);
    mask_padded[..pattern_length].copy_from_slice(mask);

    let pattern = unsafe { _mm256_loadu_si256(pattern_padded.as_ptr().cast::<__m256i>()) };
    let mask = unsafe { _mm256_loadu_si256(mask_padded.as_ptr().cast::<__m256i>()) };

    for i in 0..=stop_index {
        if library[i] != bytes[0] {
            continue;
        }
        let chunk_bytes = unsafe { _mm256_loadu_si256(library.as_ptr().add(i) as *const __m256i) };
        let pattern_xor = unsafe { _mm256_xor_si256(chunk_bytes, pattern) };
        let masked = unsafe { _mm256_and_si256(pattern_xor, mask) };

        if unsafe { _mm256_testz_si256(masked, masked) } == 1 {
            return Some(i);
        }
    }

    None
}

#[derive(Debug, Clone, Copy)]
pub struct ProcessName {
    pub name: &'static str,
    pub kind: ProcessKind,
}

#[derive(Debug, Clone, Copy)]
pub enum ProcessKind {
    Native,
    Proton,
}

impl std::fmt::Display for ProcessName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::Process;

    fn current_process() -> Process {
        let pid = std::process::id().cast_signed();
        Process::open_pid(pid, None).expect("Failed to open current process")
    }

    #[test]
    fn test_find_export_strlen() {
        let process = current_process();
        let libc = process
            .map()
            .find_library("libc.so")
            .expect("Failed to find libc");

        let function = process.find_export(libc, "process_vm_readv");
        assert!(function.is_ok());
    }
}
