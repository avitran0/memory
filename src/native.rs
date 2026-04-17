use std::io::{Error, ErrorKind};

use crate::{
    maps::{EntryKind, MapsEntry},
    process::{PlatformProcess, SharedProcess},
};

pub struct NativeProcess {}

impl PlatformProcess for NativeProcess {
    fn find_export(
        shared: &SharedProcess,
        entry: &MapsEntry,
        name: &str,
    ) -> std::io::Result<usize> {
        let EntryKind::File(_) = entry.kind else {
            return Err(std::io::Error::other("Not a library"));
        };

        let header: elf::Header = shared.read(entry.start)?;
        if header.ident.magic != [0x7F, b'E', b'L', b'F'] {
            return Err(std::io::Error::other("Invalid magic"));
        }

        let sections: Vec<elf::SectionHeader> = shared.read_vec(
            entry.start + header.shoff as usize,
            header.shentsize as usize,
            header.shnum as usize,
        )?;

        // export table (.dynsym section)
        let dynsym_section = sections
            .iter()
            .find(|s| s.type_ == 11)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "No .dynsym section found"))?;

        // .dynstr section *should* be in the link address of the .dynsym section header
        let dynstr_section = sections.get(dynsym_section.link as usize).ok_or_else(|| {
            Error::new(
                ErrorKind::NotFound,
                "Failed to find .dynstr section from .dynsym link",
            )
        })?;

        let symbol_count = dynsym_section.size / dynsym_section.entsize;
        for i in 0..symbol_count {
            let symbol_offset =
                dynsym_section.addr as usize + (i as usize * dynsym_section.entsize as usize);
            let symbol: elf::Symbol = shared.read(entry.start + symbol_offset)?;

            if symbol.name == 0 {
                continue;
            }

            let name_offset = dynstr_section.addr as usize + symbol.name as usize;
            let symbol_name = shared.read_string(entry.start + name_offset)?;

            if symbol_name == name {
                return Ok(entry.start + symbol.value as usize);
            }
        }

        Err(Error::new(
            ErrorKind::NotFound,
            format!("Failed to find export {}", entry.kind),
        ))
    }
}

mod elf {
    use bytemuck::{AnyBitPattern, NoUninit};

    #[repr(C)]
    #[derive(Default, Clone, Copy, AnyBitPattern, NoUninit)]
    pub struct Ident {
        pub magic: [u8; 4],
        /// architecture (32 or 64 bits)
        class: u8,
        /// byte order
        data: u8,
        /// elf version, always 1
        version: u8,
        osabi: u8,
        abi_version: u8,
        _pad: [u8; 7],
    }

    #[repr(C)]
    #[derive(Default, Clone, Copy, AnyBitPattern, NoUninit)]
    pub struct Header {
        pub ident: Ident,
        type_: u16,
        machine: u16,
        version: u32,
        entry: u64,
        /// program header offset
        pub phoff: u64,
        /// section header offset
        pub shoff: u64,
        flags: u32,
        /// header size
        hsize: u16,
        /// program header entry size
        pub phentsize: u16,
        /// program header count
        pub phnum: u16,
        /// section header entry size
        pub shentsize: u16,
        /// section header count
        pub shnum: u16,
        /// section header string table index
        pub shstrndx: u16,
    }

    #[repr(C)]
    #[derive(Default, Clone, Copy, AnyBitPattern, NoUninit)]
    pub struct SectionHeader {
        pub name: u32,
        pub type_: u32,
        pub flags: u64,
        pub addr: u64,
        pub offset: u64,
        pub size: u64,
        /// contains some related info
        pub link: u32,
        pub info: u32,
        pub addr_align: u64,
        /// section entry size
        pub entsize: u64,
    }

    #[repr(C)]
    #[derive(Default, Clone, Copy, AnyBitPattern, NoUninit)]
    pub struct Symbol {
        /// index in the string table
        pub name: u32,
        pub info: u8,
        pub other: u8,
        pub shndx: u16,
        pub value: u64,
        pub size: u64,
    }
}

#[cfg(test)]
mod test {
    use crate::{
        native::NativeProcess,
        process::{PlatformProcess, SharedProcess},
    };

    #[test]
    fn find_export() {
        let shared = SharedProcess::open_pid(std::process::id().cast_signed()).unwrap();

        let map = shared.map();
        assert!(
            NativeProcess::find_export(
                &shared,
                map.find_library("libc.so").unwrap(),
                "process_vm_readv"
            )
            .is_ok()
        );
    }
}
