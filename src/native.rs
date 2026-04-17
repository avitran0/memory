use std::io::{Error, ErrorKind};

use crate::{
    maps::{EntryKind, MapsEntry},
    process::{PlatformProcess, SharedProcess},
};

pub struct NativeProcess {}

impl PlatformProcess for NativeProcess {
    fn find_export(shared: &SharedProcess, entry: &MapsEntry) -> std::io::Result<usize> {
        let EntryKind::File(_) = entry.kind else {
            return Err(std::io::Error::other("Not a library"));
        };

        let header: elf::Header = shared.read(entry.start)?;
        if header.ident.magic != [0x7F, b'E', b'L', b'F'] {
            return Err(std::io::Error::other("Invalid magic"));
        }

        let sections = Self::elf_sections(shared, &header)?;
        let _string_table = sections.get(header.shstrndx as usize).ok_or(Error::new(
            std::io::ErrorKind::NotFound,
            "Failed to find string table",
        ));

        Err(Error::new(
            ErrorKind::NotFound,
            format!("Failed to find export {}", entry.kind),
        ))
    }
}

impl NativeProcess {
    fn elf_sections(
        shared: &SharedProcess,
        header: &elf::Header,
    ) -> std::io::Result<Vec<elf::SectionHeader>> {
        shared.read_vec(
            header.shoff as usize,
            header.shentsize as usize,
            header.shnum as usize,
        )
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
        name: u32,
        type_: u32,
        flags: u64,
        addr: u64,
        offset: u64,
        size: u64,
        link: u32,
        info: u32,
        addr_align: u64,
        entsize: u64,
    }
}
