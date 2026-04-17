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

        let programs: Vec<elf::ProgramHeader> = shared.read_vec(
            entry.start + header.phoff as usize,
            header.phentsize as usize,
            header.phnum as usize,
        )?;

        let dyn_segment = programs
            .iter()
            .find(|p| p.type_ == 2)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "No PT_DYNAMIC segment found"))?;

        let dyn_count = dyn_segment.filesz / 16;
        let mut symtab_addr = 0usize;
        let mut strtab_addr = 0usize;

        for i in 0..dyn_count {
            let dyn_offset = (dyn_segment.vaddr as usize) + (i as usize * 16);
            let dyn_entry: elf::Dynamic = shared.read(entry.start + dyn_offset)?;

            match dyn_entry.tag {
                4 => symtab_addr = dyn_entry.value as usize, // DT_SYMTAB
                5 => strtab_addr = dyn_entry.value as usize, // DT_STRTAB
                0 => break,                                  // DT_NULL
                _ => {}
            }
        }

        if symtab_addr == 0 || strtab_addr == 0 {
            return Err(Error::new(
                ErrorKind::NotFound,
                "Failed to find DT_SYMTAB or DT_STRTAB",
            ));
        }

        let mut i = 0;
        loop {
            let symbol_addr = symtab_addr + (i * 16);
            let symbol: elf::Symbol = shared.read(symbol_addr)?;

            if symbol.name == 0 && i > 0 {
                break;
            }

            if symbol.name != 0 {
                let name_addr = strtab_addr + symbol.name as usize;
                let symbol_name = shared.read_string(name_addr)?;

                if symbol_name == name {
                    return Ok(entry.start + symbol.value as usize);
                }
            }

            i += 1;
        }

        Err(Error::new(
            ErrorKind::NotFound,
            format!("Failed to find export {}", name),
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
        pub hsize: u16,
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
    pub struct ProgramHeader {
        pub type_: u32,
        pub flags: u32,
        pub offset: u64,
        pub vaddr: u64,
        pub paddr: u64,
        pub filesz: u64,
        pub memsz: u64,
        pub align: u64,
    }

    #[repr(C)]
    #[derive(Default, Clone, Copy, AnyBitPattern, NoUninit)]
    pub struct Dynamic {
        pub tag: u64,
        pub value: u64,
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
