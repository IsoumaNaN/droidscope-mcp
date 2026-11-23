use std::collections::{HashMap, HashSet};
use serde_json::{Map, Value};

#[derive(Debug, Clone)]
pub struct ElfSection {
    pub name: String,
    pub sh_type: u32,
    pub flags: u64,
    pub vaddr: u64,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct ElfSegment {
    pub p_type: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
}

#[derive(Debug, Clone)]
pub struct ElfSymbol {
    pub name: String,
    pub vaddr: u64,
    pub size: u64,
    pub bind: u8,
    pub sym_type: u8,
    pub shndx: u16,
}

#[derive(Debug, Clone)]
pub struct JniRegisteredMethod {
    pub method_name: String,
    pub signature: String,
    pub fn_vaddr: u64,
    pub source: String,
    pub table_vaddr: Option<u64>,
    pub matched_java_classes: Vec<String>,
}

pub struct ParsedElf<'a> {
    pub data: &'a [u8],
    pub is_64: bool,
    pub is_le: bool,
    pub machine: u16,
    pub entry: u64,
    pub segments: Vec<ElfSegment>,
    pub sections: Vec<ElfSection>,
    pub needed_libs: Vec<String>,
    pub soname: Option<String>,
    pub exports: Vec<ElfSymbol>,
    pub imports: Vec<String>,
    pub init_array: Vec<u64>,
    /// Virtual address -> relocated target virtual address (from RELA/REL)
    pub relocations: HashMap<u64, u64>,
    /// Virtual address (GOT or PLT stub) -> imported/exported symbol name
    pub addr_to_symbol: HashMap<u64, String>,
    pub symbol_to_addr: HashMap<String, u64>,
}

impl<'a> ParsedElf<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, String> {
        if data.len() < 52 || &data[0..4] != b"\x7fELF" {
            return Err("Not a valid ELF binary".to_string());
        }
        let ei_class = data[4];
        let ei_data = data[5];
        let is_64 = match ei_class {
            1 => false,
            2 => true,
            _ => return Err(format!("Unsupported ELF class: {}", ei_class)),
        };
        let is_le = ei_data == 1;

        let rd16 = |off: usize| -> u16 {
            if off + 2 > data.len() {
                return 0;
            }
            if is_le {
                u16::from_le_bytes([data[off], data[off + 1]])
            } else {
                u16::from_be_bytes([data[off], data[off + 1]])
            }
        };
        let rd32 = |off: usize| -> u32 {
            if off + 4 > data.len() {
                return 0;
            }
            let b: [u8; 4] = data[off..off + 4].try_into().unwrap();
            if is_le {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            }
        };
        let rd64 = |off: usize| -> u64 {
            if off + 8 > data.len() {
                return 0;
            }
            let b: [u8; 8] = data[off..off + 8].try_into().unwrap();
            if is_le {
                u64::from_le_bytes(b)
            } else {
                u64::from_be_bytes(b)
            }
        };

        let machine = rd16(18);
        let (entry, phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx) = if is_64 {
            if data.len() < 64 {
                return Err("Truncated ELF64 header".to_string());
            }
            (
                rd64(24),
                rd64(32) as usize,
                rd64(40) as usize,
                rd16(54) as usize,
                rd16(56) as usize,
                rd16(58) as usize,
                rd16(60) as usize,
                rd16(62) as usize,
            )
        } else {
            (
                rd32(24) as u64,
                rd32(28) as usize,
                rd32(32) as usize,
                rd16(42) as usize,
                rd16(44) as usize,
                rd16(46) as usize,
                rd16(48) as usize,
                rd16(50) as usize,
            )
        };

        // 1. Parse Program Headers
        let mut segments = Vec::new();
        if phoff > 0 && phentsize > 0 && phnum < 1024 {
            for i in 0..phnum {
                let off = phoff + i * phentsize;
                if off + phentsize > data.len() {
                    break;
                }
                if is_64 {
                    segments.push(ElfSegment {
                        p_type: rd32(off),
                        flags: rd32(off + 4),
                        offset: rd64(off + 8),
                        vaddr: rd64(off + 16),
                        filesz: rd64(off + 32),
                        memsz: rd64(off + 40),
                    });
                } else {
                    segments.push(ElfSegment {
                        p_type: rd32(off),
                        offset: rd32(off + 4) as u64,
                        vaddr: rd32(off + 8) as u64,
                        filesz: rd32(off + 16) as u64,
                        memsz: rd32(off + 20) as u64,
                        flags: rd32(off + 24),
                    });
                }
            }
        }

        // 2. Parse Section Headers
        let mut raw_sections = Vec::new();
        if shoff > 0 && shentsize > 0 && shnum < 4096 {
            for i in 0..shnum {
                let off = shoff + i * shentsize;
                if off + shentsize > data.len() {
                    break;
                }
                if is_64 {
                    raw_sections.push((
                        rd32(off) as usize,
                        rd32(off + 4),
                        rd64(off + 8),
                        rd64(off + 16),
                        rd64(off + 24),
                        rd64(off + 32),
                        rd32(off + 40) as usize,
                        rd64(off + 56) as usize,
                    ));
                } else {
                    raw_sections.push((
                        rd32(off) as usize,
                        rd32(off + 4),
                        rd32(off + 8) as u64,
                        rd32(off + 12) as u64,
                        rd32(off + 16) as u64,
                        rd32(off + 20) as u64,
                        rd32(off + 24) as usize,
                        rd32(off + 36) as usize,
                    ));
                }
            }
        }

        let shstrtab_range = raw_sections
            .get(shstrndx)
            .map(|s| (s.4 as usize, (s.4 + s.5) as usize))
            .filter(|&(start, end)| start < end && end <= data.len());

        let mut sections = Vec::with_capacity(raw_sections.len());
        for &(name_off, sh_type, flags, vaddr, offset, size, _link, _entsize) in &raw_sections {
            let name = if let Some((s_start, s_end)) = shstrtab_range {
                read_cstr(&data[s_start..s_end], name_off)
            } else {
                String::new()
            };
            sections.push(ElfSection {
                name,
                sh_type,
                flags,
                vaddr,
                offset,
                size,
            });
        }

        let mut elf = ParsedElf {
            data,
            is_64,
            is_le,
            machine,
            entry,
            segments,
            sections,
            needed_libs: Vec::new(),
            soname: None,
            exports: Vec::new(),
            imports: Vec::new(),
            init_array: Vec::new(),
            relocations: HashMap::new(),
            addr_to_symbol: HashMap::new(),
            symbol_to_addr: HashMap::new(),
        };

        elf.parse_symbols_and_relocs(&raw_sections);
        elf.parse_dynamic();
        elf.parse_init_array();
        elf.resolve_plt_stubs();

        Ok(elf)
    }

    pub fn arch_name(&self) -> &'static str {
        match self.machine {
            183 => "AArch64 (ARM64)",
            40 => "ARM32",
            62 => "x86_64",
            3 => "x86",
            _ => "Unknown",
        }
    }

    pub fn vaddr_to_offset(&self, vaddr: u64) -> Option<usize> {
        for seg in &self.segments {
            if seg.p_type == 1 && vaddr >= seg.vaddr && vaddr < seg.vaddr.saturating_add(seg.filesz)
            {
                let off = seg.offset + (vaddr - seg.vaddr);
                if (off as usize) < self.data.len() {
                    return Some(off as usize);
                }
            }
        }
        for sec in &self.sections {
            if sec.sh_type != 8
                && sec.vaddr > 0
                && vaddr >= sec.vaddr
                && vaddr < sec.vaddr.saturating_add(sec.size)
            {
                let off = sec.offset + (vaddr - sec.vaddr);
                if (off as usize) < self.data.len() {
                    return Some(off as usize);
                }
            }
        }
        None
    }

    pub fn offset_to_vaddr(&self, offset: usize) -> Option<u64> {
        let off = offset as u64;
        for seg in &self.segments {
            if seg.p_type == 1 && off >= seg.offset && off < seg.offset.saturating_add(seg.filesz) {
                return Some(seg.vaddr + (off - seg.offset));
            }
        }
        None
    }

    pub fn is_executable_vaddr(&self, vaddr: u64) -> bool {
        if vaddr == 0 {
            return false;
        }
        for seg in &self.segments {
            // PT_LOAD = 1, PF_X = 1
            if seg.p_type == 1
                && (seg.flags & 1) != 0
                && vaddr >= seg.vaddr
                && vaddr < seg.vaddr.saturating_add(seg.filesz)
            {
                return true;
            }
        }
        for sec in &self.sections {
            // SHF_EXECINSTR = 0x4
            if (sec.flags & 0x4) != 0
                && vaddr >= sec.vaddr
                && vaddr < sec.vaddr.saturating_add(sec.size)
            {
                return true;
            }
        }
        false
    }

    pub fn read_u32_at_offset(&self, off: usize) -> Option<u32> {
        if off + 4 > self.data.len() {
            return None;
        }
        let b: [u8; 4] = self.data[off..off + 4].try_into().ok()?;
        Some(if self.is_le {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }

    pub fn read_u64_at_offset(&self, off: usize) -> Option<u64> {
        if off + 8 > self.data.len() {
            return None;
        }
        let b: [u8; 8] = self.data[off..off + 8].try_into().ok()?;
        Some(if self.is_le {
            u64::from_le_bytes(b)
        } else {
            u64::from_be_bytes(b)
        })
    }

    pub fn read_ptr_at_vaddr(&self, vaddr: u64) -> Option<u64> {
        if let Some(&reloc_target) = self.relocations.get(&vaddr) {
            if reloc_target != 0 {
                return Some(reloc_target);
            }
        }
        let off = self.vaddr_to_offset(vaddr)?;
        let raw = if self.is_64 {
            self.read_u64_at_offset(off)?
        } else {
            self.read_u32_at_offset(off)? as u64
        };
        // Strip AArch64 pointer authentication / top-byte-ignore tags if present
        let untagged = if self.is_64 && (raw >> 48) != 0 && (raw >> 48) != 0xFFFF {
            raw & 0x0000_FFFF_FFFF_FFFF
        } else {
            raw
        };
        Some(untagged)
    }

    pub fn read_cstr_at_vaddr(&self, vaddr: u64, max_len: usize) -> Option<String> {
        let off = self.vaddr_to_offset(vaddr)?;
        read_validated_cstr(self.data, off, max_len)
    }

    fn parse_symbols_and_relocs(
        &mut self,
        raw_sections: &[(usize, u32, u64, u64, u64, u64, usize, usize)],
    ) {
        let mut dynsym_names: Vec<(String, u64)> = Vec::new();
        let mut seen_imports: HashSet<String> = HashSet::new();
        let mut seen_exports: HashSet<String> = HashSet::new();

        for (sec_idx, &(_name_off, sh_type, _flags, _vaddr, offset, size, link, entsize)) in
            raw_sections.iter().enumerate()
        {
            // SHT_DYNSYM = 11, SHT_SYMTAB = 2
            if sh_type != 11 && sh_type != 2 {
                continue;
            }
            let Some(&(_, _, _, _, str_off, str_size, _, _)) = raw_sections.get(link) else {
                continue;
            };
            let s_start = str_off as usize;
            let s_end = (str_off + str_size) as usize;
            if s_start >= s_end || s_end > self.data.len() {
                continue;
            }
            let strtab = &self.data[s_start..s_end];
            let entry_sz = if entsize > 0 {
                entsize
            } else if self.is_64 {
                24
            } else {
                16
            };
            let count = (size as usize) / entry_sz;
            let base = offset as usize;

            let mut local_syms = Vec::with_capacity(count);
            for i in 0..count {
                let eoff = base + i * entry_sz;
                if eoff + entry_sz > self.data.len() {
                    break;
                }
                let (st_name, st_info, st_shndx, st_value, st_size) = if self.is_64 {
                    (
                        self.read_u32_at_offset(eoff).unwrap_or(0) as usize,
                        self.data[eoff + 4],
                        if eoff + 8 <= self.data.len() {
                            u16::from_le_bytes([self.data[eoff + 6], self.data[eoff + 7]])
                        } else {
                            0
                        },
                        self.read_u64_at_offset(eoff + 8).unwrap_or(0),
                        self.read_u64_at_offset(eoff + 16).unwrap_or(0),
                    )
                } else {
                    (
                        self.read_u32_at_offset(eoff).unwrap_or(0) as usize,
                        self.data[eoff + 12],
                        if eoff + 16 <= self.data.len() {
                            u16::from_le_bytes([self.data[eoff + 14], self.data[eoff + 15]])
                        } else {
                            0
                        },
                        self.read_u32_at_offset(eoff + 4).unwrap_or(0) as u64,
                        self.read_u32_at_offset(eoff + 8).unwrap_or(0) as u64,
                    )
                };
                let name = read_cstr(strtab, st_name);
                local_syms.push((name.clone(), st_value));
                if name.is_empty() {
                    continue;
                }
                let bind = st_info >> 4;
                let sym_type = st_info & 0xf;
                if st_shndx == 0 {
                    if seen_imports.insert(name.clone()) {
                        self.imports.push(name);
                    }
                } else if st_value > 0 {
                    let clean_addr = if self.machine == 40 {
                        st_value & !1
                    } else {
                        st_value
                    };
                    self.addr_to_symbol
                        .entry(clean_addr)
                        .or_insert_with(|| name.clone());
                    self.symbol_to_addr.entry(name.clone()).or_insert(clean_addr);
                    if (bind == 1 || bind == 2) && seen_exports.insert(name.clone()) {
                        self.exports.push(ElfSymbol {
                            name,
                            vaddr: clean_addr,
                            size: st_size,
                            bind,
                            sym_type,
                            shndx: st_shndx,
                        });
                    }
                }
            }
            if sh_type == 11 || dynsym_names.is_empty() {
                dynsym_names = local_syms;
            }
            let _ = sec_idx;
        }

        // Parse SHT_RELA (4) and SHT_REL (9)
        for &(_name_off, sh_type, _flags, _vaddr, offset, size, _link, entsize) in raw_sections {
            if sh_type == 4 {
                let entry_sz = if entsize > 0 {
                    entsize
                } else if self.is_64 {
                    24
                } else {
                    12
                };
                let count = (size as usize) / entry_sz;
                let base = offset as usize;
                for i in 0..count {
                    let eoff = base + i * entry_sz;
                    if eoff + entry_sz > self.data.len() {
                        break;
                    }
                    if self.is_64 {
                        let r_offset = self.read_u64_at_offset(eoff).unwrap_or(0);
                        let r_info = self.read_u64_at_offset(eoff + 8).unwrap_or(0);
                        let r_addend = self.read_u64_at_offset(eoff + 16).unwrap_or(0);
                        let sym_idx = (r_info >> 32) as usize;
                        let r_type = (r_info & 0xFFFF_FFFF) as u32;
                        // R_AARCH64_RELATIVE (1027), R_X86_64_RELATIVE (8)
                        if r_type == 1027 || r_type == 8 {
                            if r_addend > 0 {
                                self.relocations.insert(r_offset, r_addend);
                            }
                        } else if sym_idx > 0 {
                            if let Some((sym_name, sym_val)) = dynsym_names.get(sym_idx) {
                                if !sym_name.is_empty() {
                                    self.addr_to_symbol.insert(r_offset, sym_name.clone());
                                }
                                let target = sym_val.wrapping_add(r_addend);
                                if target > 0 {
                                    self.relocations.insert(r_offset, target);
                                }
                            }
                        }
                    } else {
                        let r_offset = self.read_u32_at_offset(eoff).unwrap_or(0) as u64;
                        let r_info = self.read_u32_at_offset(eoff + 4).unwrap_or(0);
                        let r_addend = self.read_u32_at_offset(eoff + 8).unwrap_or(0) as u64;
                        let sym_idx = (r_info >> 8) as usize;
                        let r_type = r_info & 0xFF;
                        if r_type == 23 && r_addend > 0 {
                            self.relocations.insert(r_offset, r_addend);
                        } else if sym_idx > 0 {
                            if let Some((sym_name, _)) = dynsym_names.get(sym_idx) {
                                if !sym_name.is_empty() {
                                    self.addr_to_symbol.insert(r_offset, sym_name.clone());
                                }
                            }
                        }
                    }
                }
            } else if sh_type == 9 {
                let entry_sz = if entsize > 0 {
                    entsize
                } else if self.is_64 {
                    16
                } else {
                    8
                };
                let count = (size as usize) / entry_sz;
                let base = offset as usize;
                for i in 0..count {
                    let eoff = base + i * entry_sz;
                    if eoff + entry_sz > self.data.len() {
                        break;
                    }
                    let (r_offset, sym_idx) = if self.is_64 {
                        let ro = self.read_u64_at_offset(eoff).unwrap_or(0);
                        let ri = self.read_u64_at_offset(eoff + 8).unwrap_or(0);
                        (ro, (ri >> 32) as usize)
                    } else {
                        let ro = self.read_u32_at_offset(eoff).unwrap_or(0) as u64;
                        let ri = self.read_u32_at_offset(eoff + 4).unwrap_or(0);
                        (ro, (ri >> 8) as usize)
                    };
                    if sym_idx > 0 {
                        if let Some((sym_name, _)) = dynsym_names.get(sym_idx) {
                            if !sym_name.is_empty() {
                                self.addr_to_symbol.insert(r_offset, sym_name.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    fn parse_dynamic(&mut self) {
        let mut dyn_off_size = None;
        for seg in &self.segments {
            // PT_DYNAMIC = 2
            if seg.p_type == 2 && seg.filesz > 0 {
                dyn_off_size = Some((seg.offset as usize, seg.filesz as usize));
                break;
            }
        }
        if dyn_off_size.is_none() {
            for sec in &self.sections {
                // SHT_DYNAMIC = 6
                if sec.sh_type == 6 && sec.size > 0 {
                    dyn_off_size = Some((sec.offset as usize, sec.size as usize));
                    break;
                }
            }
        }
        let Some((dyn_off, dyn_size)) = dyn_off_size else {
            return;
        };
        if dyn_off + dyn_size > self.data.len() {
            return;
        }

        // Find .dynstr
        let mut dynstr_slice: Option<&[u8]> = None;
        for sec in &self.sections {
            if sec.name == ".dynstr" && (sec.offset + sec.size) as usize <= self.data.len() {
                dynstr_slice = Some(&self.data[sec.offset as usize..(sec.offset + sec.size) as usize]);
                break;
            }
        }

        let entry_sz = if self.is_64 { 16 } else { 8 };
        let count = dyn_size / entry_sz;
        let mut needed_offsets = Vec::new();
        let mut soname_offset = None;

        for i in 0..count {
            let off = dyn_off + i * entry_sz;
            let (d_tag, d_val) = if self.is_64 {
                (
                    self.read_u64_at_offset(off).unwrap_or(0) as i64,
                    self.read_u64_at_offset(off + 8).unwrap_or(0),
                )
            } else {
                (
                    self.read_u32_at_offset(off).unwrap_or(0) as i32 as i64,
                    self.read_u32_at_offset(off + 4).unwrap_or(0) as u64,
                )
            };
            if d_tag == 0 {
                break;
            } else if d_tag == 1 {
                // DT_NEEDED
                needed_offsets.push(d_val as usize);
            } else if d_tag == 14 {
                // DT_SONAME
                soname_offset = Some(d_val as usize);
            }
        }

        if let Some(dstr) = dynstr_slice {
            for noff in needed_offsets {
                let s = read_cstr(dstr, noff);
                if !s.is_empty() {
                    self.needed_libs.push(s);
                }
            }
            if let Some(soff) = soname_offset {
                let s = read_cstr(dstr, soff);
                if !s.is_empty() {
                    self.soname = Some(s);
                }
            }
        }
    }

    fn parse_init_array(&mut self) {
        let mut init_ranges = Vec::new();
        for sec in &self.sections {
            // SHT_INIT_ARRAY = 14
            if (sec.sh_type == 14 || sec.name == ".init_array") && sec.size > 0 && sec.vaddr > 0 {
                init_ranges.push((sec.vaddr, sec.size));
            }
        }
        let step = if self.is_64 { 8u64 } else { 4u64 };
        for (base_vaddr, size) in init_ranges {
            let count = (size / step).min(512);
            for i in 0..count {
                let slot_vaddr = base_vaddr + i * step;
                if let Some(fn_ptr) = self.read_ptr_at_vaddr(slot_vaddr) {
                    if fn_ptr != 0 && fn_ptr != u64::MAX {
                        self.init_array.push(fn_ptr);
                    }
                }
            }
        }
    }

    fn resolve_plt_stubs(&mut self) {
        if self.machine != 183 {
            return;
        }
        let mut plt_ranges = Vec::new();
        for sec in &self.sections {
            if (sec.name == ".plt" || sec.name == ".plt.sec") && sec.size >= 16 {
                plt_ranges.push((sec.vaddr, sec.offset as usize, sec.size as usize));
            }
        }
        for (base_vaddr, base_off, size) in plt_ranges {
            if base_off + size > self.data.len() {
                continue;
            }
            let mut off = 0usize;
            while off + 16 <= size {
                let pc = base_vaddr + (off as u64);
                let w0 = self.read_u32_at_offset(base_off + off).unwrap_or(0);
                let w1 = self.read_u32_at_offset(base_off + off + 4).unwrap_or(0);
                // Match AArch64 PLT stub: ADRP x16, #page ; LDR x17, [x16, #pimm]
                if (w0 & 0x9F00_001F) == 0x9000_0010 && (w1 & 0xFFC0_03FF) == 0xF940_0211 {
                    let immlo = ((w0 >> 29) & 0x3) as i64;
                    let immhi = (((w0 >> 5) & 0x7FFFF) as i64) << 2;
                    let raw_imm = immhi | immlo;
                    let sign_ext = (raw_imm << 43) >> 43;
                    let page = ((pc & !0xFFF) as i64).wrapping_add(sign_ext << 12) as u64;
                    let ldr_imm12 = (((w1 >> 10) & 0xFFF) as u64) * 8;
                    let got_vaddr = page.wrapping_add(ldr_imm12);
                    if let Some(sym) = self.addr_to_symbol.get(&got_vaddr).cloned() {
                        self.addr_to_symbol.insert(pc, format!("{}@PLT", sym));
                    }
                }
                off += 4;
            }
        }
    }

    // =========================================================================
    // Tool 1: Native Library Recon & Crypto/Protection Fingerprinting
    // =========================================================================
    pub fn build_info_report(&self, lib_path: &str) -> Map<String, Value> {
        let mut out = Map::new();
        out.insert("path".to_string(), Value::String(lib_path.to_string()));
        out.insert("sizeBytes".to_string(), Value::from(self.data.len()));
        out.insert(
            "arch".to_string(),
            Value::String(self.arch_name().to_string()),
        );
        out.insert("bits".to_string(), Value::from(if self.is_64 { 64 } else { 32 }));
        out.insert(
            "entryPoint".to_string(),
            Value::String(format!("0x{:x}", self.entry)),
        );
        if let Some(ref sn) = self.soname {
            out.insert("soname".to_string(), Value::String(sn.clone()));
        }
        out.insert(
            "neededLibraries".to_string(),
            Value::Array(
                self.needed_libs
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );

        let secs: Vec<Value> = self
            .sections
            .iter()
            .filter(|s| !s.name.is_empty() || s.size > 0)
            .map(|s| {
                let mut m = Map::new();
                m.insert("name".to_string(), Value::String(s.name.clone()));
                m.insert("vaddr".to_string(), Value::String(format!("0x{:x}", s.vaddr)));
                m.insert("size".to_string(), Value::from(s.size));
                Value::Object(m)
            })
            .collect();
        out.insert("sections".to_string(), Value::Array(secs));

        let init_addrs: Vec<Value> = self
            .init_array
            .iter()
            .map(|&a| Value::String(format!("0x{:x}", a)))
            .collect();
        out.insert("initArrayConstructors".to_string(), Value::Array(init_addrs));

        let mut jni_onload = Value::Null;
        let mut static_jni = Vec::new();
        let mut other_exports = Vec::new();

        for exp in &self.exports {
            if exp.name == "JNI_OnLoad" {
                jni_onload = Value::String(format!("0x{:x}", exp.vaddr));
            } else if exp.name.starts_with("Java_") {
                let mut m = Map::new();
                m.insert("symbol".to_string(), Value::String(exp.name.clone()));
                m.insert(
                    "vaddr".to_string(),
                    Value::String(format!("0x{:x}", exp.vaddr)),
                );
                m.insert("size".to_string(), Value::from(exp.size));
                static_jni.push(Value::Object(m));
            } else if other_exports.len() < 100 {
                let mut m = Map::new();
                m.insert("symbol".to_string(), Value::String(exp.name.clone()));
                m.insert(
                    "vaddr".to_string(),
                    Value::String(format!("0x{:x}", exp.vaddr)),
                );
                other_exports.push(Value::Object(m));
            }
        }

        out.insert("jniOnLoad".to_string(), jni_onload);
        out.insert("staticJniExports".to_string(), Value::Array(static_jni));
        out.insert("otherExportsSample".to_string(), Value::Array(other_exports));
        out.insert("totalExports".to_string(), Value::from(self.exports.len()));
        out.insert("totalImports".to_string(), Value::from(self.imports.len()));

        // Categorize security-relevant imports
        let mut anti_debug = Vec::new();
        let mut dyn_load = Vec::new();
        let mut file_proc = Vec::new();
        let mut net_ssl = Vec::new();
        let mut crypto_imp = Vec::new();

        for imp in &self.imports {
            let l = imp.to_lowercase();
            if imp == "ptrace"
                || imp == "prctl"
                || imp == "tgkill"
                || imp == "kill"
                || imp == "fork"
                || imp == "inotify_add_watch"
                || imp == "__system_property_get"
            {
                anti_debug.push(Value::String(imp.clone()));
            } else if imp == "dlopen"
                || imp == "dlsym"
                || imp == "dladdr"
                || imp == "android_dlopen_ext"
                || imp == "mmap"
                || imp == "mprotect"
            {
                dyn_load.push(Value::String(imp.clone()));
            } else if imp == "fopen"
                || imp == "open"
                || imp == "openat"
                || imp == "readlink"
                || imp == "readlinkat"
                || imp == "access"
                || imp == "faccessat"
                || imp == "popen"
                || imp == "system"
            {
                file_proc.push(Value::String(imp.clone()));
            } else if imp == "socket"
                || imp == "connect"
                || imp == "sendto"
                || imp == "recvfrom"
                || l.contains("ssl_")
                || l.contains("x509_")
            {
                if net_ssl.len() < 40 {
                    net_ssl.push(Value::String(imp.clone()));
                }
            } else if l.contains("aes")
                || l.contains("evp_")
                || l.contains("hmac")
                || l.contains("sha256")
                || l.contains("sha1")
                || l.contains("md5")
                || l.contains("rsa")
            {
                if crypto_imp.len() < 40 {
                    crypto_imp.push(Value::String(imp.clone()));
                }
            }
        }

        let mut notable = Map::new();
        notable.insert("antiDebugAndProcess".to_string(), Value::Array(anti_debug));
        notable.insert("dynamicLoadingAndMemory".to_string(), Value::Array(dyn_load));
        notable.insert("fileAndSystem".to_string(), Value::Array(file_proc));
        notable.insert("networkAndTls".to_string(), Value::Array(net_ssl));
        notable.insert("cryptoImports".to_string(), Value::Array(crypto_imp));
        out.insert("notableImports".to_string(), Value::Object(notable));

        out.insert(
            "cryptoSignatures".to_string(),
            Value::Array(self.scan_crypto_signatures()),
        );
        out.insert(
            "protectionsAndIndicators".to_string(),
            Value::Array(self.scan_protections()),
        );

        out
    }

    fn scan_crypto_signatures(&self) -> Vec<Value> {
        let patterns: &[(&str, &[u8])] = &[
            (
                "AES Forward S-Box (Rijndael)",
                &[
                    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe,
                    0xd7, 0xab, 0x76,
                ],
            ),
            (
                "AES Inverse S-Box",
                &[
                    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81,
                    0xf3, 0xd7, 0xfb,
                ],
            ),
            (
                "SHA-256 K Constants (0x428a2f98...)",
                &[
                    0x98, 0x2f, 0x8a, 0x42, 0x91, 0x44, 0x37, 0x71, 0xcf, 0xfb, 0xc0, 0xb5, 0xa5,
                    0xdb, 0xb5, 0xe9,
                ],
            ),
            (
                "ChaCha20 / Salsa20 Constant (\"expand 32-byte k\")",
                b"expand 32-byte k",
            ),
            (
                "MD5 / SHA-1 Little-Endian IV (0x67452301, 0xefcdab89)",
                &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98],
            ),
            (
                "Standard Base64 Alphabet",
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            ),
        ];

        let mut hits = Vec::new();
        for &(label, needle) in patterns {
            if let Some(pos) = find_subslice(self.data, needle) {
                let vaddr = self.offset_to_vaddr(pos).unwrap_or(pos as u64);
                let mut m = Map::new();
                m.insert("algorithm".to_string(), Value::String(label.to_string()));
                m.insert(
                    "vaddr".to_string(),
                    Value::String(format!("0x{:x}", vaddr)),
                );
                m.insert(
                    "fileOffset".to_string(),
                    Value::String(format!("0x{:x}", pos)),
                );
                hits.push(Value::Object(m));
            }
        }
        hits
    }

    fn scan_protections(&self) -> Vec<Value> {
        let mut indicators = Vec::new();

        let has_symtab = self.sections.iter().any(|s| s.name == ".symtab");
        if !has_symtab {
            indicators.push(Value::String(
                "Stripped symbol table (.symtab removed)".to_string(),
            ));
        }
        if self.sections.is_empty() {
            indicators.push(Value::String(
                "Section header table stripped/tampered (SHT_NULL / 0 sections)".to_string(),
            ));
        }
        if !self.init_array.is_empty() {
            indicators.push(Value::String(format!(
                "{} .init_array constructor(s) execute on dlopen before JNI_OnLoad",
                self.init_array.len()
            )));
        }

        let probe_needles: &[(&str, &[u8])] = &[
            ("Frida detection string (\"frida\")", b"frida"),
            ("Frida thread detection (\"gum-js-loop\")", b"gum-js-loop"),
            ("Frida thread detection (\"gmain\")", b"gmain"),
            ("Memory map inspection (\"/proc/self/maps\")", b"/proc/self/maps"),
            ("Debugger TracerPid check (\"TracerPid\")", b"TracerPid"),
            ("Root / Magisk check (\"magisk\")", b"magisk"),
            ("Xposed / Zygisk check (\"xposed\")", b"xposed"),
        ];

        for &(desc, needle) in probe_needles {
            if let Some(pos) = find_subslice(self.data, needle) {
                let vaddr = self.offset_to_vaddr(pos).unwrap_or(pos as u64);
                indicators.push(Value::String(format!("{} at 0x{:x}", desc, vaddr)));
            }
        }

        indicators
    }

    // =========================================================================
    // Tool 2: RegisterNatives + Static JNI Resolver
    // =========================================================================
    pub fn resolve_register_natives(
        &self,
        dex_native_map: &HashMap<(String, String), Vec<String>>,
        dex_jni_sym_map: &HashMap<String, (String, String, String)>,
    ) -> Vec<JniRegisteredMethod> {
        let mut results: Vec<JniRegisteredMethod> = Vec::new();
        let mut seen: HashSet<(String, String, u64)> = HashSet::new();

        // 1. Static `Java_...` exports
        for exp in &self.exports {
            if !exp.name.starts_with("Java_") || exp.vaddr == 0 {
                continue;
            }
            let (mname, msig, classes) = if let Some((cls, mn, sig)) =
                dex_jni_sym_map.get(&exp.name)
            {
                (mn.clone(), sig.clone(), vec![cls.clone()])
            } else {
                // Best-effort match without overload suffix
                let base_sym = exp.name.split("__").next().unwrap_or(&exp.name);
                if let Some((cls, mn, sig)) = dex_jni_sym_map.get(base_sym) {
                    (mn.clone(), sig.clone(), vec![cls.clone()])
                } else {
                    (exp.name.clone(), String::new(), Vec::new())
                }
            };
            if seen.insert((mname.clone(), msig.clone(), exp.vaddr)) {
                results.push(JniRegisteredMethod {
                    method_name: mname,
                    signature: msig,
                    fn_vaddr: exp.vaddr,
                    source: "dynsym_export".to_string(),
                    table_vaddr: None,
                    matched_java_classes: classes,
                });
            }
        }

        // 2. Scan data segments / sections for `JNINativeMethod { const char* name, const char* sig, void* fnPtr }`
        let ptr_sz = if self.is_64 { 8u64 } else { 4u64 };
        let struct_sz = ptr_sz * 3;

        let mut scan_ranges: Vec<(u64, u64)> = Vec::new();
        for seg in &self.segments {
            if seg.p_type == 1 && seg.filesz >= struct_sz {
                scan_ranges.push((seg.vaddr, seg.vaddr + seg.filesz));
            }
        }

        for (start_vaddr, end_vaddr) in scan_ranges {
            let mut cur = (start_vaddr + (ptr_sz - 1)) & !(ptr_sz - 1);
            while cur + struct_sz <= end_vaddr {
                if let Some((mname, msig, fn_ptr)) = self.try_read_jni_method_entry(cur) {
                    if seen.insert((mname.clone(), msig.clone(), fn_ptr)) {
                        let classes = dex_native_map
                            .get(&(mname.clone(), msig.clone()))
                            .cloned()
                            .unwrap_or_default();
                        results.push(JniRegisteredMethod {
                            method_name: mname,
                            signature: msig,
                            fn_vaddr: fn_ptr,
                            source: "JNINativeMethod_table".to_string(),
                            table_vaddr: Some(cur),
                            matched_java_classes: classes,
                        });
                    }
                    cur += struct_sz;
                } else {
                    cur += ptr_sz;
                }
            }
        }

        // 3. AArch64 `ADR` / `ADRP + ADD` / `ADRP + LDR` dynamic triplet & stack RegisterNatives scanner in executable segments
        if self.machine == 183 {
            let mut rodata_jni_sigs: Vec<String> = Vec::new();
            for seg in &self.segments {
                if seg.p_type != 1 || (seg.flags & 1) == 0 {
                    continue;
                }
                let start_off = seg.offset as usize;
                let end_off = ((seg.offset + seg.filesz) as usize).min(self.data.len());
                if start_off + 16 > end_off {
                    continue;
                }
                let mut reg_pages: [u64; 32] = [0; 32];
                let mut window: Vec<(u64, u64)> = Vec::new(); // (insn_pc, target_vaddr)

                let mut off = start_off;
                while off + 4 <= end_off {
                    let pc = seg.vaddr + ((off - start_off) as u64);
                    let insn = self.read_u32_at_offset(off).unwrap_or(0);
                    let mut newly_resolved: Option<u64> = None;

                    if (insn & 0x1F00_0000) == 0x1000_0000 {
                        let is_adrp = (insn >> 31) != 0;
                        let rd = (insn & 0x1F) as usize;
                        let immlo = ((insn >> 29) & 0x3) as i64;
                        let immhi = (((insn >> 5) & 0x7FFFF) as i64) << 2;
                        let raw_imm = immhi | immlo;
                        let sign_ext = (raw_imm << 43) >> 43;
                        if is_adrp {
                            let page = ((pc & !0xFFF) as i64).wrapping_add(sign_ext << 12) as u64;
                            if rd < 31 {
                                reg_pages[rd] = page;
                            }
                        } else {
                            let target = (pc as i64).wrapping_add(sign_ext) as u64;
                            if rd < 31 {
                                reg_pages[rd] = 0;
                            }
                            newly_resolved = Some(target);
                        }
                    } else if (insn & 0xFF80_0000) == 0x9100_0000 {
                        let rd = (insn & 0x1F) as usize;
                        let rn = ((insn >> 5) & 0x1F) as usize;
                        let imm12 = ((insn >> 10) & 0xFFF) as u64;
                        let sh = (insn >> 22) & 1;
                        let addend = if sh == 1 { imm12 << 12 } else { imm12 };
                        if rn < 31 && reg_pages[rn] != 0 {
                            let target = reg_pages[rn].wrapping_add(addend);
                            if rd == rn {
                                reg_pages[rd] = 0;
                            }
                            newly_resolved = Some(target);
                        }
                    } else if (insn & 0xFFC0_0000) == 0xF940_0000 {
                        // 64-bit LDR unsigned immediate (often GOT load or JNINativeInterface dispatch)
                        let rt = (insn & 0x1F) as usize;
                        let rn = ((insn >> 5) & 0x1F) as usize;
                        let imm12 = (((insn >> 10) & 0xFFF) as u64) * 8;
                        if rn < 31 && reg_pages[rn] != 0 {
                            let got_addr = reg_pages[rn].wrapping_add(imm12);
                            if rt == rn {
                                reg_pages[rt] = 0;
                            }
                            if let Some(ptr) = self.read_ptr_at_vaddr(got_addr) {
                                if ptr != 0 {
                                    newly_resolved = Some(ptr);
                                }
                            }
                        } else if imm12 == 0x6b8 {
                            // (*env)->RegisterNatives at offset 0x6b8 (215 * 8) in 64-bit JNINativeInterface!
                            let mut has_blr = false;
                            for lookahead in 1..=6 {
                                if let Some(w_next) = self.read_u32_at_offset(off + lookahead * 4) {
                                    if (w_next & 0xFFFF_FC1F) == 0xD63F_0000 {
                                        has_blr = true;
                                        break;
                                    }
                                }
                            }
                            if has_blr {
                                if let Some(&(_, fn_ptr)) = window
                                    .iter()
                                    .rev()
                                    .find(|&&(_, cand)| self.is_executable_vaddr(cand))
                                {
                                    let (mname, msig, classes) = if let Some(sig) = rodata_jni_sigs.first() {
                                        let matched = dex_native_map
                                            .iter()
                                            .find(|((_, s), _)| s == sig)
                                            .map(|((n, s), cls)| (n.clone(), s.clone(), cls.clone()));
                                        matched.unwrap_or_else(|| {
                                            ("<encrypted_jni_name>".to_string(), sig.clone(), Vec::new())
                                        })
                                    } else {
                                        (
                                            "<stack_registered_native>".to_string(),
                                            String::new(),
                                            Vec::new(),
                                        )
                                    };
                                    if seen.insert((mname.clone(), msig.clone(), fn_ptr)) {
                                        results.push(JniRegisteredMethod {
                                            method_name: mname,
                                            signature: msig,
                                            fn_vaddr: fn_ptr,
                                            source: "arm64_stack_registernatives".to_string(),
                                            table_vaddr: Some(pc),
                                            matched_java_classes: classes,
                                        });
                                    }
                                }
                            }
                        }
                    }

                    if let Some(target) = newly_resolved {
                        window.push((pc, target));
                        if window.len() > 12 {
                            window.remove(0);
                        }
                        if let Some(sig_str) = self.read_cstr_at_vaddr(target, 256) {
                            if is_valid_jni_signature(&sig_str) {
                                if !rodata_jni_sigs.contains(&sig_str) {
                                    rodata_jni_sigs.push(sig_str.clone());
                                }
                                let mut found_name = None;
                                let mut found_fn = None;
                                for &(_, cand_vaddr) in &window {
                                    if cand_vaddr == target {
                                        continue;
                                    }
                                    if self.is_executable_vaddr(cand_vaddr) {
                                        found_fn = Some(cand_vaddr);
                                    } else if let Some(s) =
                                        self.read_cstr_at_vaddr(cand_vaddr, 128)
                                    {
                                        if is_valid_java_method_identifier(&s) {
                                            found_name = Some(s);
                                        }
                                    }
                                }
                                if let (Some(mname), Some(fn_ptr)) = (found_name, found_fn) {
                                    if seen.insert((mname.clone(), sig_str.clone(), fn_ptr)) {
                                        let classes = dex_native_map
                                            .get(&(mname.clone(), sig_str.clone()))
                                            .cloned()
                                            .unwrap_or_default();
                                        results.push(JniRegisteredMethod {
                                            method_name: mname,
                                            signature: sig_str,
                                            fn_vaddr: fn_ptr,
                                            source: "arm64_code_triplet".to_string(),
                                            table_vaddr: Some(pc),
                                            matched_java_classes: classes,
                                        });
                                    }
                                }
                            }
                        }
                    }
                    off += 4;
                }
            }
        }

        results
    }

    fn try_read_jni_method_entry(&self, vaddr: u64) -> Option<(String, String, u64)> {
        let ptr_sz = if self.is_64 { 8u64 } else { 4u64 };
        let name_ptr = self.read_ptr_at_vaddr(vaddr)?;
        let sig_ptr = self.read_ptr_at_vaddr(vaddr + ptr_sz)?;
        let fn_ptr_raw = self.read_ptr_at_vaddr(vaddr + ptr_sz * 2)?;

        if name_ptr == 0 || sig_ptr == 0 || fn_ptr_raw == 0 {
            return None;
        }
        let fn_ptr = if self.machine == 40 {
            fn_ptr_raw & !1
        } else {
            fn_ptr_raw
        };
        if !self.is_executable_vaddr(fn_ptr) {
            return None;
        }
        let sig = self.read_cstr_at_vaddr(sig_ptr, 512)?;
        if !is_valid_jni_signature(&sig) {
            return None;
        }
        let name = self.read_cstr_at_vaddr(name_ptr, 256)?;
        if !is_valid_java_method_identifier(&name) {
            return None;
        }
        Some((name, sig, fn_ptr))
    }

    // =========================================================================
    // Tool 3: Native Strings + ARM64 Code Xrefs
    // =========================================================================
    pub fn search_strings_with_xrefs(
        &self,
        query: Option<&str>,
        limit: usize,
    ) -> Vec<Map<String, Value>> {
        let needle = query
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty());

        // 1. Collect matching strings with their virtual addresses
        let mut matches: Vec<(u64, String)> = Vec::new();
        let mut i = 0usize;
        while i < self.data.len() {
            if is_printable_ascii(self.data[i]) {
                let start = i;
                while i < self.data.len() && is_printable_ascii(self.data[i]) {
                    i += 1;
                }
                let len = i - start;
                if len >= 4 && i < self.data.len() && self.data[i] == 0 {
                    if let Ok(s) = std::str::from_utf8(&self.data[start..i]) {
                        let keep = match &needle {
                            Some(q) => s.to_lowercase().contains(q),
                            None => len >= 6,
                        };
                        if keep {
                            let vaddr = self.offset_to_vaddr(start).unwrap_or(start as u64);
                            matches.push((vaddr, s.to_string()));
                            if limit > 0 && matches.len() >= limit {
                                break;
                            }
                        }
                    }
                }
            }
            i += 1;
        }

        if matches.is_empty() {
            return Vec::new();
        }

        // 2. Build ARM64 ADRP+ADD Xrefs to the matched string addresses
        let target_vaddrs: HashSet<u64> = matches.iter().map(|&(v, _)| v).collect();
        let mut xrefs_map: HashMap<u64, Vec<u64>> = HashMap::new();

        if self.machine == 183 {
            for seg in &self.segments {
                if seg.p_type != 1 || (seg.flags & 1) == 0 {
                    continue;
                }
                let start_off = seg.offset as usize;
                let end_off = ((seg.offset + seg.filesz) as usize).min(self.data.len());
                let mut reg_pages: [u64; 32] = [0; 32];
                let mut off = start_off;
                while off + 4 <= end_off {
                    let pc = seg.vaddr + ((off - start_off) as u64);
                    let insn = self.read_u32_at_offset(off).unwrap_or(0);
                    if (insn & 0x9F00_0000) == 0x9000_0000 {
                        let rd = (insn & 0x1F) as usize;
                        let immlo = ((insn >> 29) & 0x3) as i64;
                        let immhi = (((insn >> 5) & 0x7FFFF) as i64) << 2;
                        let raw_imm = immhi | immlo;
                        let sign_ext = (raw_imm << 43) >> 43;
                        let page = ((pc & !0xFFF) as i64).wrapping_add(sign_ext << 12) as u64;
                        if rd < 31 {
                            reg_pages[rd] = page;
                        }
                    } else if (insn & 0xFF80_0000) == 0x9100_0000 {
                        let rd = (insn & 0x1F) as usize;
                        let rn = ((insn >> 5) & 0x1F) as usize;
                        let imm12 = ((insn >> 10) & 0xFFF) as u64;
                        let sh = (insn >> 22) & 1;
                        let addend = if sh == 1 { imm12 << 12 } else { imm12 };
                        if rn < 31 && reg_pages[rn] != 0 {
                            let target = reg_pages[rn].wrapping_add(addend);
                            if target_vaddrs.contains(&target) {
                                let list = xrefs_map.entry(target).or_default();
                                if list.len() < 16 {
                                    list.push(pc);
                                }
                            }
                            if rd == rn {
                                reg_pages[rd] = 0;
                            }
                        }
                    }
                    off += 4;
                }
            }
        }

        matches
            .into_iter()
            .map(|(vaddr, s)| {
                let mut m = Map::new();
                m.insert(
                    "vaddr".to_string(),
                    Value::String(format!("0x{:x}", vaddr)),
                );
                m.insert("value".to_string(), Value::String(s));
                let xrefs = xrefs_map
                    .remove(&vaddr)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|x| Value::String(format!("0x{:x}", x)))
                    .collect();
                m.insert("codeXrefs".to_string(), Value::Array(xrefs));
                m
            })
            .collect()
    }

    // =========================================================================
    // Tool 4: AArch64 (ARM64) Disassembler with String & Symbol Resolution
    // =========================================================================
    pub fn disassemble_arm64(
        &self,
        target: &str,
        insn_count: usize,
    ) -> Result<Map<String, Value>, String> {
        let trimmed = target.trim();
        let start_vaddr = if let Some(hex) = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
        {
            u64::from_str_radix(hex, 16)
                .map_err(|_| format!("Invalid hex virtual address: {}", trimmed))?
        } else if let Some(&sym_addr) = self.symbol_to_addr.get(trimmed) {
            sym_addr
        } else if let Ok(addr) = u64::from_str_radix(trimmed, 16) {
            addr
        } else {
            return Err(format!(
                "Symbol or hex address not found in ELF: {}",
                trimmed
            ));
        };

        let Some(start_off) = self.vaddr_to_offset(start_vaddr) else {
            return Err(format!(
                "Virtual address 0x{:x} is not mapped in any ELF file segment",
                start_vaddr
            ));
        };

        let count = insn_count.clamp(1, 500);
        let mut lines = Vec::with_capacity(count);
        let mut reg_pages: [u64; 32] = [0; 32];
        let mut lr_tramp_regs: [u64; 32] = [0; 32];

        for i in 0..count {
            let off = start_off + i * 4;
            if off + 4 > self.data.len() {
                break;
            }
            let pc = start_vaddr + (i as u64) * 4;
            let word = self.read_u32_at_offset(off).unwrap_or(0);
            let (mnemonic, mut comment) = self.decode_one_arm64(pc, word, &mut reg_pages);

            // Track LR-based anti-disassembly trampolines:
            //   bl <get_pc_leaf>  => x0 = pc + 4
            //   mov xN, x0        => xN = x0
            //   add xM, xN, #imm  => xM = xN + imm
            //   br xM             => jumps to (bl_pc + 4 + imm)
            if (word & 0xFC00_0000) == 0x9400_0000 {
                let imm26 = (word & 0x03FF_FFFF) as i64;
                let sign_ext = (imm26 << 38) >> 38;
                let callee = (pc as i64).wrapping_add(sign_ext * 4) as u64;
                if self.is_get_pc_leaf(callee) {
                    lr_tramp_regs[0] = pc + 4;
                    comment = Some(format!("get_pc leaf -> x0 = 0x{:x}", pc + 4));
                } else {
                    lr_tramp_regs[0] = 0;
                }
            } else if (word & 0xFFE0_FFE0) == 0xAA00_03E0 {
                let rd = (word & 0x1F) as usize;
                let rm = ((word >> 16) & 0x1F) as usize;
                if rd < 31 && rm < 31 {
                    lr_tramp_regs[rd] = lr_tramp_regs[rm];
                }
            } else if (word & 0xFF80_0000) == 0x9100_0000 {
                let rd = (word & 0x1F) as usize;
                let rn = ((word >> 5) & 0x1F) as usize;
                let imm12 = ((word >> 10) & 0xFFF) as u64;
                let sh = (word >> 22) & 1;
                let addend = if sh == 1 { imm12 << 12 } else { imm12 };
                if rd < 31 && rn < 31 && lr_tramp_regs[rn] != 0 {
                    lr_tramp_regs[rd] = lr_tramp_regs[rn].wrapping_add(addend);
                }
            } else if (word & 0xFFFF_FC1F) == 0xD61F_0000 {
                let rn = ((word >> 5) & 0x1F) as usize;
                if rn < 31 && lr_tramp_regs[rn] != 0 {
                    let target = lr_tramp_regs[rn];
                    let skipped = target.saturating_sub(pc + 4);
                    comment = Some(format!(
                        "anti-disasm trampoline -> 0x{:x} (skips 0x{:x} bytes)",
                        target, skipped
                    ));
                }
            }

            let line = match comment {
                Some(c) => format!(
                    "0x{:08x}:  {:08x}    {:<34} ; {}",
                    pc, word, mnemonic, c
                ),
                None => format!("0x{:08x}:  {:08x}    {}", pc, word, mnemonic),
            };
            lines.push(line);
        }

        let mut out = Map::new();
        out.insert(
            "startVaddr".to_string(),
            Value::String(format!("0x{:x}", start_vaddr)),
        );
        if let Some(sym) = self.addr_to_symbol.get(&start_vaddr) {
            out.insert("symbol".to_string(), Value::String(sym.clone()));
        }
        out.insert("instructionCount".to_string(), Value::from(lines.len()));
        out.insert("disassembly".to_string(), Value::String(lines.join("\n")));
        Ok(out)
    }

    // =========================================================================
    // Tool 5: AArch64 Function CFG, XREF, JNI Vtable & Anti-Obfuscation Analyzer
    // =========================================================================
    pub fn analyze_function_arm64(
        &self,
        target: &str,
        max_insns: usize,
    ) -> Result<Map<String, Value>, String> {
        let trimmed = target.trim();
        let start_vaddr = if let Some(hex) = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
        {
            u64::from_str_radix(hex, 16)
                .map_err(|_| format!("Invalid hex virtual address: {}", trimmed))?
        } else if let Some(&sym_addr) = self.symbol_to_addr.get(trimmed) {
            sym_addr
        } else if let Ok(addr) = u64::from_str_radix(trimmed, 16) {
            addr
        } else {
            return Err(format!(
                "Symbol or hex address not found in ELF: {}",
                trimmed
            ));
        };

        if self.vaddr_to_offset(start_vaddr).is_none() {
            return Err(format!(
                "Virtual address 0x{:x} is not mapped in any ELF file segment",
                start_vaddr
            ));
        }

        // 1. Scan incoming XREFs (code BL/B/ADRP+ADD/ADR and data pointers)
        let incoming_xrefs = self.find_incoming_xrefs(start_vaddr, 32);

        // 2. Worklist-based CFG traversal that automatically jumps across LR trampolines
        let budget = max_insns.clamp(16, 1024);
        let mut visited_pcs: HashSet<u64> = HashSet::new();
        let mut block_queue: Vec<u64> = vec![start_vaddr];
        let mut queued_blocks: HashSet<u64> = HashSet::from([start_vaddr]);

        let mut basic_blocks: Vec<Map<String, Value>> = Vec::new();
        let mut outgoing_calls: Vec<Map<String, Value>> = Vec::new();
        let mut seen_calls: HashSet<u64> = HashSet::new();
        let mut jni_calls: Vec<Map<String, Value>> = Vec::new();
        let mut string_refs: Vec<Map<String, Value>> = Vec::new();
        let mut seen_strings: HashSet<u64> = HashSet::new();
        let mut global_refs: Vec<Map<String, Value>> = Vec::new();
        let mut seen_globals: HashSet<u64> = HashSet::new();

        let mut trampolines: Vec<Map<String, Value>> = Vec::new();
        let mut anti_emu_traps: Vec<Map<String, Value>> = Vec::new();
        let mut integrity_constants: Vec<String> = Vec::new();
        let mut has_sdiv_msub_xor = (false, false, false);

        while let Some(block_start) = block_queue.pop() {
            if visited_pcs.len() >= budget || basic_blocks.len() >= 64 {
                break;
            }
            let Some(mut off) = self.vaddr_to_offset(block_start) else {
                continue;
            };
            let mut pc = block_start;
            let mut insn_count_in_block = 0usize;
            let mut successors: Vec<u64> = Vec::new();
            let mut terminator = "fallthrough".to_string();
            let mut reg_pages: [u64; 32] = [0; 32];
            let mut lr_tramp_regs: [u64; 32] = [0; 32];
            let mut mov_imm_regs: [u64; 32] = [0; 32];
            let mut pending_jni_reg: [Option<(u64, &'static str)>; 32] = [None; 32];

            while off + 4 <= self.data.len() && visited_pcs.len() < budget {
                if insn_count_in_block > 0 && visited_pcs.contains(&pc) {
                    successors.push(pc);
                    terminator = format!("fallthrough -> 0x{:x}", pc);
                    break;
                }
                visited_pcs.insert(pc);
                insn_count_in_block += 1;

                let w = self.read_u32_at_offset(off).unwrap_or(0);
                let (mnem, _) = self.decode_one_arm64(pc, w, &mut reg_pages);

                // Track MOVZ/MOVK 32-bit constants (for self-integrity checksum seeds/hashes)
                if (w & 0x1F80_0000) == 0x1280_0000 {
                    let opc = (w >> 29) & 0x3;
                    let hw = ((w >> 21) & 0x3) * 16;
                    let imm16 = ((w >> 5) & 0xFFFF) as u64;
                    let rd = (w & 0x1F) as usize;
                    if rd < 31 {
                        if opc == 2 {
                            mov_imm_regs[rd] = imm16 << hw;
                        } else if opc == 3 {
                            mov_imm_regs[rd] = (mov_imm_regs[rd] & !(0xFFFFu64 << hw)) | (imm16 << hw);
                            if mov_imm_regs[rd] > 0xFFFF_FFFF
                                || (hw == 16 && (mov_imm_regs[rd] & 0xFFFF_0000) != 0)
                            {
                                let hex_c = format!("0x{:08x}", mov_imm_regs[rd]);
                                if !integrity_constants.contains(&hex_c) {
                                    integrity_constants.push(hex_c);
                                }
                            }
                        }
                    }
                }

                // Track stack string decryption pattern (SDIV + MSUB + EOR)
                if (w & 0x7FE0_FC00) == 0x1AC0_0C00 {
                    has_sdiv_msub_xor.0 = true;
                } else if (w & 0x7FE0_8000) == 0x1B00_8000 {
                    has_sdiv_msub_xor.1 = true;
                } else if (w & 0x7F00_0000) == 0x4A00_0000 {
                    has_sdiv_msub_xor.2 = true;
                }

                // Track anti-emulator traps (MSR NZCV / BRK)
                if (w & 0xFFFF_FFE0) == 0xD51B_4200 {
                    let mut trap = Map::new();
                    trap.insert("vaddr".to_string(), Value::String(format!("0x{:x}", pc)));
                    trap.insert("kind".to_string(), Value::String("nzcv_flag_overwrite".to_string()));
                    trap.insert("instruction".to_string(), Value::String(mnem.clone()));
                    anti_emu_traps.push(trap);
                } else if (w & 0xFFE0_001F) == 0xD420_0000 {
                    let mut trap = Map::new();
                    trap.insert("vaddr".to_string(), Value::String(format!("0x{:x}", pc)));
                    trap.insert("kind".to_string(), Value::String("software_breakpoint_trap".to_string()));
                    trap.insert("instruction".to_string(), Value::String(mnem.clone()));
                    anti_emu_traps.push(trap);
                }

                // Track ADRP + ADD (strings / globals) and ADRP + LDR/STR (globals) and JNIEnv vtable loads
                if (w & 0xFF80_0000) == 0x9100_0000 {
                    let rd = (w & 0x1F) as usize;
                    let rn = ((w >> 5) & 0x1F) as usize;
                    let imm12 = ((w >> 10) & 0xFFF) as u64;
                    let sh = (w >> 22) & 1;
                    let addend = if sh == 1 { imm12 << 12 } else { imm12 };
                    if rd < 31 && rn < 31 && lr_tramp_regs[rn] != 0 {
                        lr_tramp_regs[rd] = lr_tramp_regs[rn].wrapping_add(addend);
                    } else if rn < 31 && reg_pages[rn] != 0 {
                        let target_addr = reg_pages[rn].wrapping_add(addend);
                        if let Some(s) = self.read_cstr_at_vaddr(target_addr, 128) {
                            if s.len() >= 2 && seen_strings.insert(target_addr) {
                                let mut sm = Map::new();
                                sm.insert("atVaddr".to_string(), Value::String(format!("0x{:x}", pc)));
                                sm.insert("stringVaddr".to_string(), Value::String(format!("0x{:x}", target_addr)));
                                sm.insert("value".to_string(), Value::String(s));
                                string_refs.push(sm);
                            }
                        } else if seen_globals.insert(target_addr) {
                            let mut gm = Map::new();
                            gm.insert("atVaddr".to_string(), Value::String(format!("0x{:x}", pc)));
                            gm.insert("targetVaddr".to_string(), Value::String(format!("0x{:x}", target_addr)));
                            gm.insert("access".to_string(), Value::String("address".to_string()));
                            global_refs.push(gm);
                        }
                    }
                } else if (w & 0xFFE0_FFE0) == 0xAA00_03E0 {
                    let rd = (w & 0x1F) as usize;
                    let rm = ((w >> 16) & 0x1F) as usize;
                    if rd < 31 && rm < 31 {
                        lr_tramp_regs[rd] = lr_tramp_regs[rm];
                    }
                } else if (w & 0x3B00_0000) == 0x3900_0000 {
                    let size = (w >> 30) & 0x3;
                    let opc = (w >> 22) & 0x3;
                    let imm12 = ((w >> 10) & 0xFFF) as u64;
                    let rn = ((w >> 5) & 0x1F) as usize;
                    let rt = (w & 0x1F) as usize;
                    let offset = imm12 << size;
                    if rn < 31 && reg_pages[rn] != 0 {
                        let target_addr = reg_pages[rn].wrapping_add(offset);
                        if seen_globals.insert(target_addr) {
                            let mut gm = Map::new();
                            gm.insert("atVaddr".to_string(), Value::String(format!("0x{:x}", pc)));
                            gm.insert("targetVaddr".to_string(), Value::String(format!("0x{:x}", target_addr)));
                            gm.insert(
                                "access".to_string(),
                                Value::String(if opc == 0 { "store" } else { "load" }.to_string()),
                            );
                            global_refs.push(gm);
                        }
                        if rt < 31 {
                            pending_jni_reg[rt] = None;
                        }
                    } else if size == 3 && opc == 1 && rt < 31 {
                        pending_jni_reg[rt] = jni_vtable_method_name(offset).map(|name| (offset, name));
                    }
                }

                // Control flow instructions
                // 1. RET
                if (w & 0xFFFF_FC1F) == 0xD65F_0000 {
                    terminator = mnem;
                    break;
                }
                // 2. BR xN (including LR-based anti-disassembly trampolines)
                if (w & 0xFFFF_FC1F) == 0xD61F_0000 {
                    let rn = ((w >> 5) & 0x1F) as usize;
                    if rn < 31 && lr_tramp_regs[rn] != 0 {
                        let target_pc = lr_tramp_regs[rn];
                        let skipped = target_pc.saturating_sub(pc + 4);
                        let mut tm = Map::new();
                        tm.insert("fromVaddr".to_string(), Value::String(format!("0x{:x}", pc)));
                        tm.insert("toVaddr".to_string(), Value::String(format!("0x{:x}", target_pc)));
                        tm.insert("skippedBytes".to_string(), Value::from(skipped));
                        trampolines.push(tm);

                        successors.push(target_pc);
                        if queued_blocks.insert(target_pc) {
                            block_queue.push(target_pc);
                        }
                        terminator = format!("br x{} (trampoline -> 0x{:x})", rn, target_pc);
                    } else {
                        terminator = mnem;
                    }
                    break;
                }
                // 3. BLR xN (indirect call, check JNIEnv vtable)
                if (w & 0xFFFF_FC1F) == 0xD63F_0000 {
                    let rn = ((w >> 5) & 0x1F) as usize;
                    if rn < 31 {
                        if let Some((voff, jni_name)) = pending_jni_reg[rn] {
                            let mut jm = Map::new();
                            jm.insert("callSite".to_string(), Value::String(format!("0x{:x}", pc)));
                            jm.insert("vtableOffset".to_string(), Value::String(format!("0x{:x}", voff)));
                            jm.insert("jniMethod".to_string(), Value::String(jni_name.to_string()));
                            jni_calls.push(jm);
                        }
                    }
                }
                // 4. B / BL
                if (w & 0x7C00_0000) == 0x1400_0000 {
                    let is_bl = (w >> 31) != 0;
                    let imm26 = (w & 0x03FF_FFFF) as i64;
                    let sign_ext = (imm26 << 38) >> 38;
                    let target_pc = (pc as i64).wrapping_add(sign_ext * 4) as u64;
                    if is_bl {
                        if self.is_get_pc_leaf(target_pc) {
                            lr_tramp_regs[0] = pc + 4;
                        } else {
                            lr_tramp_regs[0] = 0;
                            if seen_calls.insert(target_pc) {
                                let mut cm = Map::new();
                                cm.insert("callSite".to_string(), Value::String(format!("0x{:x}", pc)));
                                cm.insert("targetVaddr".to_string(), Value::String(format!("0x{:x}", target_pc)));
                                if let Some(sym) = self.addr_to_symbol.get(&target_pc) {
                                    cm.insert("symbol".to_string(), Value::String(sym.clone()));
                                }
                                outgoing_calls.push(cm);
                            }
                        }
                    } else {
                        successors.push(target_pc);
                        if queued_blocks.insert(target_pc) {
                            block_queue.push(target_pc);
                        }
                        terminator = mnem;
                        break;
                    }
                }
                // 5. Conditional branches: B.cond, CBZ/CBNZ, TBZ/TBNZ
                if (w & 0xFF00_0010) == 0x5400_0000 || (w & 0x7E00_0000) == 0x3400_0000 {
                    let imm19 = ((w >> 5) & 0x7FFFF) as i64;
                    let sign_ext = (imm19 << 45) >> 45;
                    let target_pc = (pc as i64).wrapping_add(sign_ext * 4) as u64;
                    let fallthrough_pc = pc + 4;
                    successors.push(target_pc);
                    successors.push(fallthrough_pc);
                    if queued_blocks.insert(fallthrough_pc) {
                        block_queue.push(fallthrough_pc);
                    }
                    if queued_blocks.insert(target_pc) {
                        block_queue.push(target_pc);
                    }
                    terminator = mnem;
                    break;
                }
                if (w & 0x7E00_0000) == 0x3600_0000 {
                    let imm14 = ((w >> 5) & 0x3FFF) as i64;
                    let sign_ext = (imm14 << 50) >> 50;
                    let target_pc = (pc as i64).wrapping_add(sign_ext * 4) as u64;
                    let fallthrough_pc = pc + 4;
                    successors.push(target_pc);
                    successors.push(fallthrough_pc);
                    if queued_blocks.insert(fallthrough_pc) {
                        block_queue.push(fallthrough_pc);
                    }
                    if queued_blocks.insert(target_pc) {
                        block_queue.push(target_pc);
                    }
                    terminator = mnem;
                    break;
                }

                off += 4;
                pc += 4;
            }

            let mut bm = Map::new();
            bm.insert(
                "startVaddr".to_string(),
                Value::String(format!("0x{:x}", block_start)),
            );
            bm.insert(
                "endVaddr".to_string(),
                Value::String(format!(
                    "0x{:x}",
                    block_start + (insn_count_in_block.saturating_sub(1) as u64) * 4
                )),
            );
            bm.insert(
                "instructionCount".to_string(),
                Value::from(insn_count_in_block),
            );
            bm.insert("terminator".to_string(), Value::String(terminator));
            bm.insert(
                "successors".to_string(),
                Value::Array(
                    successors
                        .into_iter()
                        .map(|s| Value::String(format!("0x{:x}", s)))
                        .collect(),
                ),
            );
            basic_blocks.push(bm);
        }

        basic_blocks.sort_by_key(|b| {
            b.get("startVaddr")
                .and_then(|v| v.as_str())
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .unwrap_or(0)
        });

        let mut protection = Map::new();
        protection.insert(
            "antiDisasmTrampolines".to_string(),
            Value::Array(trampolines.into_iter().map(Value::Object).collect()),
        );
        protection.insert(
            "antiEmulatorTraps".to_string(),
            Value::Array(anti_emu_traps.into_iter().map(Value::Object).collect()),
        );
        protection.insert(
            "integrityAndHashConstants".to_string(),
            Value::Array(integrity_constants.into_iter().map(Value::String).collect()),
        );
        protection.insert(
            "stackModuloXorDecryption".to_string(),
            Value::Bool(has_sdiv_msub_xor.0 && has_sdiv_msub_xor.1 && has_sdiv_msub_xor.2),
        );

        let mut out = Map::new();
        out.insert(
            "startVaddr".to_string(),
            Value::String(format!("0x{:x}", start_vaddr)),
        );
        if let Some(sym) = self.addr_to_symbol.get(&start_vaddr) {
            out.insert("symbol".to_string(), Value::String(sym.clone()));
        }
        out.insert(
            "reachableInstructions".to_string(),
            Value::from(visited_pcs.len()),
        );
        out.insert(
            "incomingXrefs".to_string(),
            Value::Array(incoming_xrefs.into_iter().map(Value::Object).collect()),
        );
        out.insert(
            "basicBlocks".to_string(),
            Value::Array(basic_blocks.into_iter().map(Value::Object).collect()),
        );
        out.insert(
            "outgoingCalls".to_string(),
            Value::Array(outgoing_calls.into_iter().map(Value::Object).collect()),
        );
        out.insert(
            "jniApiCalls".to_string(),
            Value::Array(jni_calls.into_iter().map(Value::Object).collect()),
        );
        out.insert(
            "stringRefs".to_string(),
            Value::Array(string_refs.into_iter().map(Value::Object).collect()),
        );
        out.insert(
            "globalDataRefs".to_string(),
            Value::Array(global_refs.into_iter().map(Value::Object).collect()),
        );
        out.insert("protectionSummary".to_string(), Value::Object(protection));
        Ok(out)
    }

    fn is_get_pc_leaf(&self, vaddr: u64) -> bool {
        let Some(off) = self.vaddr_to_offset(vaddr) else {
            return false;
        };
        if off + 24 > self.data.len() {
            return false;
        }
        // Pattern:
        //   sub sp, sp, #0x10      (0xd10043ff)
        //   stp x29, x30, [sp]     (0xa9007bfd)
        //   ldr x0, [sp, #0x8]     (0xf94007e0)
        //   ldp x29, x30, [sp]     (0xa9407bfd)
        //   add sp, sp, #0x10      (0x910043ff)
        //   ret                    (0xd65f03c0)
        let w0 = self.read_u32_at_offset(off).unwrap_or(0);
        let w1 = self.read_u32_at_offset(off + 4).unwrap_or(0);
        let w2 = self.read_u32_at_offset(off + 8).unwrap_or(0);
        let w5 = self.read_u32_at_offset(off + 20).unwrap_or(0);
        w0 == 0xD100_43FF && w1 == 0xA900_7BFD && w2 == 0xF940_07E0 && w5 == 0xD65F_03C0
    }

    fn find_incoming_xrefs(&self, target_vaddr: u64, limit: usize) -> Vec<Map<String, Value>> {
        let mut xrefs = Vec::new();
        if self.machine != 183 {
            return xrefs;
        }
        for seg in &self.segments {
            if seg.p_type != 1 {
                continue;
            }
            let start_off = seg.offset as usize;
            let end_off = ((seg.offset + seg.filesz) as usize).min(self.data.len());
            if (seg.flags & 1) != 0 {
                let mut reg_pages: [u64; 32] = [0; 32];
                let mut off = start_off;
                while off + 4 <= end_off {
                    let pc = seg.vaddr + ((off - start_off) as u64);
                    let w = self.read_u32_at_offset(off).unwrap_or(0);
                    // B / BL
                    if (w & 0x7C00_0000) == 0x1400_0000 {
                        let is_bl = (w >> 31) != 0;
                        let imm26 = (w & 0x03FF_FFFF) as i64;
                        let sign_ext = (imm26 << 38) >> 38;
                        let dest = (pc as i64).wrapping_add(sign_ext * 4) as u64;
                        if dest == target_vaddr {
                            let mut xm = Map::new();
                            xm.insert("fromVaddr".to_string(), Value::String(format!("0x{:x}", pc)));
                            xm.insert(
                                "type".to_string(),
                                Value::String(if is_bl { "call (bl)" } else { "jump (b)" }.to_string()),
                            );
                            xrefs.push(xm);
                            if xrefs.len() >= limit {
                                return xrefs;
                            }
                        }
                    } else if (w & 0x1F00_0000) == 0x1000_0000 {
                        let is_adrp = (w >> 31) != 0;
                        let rd = (w & 0x1F) as usize;
                        let immlo = ((w >> 29) & 0x3) as i64;
                        let immhi = (((w >> 5) & 0x7FFFF) as i64) << 2;
                        let raw_imm = immhi | immlo;
                        let sign_ext = (raw_imm << 43) >> 43;
                        let dest = if is_adrp {
                            ((pc & !0xFFF) as i64).wrapping_add(sign_ext << 12) as u64
                        } else {
                            (pc as i64).wrapping_add(sign_ext) as u64
                        };
                        if !is_adrp && dest == target_vaddr {
                            let mut xm = Map::new();
                            xm.insert("fromVaddr".to_string(), Value::String(format!("0x{:x}", pc)));
                            xm.insert("type".to_string(), Value::String("adr".to_string()));
                            xrefs.push(xm);
                            if xrefs.len() >= limit {
                                return xrefs;
                            }
                        }
                        if rd < 31 {
                            reg_pages[rd] = if is_adrp { dest } else { 0 };
                        }
                    } else if (w & 0xFF80_0000) == 0x9100_0000 {
                        let rd = (w & 0x1F) as usize;
                        let rn = ((w >> 5) & 0x1F) as usize;
                        let imm12 = ((w >> 10) & 0xFFF) as u64;
                        let sh = (w >> 22) & 1;
                        let addend = if sh == 1 { imm12 << 12 } else { imm12 };
                        if rn < 31 && reg_pages[rn] != 0 {
                            let dest = reg_pages[rn].wrapping_add(addend);
                            if dest == target_vaddr {
                                let mut xm = Map::new();
                                xm.insert("fromVaddr".to_string(), Value::String(format!("0x{:x}", pc)));
                                xm.insert("type".to_string(), Value::String("adrp+add".to_string()));
                                xrefs.push(xm);
                                if xrefs.len() >= limit {
                                    return xrefs;
                                }
                            }
                            if rd == rn {
                                reg_pages[rd] = 0;
                            }
                        }
                    }
                    off += 4;
                }
            } else {
                // Data segment 64-bit pointer scan (.data.rel.ro / .init_array / .got)
                let mut off = start_off;
                while off + 8 <= end_off {
                    let val = self.read_u64_at_offset(off).unwrap_or(0);
                    if val == target_vaddr {
                        let ptr_vaddr = seg.vaddr + ((off - start_off) as u64);
                        let mut xm = Map::new();
                        xm.insert("fromVaddr".to_string(), Value::String(format!("0x{:x}", ptr_vaddr)));
                        xm.insert("type".to_string(), Value::String("data_pointer".to_string()));
                        xrefs.push(xm);
                        if xrefs.len() >= limit {
                            return xrefs;
                        }
                    }
                    off += 8;
                }
            }
        }
        xrefs
    }

    fn decode_one_arm64(
        &self,
        pc: u64,
        w: u32,
        reg_pages: &mut [u64; 32],
    ) -> (String, Option<String>) {
        let reg_x = |r: u32, sp_is_sp: bool| -> String {
            match r & 0x1F {
                31 => {
                    if sp_is_sp {
                        "sp".to_string()
                    } else {
                        "xzr".to_string()
                    }
                }
                n => format!("x{}", n),
            }
        };
        let reg_w = |r: u32, sp_is_wsp: bool| -> String {
            match r & 0x1F {
                31 => {
                    if sp_is_wsp {
                        "wsp".to_string()
                    } else {
                        "wzr".to_string()
                    }
                }
                n => format!("w{}", n),
            }
        };
        let cond_name = |cond: u32| -> &'static str {
            match cond & 0xF {
                0 => "eq",
                1 => "ne",
                2 => "cs",
                3 => "cc",
                4 => "mi",
                5 => "pl",
                6 => "vs",
                7 => "vc",
                8 => "hi",
                9 => "ls",
                10 => "ge",
                11 => "lt",
                12 => "gt",
                13 => "le",
                14 => "al",
                _ => "nv",
            }
        };

        // NOP / RET / BR / BLR
        if w == 0xD503_201F {
            return ("nop".to_string(), None);
        }
        if (w & 0xFFFF_FC1F) == 0xD65F_0000 {
            let rn = (w >> 5) & 0x1F;
            if rn == 30 {
                return ("ret".to_string(), None);
            }
            return (format!("ret x{}", rn), None);
        }
        if (w & 0xFFFF_FC1F) == 0xD61F_0000 {
            let rn = (w >> 5) & 0x1F;
            return (format!("br x{}", rn), None);
        }
        if (w & 0xFFFF_FC1F) == 0xD63F_0000 {
            let rn = (w >> 5) & 0x1F;
            return (format!("blr x{}", rn), None);
        }

        // B / BL (unconditional immediate branch)
        if (w & 0x7C00_0000) == 0x1400_0000 {
            let is_bl = (w >> 31) != 0;
            let imm26 = (w & 0x03FF_FFFF) as i64;
            let sign_ext = (imm26 << 38) >> 38;
            let target = (pc as i64).wrapping_add(sign_ext * 4) as u64;
            let mnem = format!(
                "{} 0x{:x}",
                if is_bl { "bl" } else { "b" },
                target
            );
            let sym_comment = self.addr_to_symbol.get(&target).cloned();
            return (mnem, sym_comment);
        }

        // B.cond
        if (w & 0xFF00_0010) == 0x5400_0000 {
            let cond = w & 0xF;
            let imm19 = ((w >> 5) & 0x7FFFF) as i64;
            let sign_ext = (imm19 << 45) >> 45;
            let target = (pc as i64).wrapping_add(sign_ext * 4) as u64;
            return (format!("b.{} 0x{:x}", cond_name(cond), target), None);
        }

        // CBZ / CBNZ
        if (w & 0x7E00_0000) == 0x3400_0000 {
            let sf = (w >> 31) != 0;
            let is_nz = ((w >> 24) & 1) != 0;
            let rt = w & 0x1F;
            let imm19 = ((w >> 5) & 0x7FFFF) as i64;
            let sign_ext = (imm19 << 45) >> 45;
            let target = (pc as i64).wrapping_add(sign_ext * 4) as u64;
            let rname = if sf {
                reg_x(rt, false)
            } else {
                reg_w(rt, false)
            };
            return (
                format!(
                    "{} {}, 0x{:x}",
                    if is_nz { "cbnz" } else { "cbz" },
                    rname,
                    target
                ),
                None,
            );
        }

        // TBZ / TBNZ
        if (w & 0x7E00_0000) == 0x3600_0000 {
            let b5 = (w >> 31) & 1;
            let is_nz = ((w >> 24) & 1) != 0;
            let b40 = (w >> 19) & 0x1F;
            let bit = (b5 << 5) | b40;
            let imm14 = ((w >> 5) & 0x3FFF) as i64;
            let sign_ext = (imm14 << 50) >> 50;
            let target = (pc as i64).wrapping_add(sign_ext * 4) as u64;
            let rt = w & 0x1F;
            let rname = if b5 != 0 {
                reg_x(rt, false)
            } else {
                reg_w(rt, false)
            };
            return (
                format!(
                    "{} {}, #{}, 0x{:x}",
                    if is_nz { "tbnz" } else { "tbz" },
                    rname,
                    bit,
                    target
                ),
                None,
            );
        }

        // ADRP / ADR
        if (w & 0x1F00_0000) == 0x1000_0000 {
            let is_adrp = (w >> 31) != 0;
            let rd = w & 0x1F;
            let immlo = ((w >> 29) & 0x3) as i64;
            let immhi = (((w >> 5) & 0x7FFFF) as i64) << 2;
            let raw_imm = immhi | immlo;
            let sign_ext = (raw_imm << 43) >> 43;
            let target = if is_adrp {
                ((pc & !0xFFF) as i64).wrapping_add(sign_ext << 12) as u64
            } else {
                (pc as i64).wrapping_add(sign_ext) as u64
            };
            if (rd as usize) < 31 {
                reg_pages[rd as usize] = if is_adrp { target } else { 0 };
            }
            let comment = if !is_adrp {
                self.describe_vaddr(target)
            } else {
                None
            };
            return (
                format!(
                    "{} {}, 0x{:x}",
                    if is_adrp { "adrp" } else { "adr" },
                    reg_x(rd, false),
                    target
                ),
                comment,
            );
        }

        // ADD / SUB immediate
        if (w & 0x1F00_0000) == 0x1100_0000 {
            let sf = (w >> 31) != 0;
            let is_sub = ((w >> 30) & 1) != 0;
            let s_flag = ((w >> 29) & 1) != 0;
            let sh = ((w >> 22) & 1) != 0;
            let imm12 = ((w >> 10) & 0xFFF) as u64;
            let rn = (w >> 5) & 0x1F;
            let rd = w & 0x1F;
            let val = if sh { imm12 << 12 } else { imm12 };

            if s_flag && rd == 31 {
                let rname = if sf {
                    reg_x(rn, true)
                } else {
                    reg_w(rn, true)
                };
                return (
                    format!(
                        "{} {}, #0x{:x}",
                        if is_sub { "cmp" } else { "cmn" },
                        rname,
                        val
                    ),
                    None,
                );
            }

            let rd_name = if sf {
                reg_x(rd, !s_flag)
            } else {
                reg_w(rd, !s_flag)
            };
            let rn_name = if sf {
                reg_x(rn, true)
            } else {
                reg_w(rn, true)
            };

            let mut comment = None;
            if sf && !is_sub && !s_flag && (rn as usize) < 31 && reg_pages[rn as usize] != 0 {
                let resolved = reg_pages[rn as usize].wrapping_add(val);
                comment = Some(
                    self.describe_vaddr(resolved)
                        .unwrap_or_else(|| format!("0x{:x}", resolved)),
                );
                if rd == rn {
                    reg_pages[rd as usize] = 0;
                }
            }

            let op = match (is_sub, s_flag) {
                (false, false) => "add",
                (false, true) => "adds",
                (true, false) => "sub",
                (true, true) => "subs",
            };
            return (format!("{} {}, {}, #0x{:x}", op, rd_name, rn_name, val), comment);
        }

        // ADD / SUB / CMP / CMN shifted register
        if (w & 0x1F20_0000) == 0x0B00_0000 {
            let sf = (w >> 31) != 0;
            let is_sub = ((w >> 30) & 1) != 0;
            let s_flag = ((w >> 29) & 1) != 0;
            let shift = (w >> 22) & 0x3;
            let rm = (w >> 16) & 0x1F;
            let imm6 = (w >> 10) & 0x3F;
            let rn = (w >> 5) & 0x1F;
            let rd = w & 0x1F;
            let r_fn = |r: u32| if sf { reg_x(r, false) } else { reg_w(r, false) };
            let shift_str = if imm6 == 0 {
                String::new()
            } else {
                let sname = match shift {
                    0 => "lsl",
                    1 => "lsr",
                    2 => "asr",
                    _ => "ror",
                };
                format!(", {} #{}", sname, imm6)
            };
            if s_flag && rd == 31 {
                let mnem = if is_sub { "cmp" } else { "cmn" };
                return (format!("{} {}, {}{}", mnem, r_fn(rn), r_fn(rm), shift_str), None);
            }
            let op = match (is_sub, s_flag) {
                (false, false) => "add",
                (false, true) => "adds",
                (true, false) => "sub",
                (true, true) => "subs",
            };
            return (
                format!("{} {}, {}, {}{}", op, r_fn(rd), r_fn(rn), r_fn(rm), shift_str),
                None,
            );
        }

        // MOVZ / MOVN / MOVK
        if (w & 0x1F80_0000) == 0x1280_0000 {
            let sf = (w >> 31) != 0;
            let opc = (w >> 29) & 0x3;
            let hw = ((w >> 21) & 0x3) * 16;
            let imm16 = ((w >> 5) & 0xFFFF) as u64;
            let rd = w & 0x1F;
            let rname = if sf {
                reg_x(rd, false)
            } else {
                reg_w(rd, false)
            };
            if opc == 2 && hw == 0 {
                return (format!("mov {}, #0x{:x}", rname, imm16), None);
            }
            let mnem = match opc {
                0 => "movn",
                2 => "movz",
                3 => "movk",
                _ => "movi",
            };
            return (
                format!("{} {}, #0x{:x}, lsl #{}", mnem, rname, imm16, hw),
                None,
            );
        }

        // UBFM / SBFM (LSL / LSR / ASR aliases)
        if (w & 0x1F80_0000) == 0x1300_0000 {
            let sf = (w >> 31) != 0;
            let opc = (w >> 29) & 0x3;
            let imms = (w >> 10) & 0x3F;
            let immr = (w >> 16) & 0x3F;
            let rn = (w >> 5) & 0x1F;
            let rd = w & 0x1F;
            let r_fn = |r: u32| if sf { reg_x(r, false) } else { reg_w(r, false) };
            let max_bit = if sf { 63 } else { 31 };
            if opc == 2 {
                if imms == max_bit {
                    return (format!("lsr {}, {}, #{}", r_fn(rd), r_fn(rn), immr), None);
                }
                if imms + 1 == immr {
                    let shift = max_bit - imms;
                    return (format!("lsl {}, {}, #{}", r_fn(rd), r_fn(rn), shift), None);
                }
                return (
                    format!("ubfm {}, {}, #{}, #{}", r_fn(rd), r_fn(rn), immr, imms),
                    None,
                );
            } else if opc == 0 && imms == max_bit {
                return (format!("asr {}, {}, #{}", r_fn(rd), r_fn(rn), immr), None);
            }
        }

        // CSEL / CSINC / CSINV / CSNEG / CSET
        if (w & 0x1FE0_0000) == 0x1A80_0000 {
            let sf = (w >> 31) != 0;
            let op = (w >> 30) & 1;
            let o2 = (w >> 10) & 1;
            let rm = (w >> 16) & 0x1F;
            let cond = (w >> 12) & 0xF;
            let rn = (w >> 5) & 0x1F;
            let rd = w & 0x1F;
            let r_fn = |r: u32| if sf { reg_x(r, false) } else { reg_w(r, false) };
            if op == 0 && o2 == 1 && rn == 31 && rm == 31 {
                return (format!("cset {}, {}", r_fn(rd), cond_name(cond ^ 1)), None);
            }
            let mnem = match (op, o2) {
                (0, 0) => "csel",
                (0, 1) => "csinc",
                (1, 0) => "csinv",
                _ => "csneg",
            };
            return (
                format!(
                    "{} {}, {}, {}, {}",
                    mnem,
                    r_fn(rd),
                    r_fn(rn),
                    r_fn(rm),
                    cond_name(cond)
                ),
                None,
            );
        }

        // MADD / MSUB / MUL & UDIV / SDIV
        if (w & 0x1FE0_FC00) == 0x1AC0_0800 {
            let sf = (w >> 31) != 0;
            let is_sdiv = ((w >> 10) & 1) != 0;
            let rm = (w >> 16) & 0x1F;
            let rn = (w >> 5) & 0x1F;
            let rd = w & 0x1F;
            let r_fn = |r: u32| if sf { reg_x(r, false) } else { reg_w(r, false) };
            return (
                format!(
                    "{} {}, {}, {}",
                    if is_sdiv { "sdiv" } else { "udiv" },
                    r_fn(rd),
                    r_fn(rn),
                    r_fn(rm)
                ),
                None,
            );
        }
        if (w & 0x1F80_0000) == 0x1B00_0000 {
            let sf = (w >> 31) != 0;
            let o0 = (w >> 15) & 1;
            let rm = (w >> 16) & 0x1F;
            let ra = (w >> 10) & 0x1F;
            let rn = (w >> 5) & 0x1F;
            let rd = w & 0x1F;
            let r_fn = |r: u32| if sf { reg_x(r, false) } else { reg_w(r, false) };
            if o0 == 0 && ra == 31 {
                return (format!("mul {}, {}, {}", r_fn(rd), r_fn(rn), r_fn(rm)), None);
            }
            return (
                format!(
                    "{} {}, {}, {}, {}",
                    if o0 == 1 { "msub" } else { "madd" },
                    r_fn(rd),
                    r_fn(rn),
                    r_fn(rm),
                    r_fn(ra)
                ),
                None,
            );
        }

        // LDR / STR unsigned immediate (64-bit & 32-bit)
        if (w & 0x3B00_0000) == 0x3900_0000 {
            let size = (w >> 30) & 0x3;
            let opc = (w >> 22) & 0x3;
            let imm12 = ((w >> 10) & 0xFFF) as u64;
            let rn = (w >> 5) & 0x1F;
            let rt = w & 0x1F;
            let scale = 1u64 << size;
            let offset = imm12 * scale;
            let rn_name = reg_x(rn, true);
            let (mnem, rt_name) = match (size, opc) {
                (3, 1) => ("ldr", reg_x(rt, false)),
                (3, 0) => ("str", reg_x(rt, false)),
                (2, 1) => ("ldr", reg_w(rt, false)),
                (2, 0) => ("str", reg_w(rt, false)),
                (2, 2) => ("ldrsw", reg_x(rt, false)),
                (1, 1) => ("ldrh", reg_w(rt, false)),
                (1, 0) => ("strh", reg_w(rt, false)),
                (0, 1) => ("ldrb", reg_w(rt, false)),
                (0, 0) => ("strb", reg_w(rt, false)),
                _ => ("mem", reg_x(rt, false)),
            };
            let mut comment = None;
            if opc == 1 && (rn as usize) < 31 && reg_pages[rn as usize] != 0 {
                let target = reg_pages[rn as usize].wrapping_add(offset);
                comment = Some(
                    self.describe_vaddr(target)
                        .unwrap_or_else(|| format!("[0x{:x}]", target)),
                );
            } else if size == 3 && opc == 1 && rn != 31 {
                if let Some(jni_fn) = jni_vtable_method_name(offset) {
                    comment = Some(format!("JNIEnv->{} (+0x{:x})", jni_fn, offset));
                }
            }
            let addr_str = if offset == 0 {
                format!("[{}]", rn_name)
            } else {
                format!("[{}, #0x{:x}]", rn_name, offset)
            };
            return (format!("{} {}, {}", mnem, rt_name, addr_str), comment);
        }

        // LDR / STR register offset (e.g. ldr x10, [x10, x11, lsl #3])
        if (w & 0x3B20_0C00) == 0x3820_0800 {
            let size = (w >> 30) & 0x3;
            let opc = (w >> 22) & 0x3;
            let rm = (w >> 16) & 0x1F;
            let option = (w >> 13) & 0x7;
            let s_bit = (w >> 12) & 1;
            let rn = (w >> 5) & 0x1F;
            let rt = w & 0x1F;
            let rn_name = reg_x(rn, true);
            let rm_name = if (option & 1) != 0 {
                reg_x(rm, false)
            } else {
                reg_w(rm, false)
            };
            let (mnem, rt_name) = match (size, opc) {
                (3, 1) => ("ldr", reg_x(rt, false)),
                (3, 0) => ("str", reg_x(rt, false)),
                (2, 1) => ("ldr", reg_w(rt, false)),
                (2, 0) => ("str", reg_w(rt, false)),
                (0, 1) => ("ldrb", reg_w(rt, false)),
                (0, 0) => ("strb", reg_w(rt, false)),
                _ => ("ldr", reg_x(rt, false)),
            };
            let ext_str = if option == 3 && s_bit == 0 {
                String::new()
            } else if option == 3 && s_bit == 1 {
                format!(", lsl #{}", size)
            } else if option == 2 {
                if s_bit == 1 {
                    format!(", uxtw #{}", size)
                } else {
                    ", uxtw".to_string()
                }
            } else if option == 6 {
                if s_bit == 1 {
                    format!(", sxtw #{}", size)
                } else {
                    ", sxtw".to_string()
                }
            } else {
                String::new()
            };
            return (
                format!("{} {}, [{}, {}{}]", mnem, rt_name, rn_name, rm_name, ext_str),
                None,
            );
        }

        // LDR / STR immediate pre-index / post-index
        if (w & 0x3B20_0400) == 0x3800_0400 {
            let size = (w >> 30) & 0x3;
            let opc = (w >> 22) & 0x3;
            let imm9 = ((w >> 12) & 0x1FF) as i64;
            let simm9 = (imm9 << 55) >> 55;
            let is_pre = ((w >> 11) & 1) != 0;
            let rn = (w >> 5) & 0x1F;
            let rt = w & 0x1F;
            let rn_name = reg_x(rn, true);
            let (mnem, rt_name) = match (size, opc) {
                (3, 1) => ("ldr", reg_x(rt, false)),
                (3, 0) => ("str", reg_x(rt, false)),
                (2, 1) => ("ldr", reg_w(rt, false)),
                (2, 0) => ("str", reg_w(rt, false)),
                (0, 1) => ("ldrb", reg_w(rt, false)),
                (0, 0) => ("strb", reg_w(rt, false)),
                _ => ("ldr", reg_x(rt, false)),
            };
            let addr = if is_pre {
                format!("[{}, #{}]!", rn_name, simm9)
            } else {
                format!("[{}], #{}", rn_name, simm9)
            };
            return (format!("{} {}, {}", mnem, rt_name, addr), None);
        }

        // LDUR / STUR unscaled signed 9-bit immediate
        if (w & 0x3B20_0C00) == 0x3800_0000 {
            let size = (w >> 30) & 0x3;
            let opc = (w >> 22) & 0x3;
            let imm9 = ((w >> 12) & 0x1FF) as i64;
            let simm9 = (imm9 << 55) >> 55;
            let rn = (w >> 5) & 0x1F;
            let rt = w & 0x1F;
            let rn_name = reg_x(rn, true);
            let (mnem, rt_name) = match (size, opc) {
                (3, 1) => ("ldur", reg_x(rt, false)),
                (3, 0) => ("stur", reg_x(rt, false)),
                (2, 1) => ("ldur", reg_w(rt, false)),
                (2, 0) => ("stur", reg_w(rt, false)),
                (1, 1) => ("ldurh", reg_w(rt, false)),
                (1, 0) => ("sturh", reg_w(rt, false)),
                (0, 1) => ("ldurb", reg_w(rt, false)),
                (0, 0) => ("sturb", reg_w(rt, false)),
                _ => ("memu", reg_x(rt, false)),
            };
            return (format!("{} {}, [{}, #{}]", mnem, rt_name, rn_name, simm9), None);
        }

        // MRS x<rt>, tpidr_el0 (TLS stack canary base in Android AArch64)
        if (w & 0xFFFF_FFE0) == 0xD53B_D040 {
            let rt = w & 0x1F;
            return (
                format!("mrs {}, tpidr_el0", reg_x(rt, false)),
                Some("TLS base (stack canary)".to_string()),
            );
        }

        // MRS / MSR NZCV (anti-emulator flag manipulation)
        if (w & 0xFFFF_FFE0) == 0xD53B_4200 {
            let rt = w & 0x1F;
            return (
                format!("mrs {}, nzcv", reg_x(rt, false)),
                Some("read condition flags".to_string()),
            );
        }
        if (w & 0xFFFF_FFE0) == 0xD51B_4200 {
            let rt = w & 0x1F;
            return (
                format!("msr nzcv, {}", reg_x(rt, false)),
                Some("overwrite condition flags (anti-emulator)".to_string()),
            );
        }
        if w == 0xD503_3F5F {
            return ("clrex".to_string(), None);
        }
        if (w & 0xFFE0_001F) == 0xD420_0000 {
            let imm16 = (w >> 5) & 0xFFFF;
            return (format!("brk #0x{:x}", imm16), Some("software breakpoint trap".to_string()));
        }
        if (w & 0xFFE0_001F) == 0xD400_0001 {
            let imm16 = (w >> 5) & 0xFFFF;
            return (format!("svc #0x{:x}", imm16), Some("supervisor syscall".to_string()));
        }

        // STP / LDP (64-bit / 32-bit)
        if (w & 0x3E00_0000) == 0x2800_0000 {
            let opc = (w >> 30) & 0x3;
            let mode = (w >> 23) & 0x3;
            let is_load = ((w >> 22) & 1) != 0;
            let imm7 = ((w >> 15) & 0x7F) as i64;
            let sign_ext = (imm7 << 57) >> 57;
            let rt2 = (w >> 10) & 0x1F;
            let rn = (w >> 5) & 0x1F;
            let rt = w & 0x1F;
            let is_64_pair = (opc & 2) != 0;
            let scale = if is_64_pair { 8 } else { 4 };
            let off = sign_ext * scale;
            let r1 = if is_64_pair {
                reg_x(rt, false)
            } else {
                reg_w(rt, false)
            };
            let r2 = if is_64_pair {
                reg_x(rt2, false)
            } else {
                reg_w(rt2, false)
            };
            let base = reg_x(rn, true);
            let mnem = if is_load { "ldp" } else { "stp" };
            let addressing = match mode {
                1 => format!("[{}], #{}", base, off),
                2 => {
                    if off == 0 {
                        format!("[{}]", base)
                    } else {
                        format!("[{}, #{}]", base, off)
                    }
                }
                3 => format!("[{}, #{}]!", base, off),
                _ => format!("[{}, #{}]", base, off),
            };
            return (format!("{} {}, {}, {}", mnem, r1, r2, addressing), None);
        }

        // Logical shifted register: AND / ORR / EOR / ANDS (including MOV alias)
        if (w & 0x1F00_0000) == 0x0A00_0000 {
            let sf = (w >> 31) != 0;
            let opc = (w >> 29) & 0x3;
            let n_bit = (w >> 21) & 1;
            let shift = (w >> 22) & 0x3;
            let rm = (w >> 16) & 0x1F;
            let imm6 = (w >> 10) & 0x3F;
            let rn = (w >> 5) & 0x1F;
            let rd = w & 0x1F;
            let r_fn = |r: u32| if sf { reg_x(r, false) } else { reg_w(r, false) };
            if opc == 1 && n_bit == 0 && rn == 31 && imm6 == 0 {
                return (format!("mov {}, {}", r_fn(rd), r_fn(rm)), None);
            }
            let shift_str = if imm6 == 0 {
                String::new()
            } else {
                let sname = match shift {
                    0 => "lsl",
                    1 => "lsr",
                    2 => "asr",
                    _ => "ror",
                };
                format!(", {} #{}", sname, imm6)
            };
            if opc == 3 && n_bit == 0 && rd == 31 {
                return (format!("tst {}, {}{}", r_fn(rn), r_fn(rm), shift_str), None);
            }
            let mnem = match (opc, n_bit) {
                (0, 0) => "and",
                (0, 1) => "bic",
                (1, 0) => "orr",
                (1, 1) => "orn",
                (2, 0) => "eor",
                (2, 1) => "eon",
                (3, 0) => "ands",
                _ => "bics",
            };
            return (
                format!("{} {}, {}, {}{}", mnem, r_fn(rd), r_fn(rn), r_fn(rm), shift_str),
                None,
            );
        }

        (format!(".inst 0x{:08x}", w), None)
    }

    fn describe_vaddr(&self, vaddr: u64) -> Option<String> {
        if let Some(sym) = self.addr_to_symbol.get(&vaddr) {
            return Some(format!("0x{:x} <{}>", vaddr, sym));
        }
        if let Some(s) = self.read_cstr_at_vaddr(vaddr, 96) {
            if s.len() >= 2 {
                let escaped = s.replace('\n', "\\n").replace('\r', "\\r");
                return Some(format!("0x{:x} {:?}", vaddr, escaped));
            }
        }
        if let Some(ptr) = self.read_ptr_at_vaddr(vaddr) {
            if let Some(sym) = self.addr_to_symbol.get(&ptr) {
                return Some(format!("[0x{:x}] -> 0x{:x} <{}>", vaddr, ptr, sym));
            }
        }
        None
    }
}

fn jni_vtable_method_name(offset: u64) -> Option<&'static str> {
    match offset {
        0x20 => Some("GetVersion"),
        0x28 => Some("DefineClass"),
        0x30 => Some("FindClass / JavaVM::GetEnv"),
        0x78 => Some("ExceptionOccurred"),
        0x80 => Some("ExceptionDescribe"),
        0x88 => Some("ExceptionClear"),
        0x90 => Some("FatalError"),
        0xa8 => Some("NewGlobalRef"),
        0xb0 => Some("DeleteGlobalRef"),
        0xb8 => Some("DeleteLocalRef"),
        0xd8 => Some("AllocObject"),
        0xe0 => Some("NewObject"),
        0xe8 => Some("NewObjectV"),
        0xf8 => Some("GetObjectClass"),
        0x100 => Some("IsInstanceOf"),
        0x108 => Some("GetMethodID"),
        0x110 => Some("CallObjectMethod"),
        0x118 => Some("CallObjectMethodV"),
        0x128 => Some("CallBooleanMethod"),
        0x188 => Some("CallIntMethod"),
        0x1a0 => Some("CallLongMethod"),
        0x1f0 => Some("CallVoidMethod"),
        0x1f8 => Some("CallVoidMethodV"),
        0x2f0 => Some("GetFieldID"),
        0x2f8 => Some("GetObjectField"),
        0x318 => Some("GetIntField"),
        0x320 => Some("GetLongField"),
        0x338 => Some("SetObjectField"),
        0x388 => Some("GetStaticMethodID"),
        0x390 => Some("CallStaticObjectMethod"),
        0x398 => Some("CallStaticObjectMethodV"),
        0x3a8 => Some("CallStaticBooleanMethod"),
        0x408 => Some("CallStaticIntMethod"),
        0x420 => Some("CallStaticLongMethod"),
        0x468 => Some("CallStaticVoidMethod"),
        0x470 => Some("CallStaticVoidMethodV"),
        0x480 => Some("GetStaticFieldID"),
        0x488 => Some("GetStaticObjectField"),
        0x538 => Some("NewStringUTF"),
        0x540 => Some("GetStringUTFLength"),
        0x548 => Some("GetStringUTFChars"),
        0x550 => Some("ReleaseStringUTFChars"),
        0x558 => Some("GetArrayLength"),
        0x560 => Some("NewObjectArray"),
        0x568 => Some("GetObjectArrayElement"),
        0x570 => Some("SetObjectArrayElement"),
        0x580 => Some("NewByteArray"),
        0x5c0 => Some("GetByteArrayElements"),
        0x5d8 => Some("GetIntArrayElements"),
        0x600 => Some("ReleaseByteArrayElements"),
        0x640 => Some("GetByteArrayRegion"),
        0x680 => Some("SetByteArrayRegion"),
        0x6b8 => Some("RegisterNatives"),
        0x6c0 => Some("UnregisterNatives"),
        0x6c8 => Some("MonitorEnter"),
        0x6d0 => Some("MonitorExit"),
        0x6e0 => Some("GetJavaVM"),
        0x720 => Some("ExceptionCheck"),
        _ => None,
    }
}

pub fn resolve_so_entry_name(
    resource_entries: &[(String, u64)],
    lib_query: &str,
) -> Option<String> {
    let q = lib_query.trim().replace('\\', "/");
    if q.is_empty() {
        return None;
    }
    // 1. Exact match
    if resource_entries.iter().any(|(n, _)| n == &q) {
        return Some(q);
    }
    let q_lower = q.to_lowercase();
    let bare = match q_lower.rfind('/') {
        Some(idx) => &q_lower[idx + 1..],
        None => q_lower.as_str(),
    };
    let normalized_file = if bare.ends_with(".so") {
        if bare.starts_with("lib") {
            bare.to_string()
        } else {
            format!("lib{}", bare)
        }
    } else if bare.starts_with("lib") {
        format!("{}.so", bare)
    } else {
        format!("lib{}.so", bare)
    };

    let mut candidates: Vec<&str> = resource_entries
        .iter()
        .map(|(n, _)| n.as_str())
        .filter(|n| {
            let nl = n.to_lowercase();
            nl == q_lower
                || nl.ends_with(&format!("/{}", normalized_file))
                || nl.ends_with(&format!("/{}", bare))
                || (nl.ends_with(".so") && nl.contains(&q_lower))
        })
        .collect();

    if candidates.is_empty() {
        return None;
    }

    // Prefer arm64-v8a > x86_64 > armeabi-v7a > x86
    let abi_rank = |path: &str| -> u8 {
        if path.contains("arm64-v8a") {
            0
        } else if path.contains("x86_64") {
            1
        } else if path.contains("armeabi-v7a") {
            2
        } else if path.contains("x86") {
            3
        } else {
            4
        }
    };
    candidates.sort_by_key(|p| (abi_rank(p), p.len()));
    Some(candidates[0].to_string())
}

fn read_cstr(buf: &[u8], off: usize) -> String {
    if off >= buf.len() {
        return String::new();
    }
    let slice = &buf[off..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

fn read_validated_cstr(buf: &[u8], off: usize, max_len: usize) -> Option<String> {
    if off >= buf.len() {
        return None;
    }
    let limit = (off + max_len).min(buf.len());
    let slice = &buf[off..limit];
    let nul_pos = slice.iter().position(|&b| b == 0)?;
    if nul_pos == 0 {
        return None;
    }
    let bytes = &slice[..nul_pos];
    if !bytes.iter().all(|&b| is_printable_ascii(b)) {
        return None;
    }
    std::str::from_utf8(bytes).ok().map(|s| s.to_string())
}

fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7E).contains(&b) || b == b'\t'
}

fn is_valid_java_method_identifier(s: &str) -> bool {
    if s.is_empty() || s.len() > 192 {
        return false;
    }
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_' || first == '$') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

fn is_valid_jni_signature(s: &str) -> bool {
    if !s.starts_with('(') || s.len() < 3 || s.len() > 512 {
        return false;
    }
    let Some(rparen) = s.find(')') else {
        return false;
    };
    if rparen + 1 >= s.len() {
        return false;
    };
    let args = &s[1..rparen];
    let ret = &s[rparen + 1..];
    is_valid_type_sequence(args, false) && is_valid_type_sequence(ret, true)
}

fn is_valid_type_sequence(seq: &str, single_or_void: bool) -> bool {
    if single_or_void && seq == "V" {
        return true;
    }
    let bytes = seq.as_bytes();
    let mut i = 0usize;
    let mut count = 0usize;
    while i < bytes.len() {
        count += 1;
        if single_or_void && count > 1 {
            return false;
        }
        while i < bytes.len() && bytes[i] == b'[' {
            i += 1;
        }
        if i >= bytes.len() {
            return false;
        }
        match bytes[i] {
            b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D' => {
                i += 1;
            }
            b'L' => {
                i += 1;
                let cls_start = i;
                while i < bytes.len() && bytes[i] != b';' {
                    let c = bytes[i];
                    if !(c.is_ascii_alphanumeric() || c == b'/' || c == b'_' || c == b'$') {
                        return false;
                    }
                    i += 1;
                }
                if i >= bytes.len() || bytes[i] != b';' || i == cls_start {
                    return false;
                }
                i += 1;
            }
            _ => return false,
        }
    }
    !single_or_void || count == 1
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}
