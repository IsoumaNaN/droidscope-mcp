use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefKind {
    None,
    StringRef,
    TypeRef,
    FieldRef,
    MethodRef,
    CallSiteRef,
    MethodAndProtoRef,
    ProtoRef,
    MethodHandleRef,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsnFormat {
    F10x,
    F12x,
    F11n,
    F11x,
    F10t,
    F20t,
    F20bc,
    F22x,
    F21t,
    F21s,
    F21h,
    F21c,
    F23x,
    F22b,
    F22t,
    F22s,
    F22c,
    F30t,
    F32x,
    F31i,
    F31t,
    F31c,
    F35c,
    F3rc,
    F45cc,
    F4rcc,
    F51l,
}

#[derive(Debug, Clone, Copy)]
pub struct OpcodeInfo {
    pub opcode: u8,
    pub name: &'static str,
    pub format: InsnFormat,
    pub ref_kind: RefKind,
}

impl OpcodeInfo {
    pub fn units(&self) -> usize {
        match self.format {
            InsnFormat::F10x
            | InsnFormat::F12x
            | InsnFormat::F11n
            | InsnFormat::F11x
            | InsnFormat::F10t => 1,
            InsnFormat::F20t
            | InsnFormat::F20bc
            | InsnFormat::F22x
            | InsnFormat::F21t
            | InsnFormat::F21s
            | InsnFormat::F21h
            | InsnFormat::F21c
            | InsnFormat::F23x
            | InsnFormat::F22b
            | InsnFormat::F22t
            | InsnFormat::F22s
            | InsnFormat::F22c => 2,
            InsnFormat::F30t
            | InsnFormat::F32x
            | InsnFormat::F31i
            | InsnFormat::F31t
            | InsnFormat::F31c
            | InsnFormat::F35c
            | InsnFormat::F3rc => 3,
            InsnFormat::F45cc | InsnFormat::F4rcc => 4,
            InsnFormat::F51l => 5,
        }
    }
}

pub fn opcode_info(op: u8) -> OpcodeInfo {
    use InsnFormat::*;
    use RefKind::*;
    let (name, format, ref_kind) = match op {
        0x00 => ("nop", F10x, None),
        0x01 => ("move", F12x, None),
        0x02 => ("move/from16", F22x, None),
        0x03 => ("move/16", F32x, None),
        0x04 => ("move-wide", F12x, None),
        0x05 => ("move-wide/from16", F22x, None),
        0x06 => ("move-wide/16", F32x, None),
        0x07 => ("move-object", F12x, None),
        0x08 => ("move-object/from16", F22x, None),
        0x09 => ("move-object/16", F32x, None),
        0x0a => ("move-result", F11x, None),
        0x0b => ("move-result-wide", F11x, None),
        0x0c => ("move-result-object", F11x, None),
        0x0d => ("move-exception", F11x, None),
        0x0e => ("return-void", F10x, None),
        0x0f => ("return", F11x, None),
        0x10 => ("return-wide", F11x, None),
        0x11 => ("return-object", F11x, None),
        0x12 => ("const/4", F11n, None),
        0x13 => ("const/16", F21s, None),
        0x14 => ("const", F31i, None),
        0x15 => ("const/high16", F21h, None),
        0x16 => ("const-wide/16", F21s, None),
        0x17 => ("const-wide/32", F31i, None),
        0x18 => ("const-wide", F51l, None),
        0x19 => ("const-wide/high16", F21h, None),
        0x1a => ("const-string", F21c, StringRef),
        0x1b => ("const-string/jumbo", F31c, StringRef),
        0x1c => ("const-class", F21c, TypeRef),
        0x1d => ("monitor-enter", F11x, None),
        0x1e => ("monitor-exit", F11x, None),
        0x1f => ("check-cast", F21c, TypeRef),
        0x20 => ("instance-of", F22c, TypeRef),
        0x21 => ("array-length", F12x, None),
        0x22 => ("new-instance", F21c, TypeRef),
        0x23 => ("new-array", F22c, TypeRef),
        0x24 => ("filled-new-array", F35c, TypeRef),
        0x25 => ("filled-new-array/range", F3rc, TypeRef),
        0x26 => ("fill-array-data", F31t, None),
        0x27 => ("throw", F11x, None),
        0x28 => ("goto", F10t, None),
        0x29 => ("goto/16", F20t, None),
        0x2a => ("goto/32", F30t, None),
        0x2b => ("packed-switch", F31t, None),
        0x2c => ("sparse-switch", F31t, None),
        0x2d => ("cmpl-float", F23x, None),
        0x2e => ("cmpg-float", F23x, None),
        0x2f => ("cmpl-double", F23x, None),
        0x30 => ("cmpg-double", F23x, None),
        0x31 => ("cmp-long", F23x, None),
        0x32 => ("if-eq", F22t, None),
        0x33 => ("if-ne", F22t, None),
        0x34 => ("if-lt", F22t, None),
        0x35 => ("if-ge", F22t, None),
        0x36 => ("if-gt", F22t, None),
        0x37 => ("if-le", F22t, None),
        0x38 => ("if-eqz", F21t, None),
        0x39 => ("if-nez", F21t, None),
        0x3a => ("if-ltz", F21t, None),
        0x3b => ("if-gez", F21t, None),
        0x3c => ("if-gtz", F21t, None),
        0x3d => ("if-lez", F21t, None),
        0x3e..=0x43 => ("unused", F10x, None),
        0x44 => ("aget", F23x, None),
        0x45 => ("aget-wide", F23x, None),
        0x46 => ("aget-object", F23x, None),
        0x47 => ("aget-boolean", F23x, None),
        0x48 => ("aget-byte", F23x, None),
        0x49 => ("aget-char", F23x, None),
        0x4a => ("aget-short", F23x, None),
        0x4b => ("aput", F23x, None),
        0x4c => ("aput-wide", F23x, None),
        0x4d => ("aput-object", F23x, None),
        0x4e => ("aput-boolean", F23x, None),
        0x4f => ("aput-byte", F23x, None),
        0x50 => ("aput-char", F23x, None),
        0x51 => ("aput-short", F23x, None),
        0x52 => ("iget", F22c, FieldRef),
        0x53 => ("iget-wide", F22c, FieldRef),
        0x54 => ("iget-object", F22c, FieldRef),
        0x55 => ("iget-boolean", F22c, FieldRef),
        0x56 => ("iget-byte", F22c, FieldRef),
        0x57 => ("iget-char", F22c, FieldRef),
        0x58 => ("iget-short", F22c, FieldRef),
        0x59 => ("iput", F22c, FieldRef),
        0x5a => ("iput-wide", F22c, FieldRef),
        0x5b => ("iput-object", F22c, FieldRef),
        0x5c => ("iput-boolean", F22c, FieldRef),
        0x5d => ("iput-byte", F22c, FieldRef),
        0x5e => ("iput-char", F22c, FieldRef),
        0x5f => ("iput-short", F22c, FieldRef),
        0x60 => ("sget", F21c, FieldRef),
        0x61 => ("sget-wide", F21c, FieldRef),
        0x62 => ("sget-object", F21c, FieldRef),
        0x63 => ("sget-boolean", F21c, FieldRef),
        0x64 => ("sget-byte", F21c, FieldRef),
        0x65 => ("sget-char", F21c, FieldRef),
        0x66 => ("sget-short", F21c, FieldRef),
        0x67 => ("sput", F21c, FieldRef),
        0x68 => ("sput-wide", F21c, FieldRef),
        0x69 => ("sput-object", F21c, FieldRef),
        0x6a => ("sput-boolean", F21c, FieldRef),
        0x6b => ("sput-byte", F21c, FieldRef),
        0x6c => ("sput-char", F21c, FieldRef),
        0x6d => ("sput-short", F21c, FieldRef),
        0x6e => ("invoke-virtual", F35c, MethodRef),
        0x6f => ("invoke-super", F35c, MethodRef),
        0x70 => ("invoke-direct", F35c, MethodRef),
        0x71 => ("invoke-static", F35c, MethodRef),
        0x72 => ("invoke-interface", F35c, MethodRef),
        0x73 => ("unused", F10x, None),
        0x74 => ("invoke-virtual/range", F3rc, MethodRef),
        0x75 => ("invoke-super/range", F3rc, MethodRef),
        0x76 => ("invoke-direct/range", F3rc, MethodRef),
        0x77 => ("invoke-static/range", F3rc, MethodRef),
        0x78 => ("invoke-interface/range", F3rc, MethodRef),
        0x79..=0x7a => ("unused", F10x, None),
        0x7b => ("neg-int", F12x, None),
        0x7c => ("not-int", F12x, None),
        0x7d => ("neg-long", F12x, None),
        0x7e => ("not-long", F12x, None),
        0x7f => ("neg-float", F12x, None),
        0x80 => ("neg-double", F12x, None),
        0x81 => ("int-to-long", F12x, None),
        0x82 => ("int-to-float", F12x, None),
        0x83 => ("int-to-double", F12x, None),
        0x84 => ("long-to-int", F12x, None),
        0x85 => ("long-to-float", F12x, None),
        0x86 => ("long-to-double", F12x, None),
        0x87 => ("float-to-int", F12x, None),
        0x88 => ("float-to-long", F12x, None),
        0x89 => ("float-to-double", F12x, None),
        0x8a => ("double-to-int", F12x, None),
        0x8b => ("double-to-long", F12x, None),
        0x8c => ("double-to-float", F12x, None),
        0x8d => ("int-to-byte", F12x, None),
        0x8e => ("int-to-char", F12x, None),
        0x8f => ("int-to-short", F12x, None),
        0x90 => ("add-int", F23x, None),
        0x91 => ("sub-int", F23x, None),
        0x92 => ("mul-int", F23x, None),
        0x93 => ("div-int", F23x, None),
        0x94 => ("rem-int", F23x, None),
        0x95 => ("and-int", F23x, None),
        0x96 => ("or-int", F23x, None),
        0x97 => ("xor-int", F23x, None),
        0x98 => ("shl-int", F23x, None),
        0x99 => ("shr-int", F23x, None),
        0x9a => ("ushr-int", F23x, None),
        0x9b => ("add-long", F23x, None),
        0x9c => ("sub-long", F23x, None),
        0x9d => ("mul-long", F23x, None),
        0x9e => ("div-long", F23x, None),
        0x9f => ("rem-long", F23x, None),
        0xa0 => ("and-long", F23x, None),
        0xa1 => ("or-long", F23x, None),
        0xa2 => ("xor-long", F23x, None),
        0xa3 => ("shl-long", F23x, None),
        0xa4 => ("shr-long", F23x, None),
        0xa5 => ("ushr-long", F23x, None),
        0xa6 => ("add-float", F23x, None),
        0xa7 => ("sub-float", F23x, None),
        0xa8 => ("mul-float", F23x, None),
        0xa9 => ("div-float", F23x, None),
        0xaa => ("rem-float", F23x, None),
        0xab => ("add-double", F23x, None),
        0xac => ("sub-double", F23x, None),
        0xad => ("mul-double", F23x, None),
        0xae => ("div-double", F23x, None),
        0xaf => ("rem-double", F23x, None),
        0xb0 => ("add-int/2addr", F12x, None),
        0xb1 => ("sub-int/2addr", F12x, None),
        0xb2 => ("mul-int/2addr", F12x, None),
        0xb3 => ("div-int/2addr", F12x, None),
        0xb4 => ("rem-int/2addr", F12x, None),
        0xb5 => ("and-int/2addr", F12x, None),
        0xb6 => ("or-int/2addr", F12x, None),
        0xb7 => ("xor-int/2addr", F12x, None),
        0xb8 => ("shl-int/2addr", F12x, None),
        0xb9 => ("shr-int/2addr", F12x, None),
        0xba => ("ushr-int/2addr", F12x, None),
        0xbb => ("add-long/2addr", F12x, None),
        0xbc => ("sub-long/2addr", F12x, None),
        0xbd => ("mul-long/2addr", F12x, None),
        0xbe => ("div-long/2addr", F12x, None),
        0xbf => ("rem-long/2addr", F12x, None),
        0xc0 => ("and-long/2addr", F12x, None),
        0xc1 => ("or-long/2addr", F12x, None),
        0xc2 => ("xor-long/2addr", F12x, None),
        0xc3 => ("shl-long/2addr", F12x, None),
        0xc4 => ("shr-long/2addr", F12x, None),
        0xc5 => ("ushr-long/2addr", F12x, None),
        0xc6 => ("add-float/2addr", F12x, None),
        0xc7 => ("sub-float/2addr", F12x, None),
        0xc8 => ("mul-float/2addr", F12x, None),
        0xc9 => ("div-float/2addr", F12x, None),
        0xca => ("rem-float/2addr", F12x, None),
        0xcb => ("add-double/2addr", F12x, None),
        0xcc => ("sub-double/2addr", F12x, None),
        0xcd => ("mul-double/2addr", F12x, None),
        0xce => ("div-double/2addr", F12x, None),
        0xcf => ("rem-double/2addr", F12x, None),
        0xd0 => ("add-int/lit16", F22s, None),
        0xd1 => ("rsub-int", F22s, None),
        0xd2 => ("mul-int/lit16", F22s, None),
        0xd3 => ("div-int/lit16", F22s, None),
        0xd4 => ("rem-int/lit16", F22s, None),
        0xd5 => ("and-int/lit16", F22s, None),
        0xd6 => ("or-int/lit16", F22s, None),
        0xd7 => ("xor-int/lit16", F22s, None),
        0xd8 => ("add-int/lit8", F22b, None),
        0xd9 => ("rsub-int/lit8", F22b, None),
        0xda => ("mul-int/lit8", F22b, None),
        0xdb => ("div-int/lit8", F22b, None),
        0xdc => ("rem-int/lit8", F22b, None),
        0xdd => ("and-int/lit8", F22b, None),
        0xde => ("or-int/lit8", F22b, None),
        0xdf => ("xor-int/lit8", F22b, None),
        0xe0 => ("shl-int/lit8", F22b, None),
        0xe1 => ("shr-int/lit8", F22b, None),
        0xe2 => ("ushr-int/lit8", F22b, None),
        0xe3..=0xf9 => ("unused", F10x, None),
        0xfa => ("invoke-polymorphic", F45cc, MethodAndProtoRef),
        0xfb => ("invoke-polymorphic/range", F4rcc, MethodAndProtoRef),
        0xfc => ("invoke-custom", F35c, CallSiteRef),
        0xfd => ("invoke-custom/range", F3rc, CallSiteRef),
        0xfe => ("const-method-handle", F21c, MethodHandleRef),
        0xff => ("const-method-type", F21c, ProtoRef),
    };
    OpcodeInfo {
        opcode: op,
        name,
        format,
        ref_kind,
    }
}

#[derive(Debug, Clone)]
pub struct DecodedInsn {
    pub offset_units: u32,
    pub opcode: u8,
    pub format: InsnFormat,
    pub ref_kind: RefKind,
    pub reg_a: u16,
    pub reg_b: u16,
    pub reg_c: u16,
    pub regs: Vec<u16>,
    pub index: u32,
    pub proto_index: u32,
    pub literal: i64,
    pub target_units: i32,
}

impl DecodedInsn {
    pub fn is_xor(&self) -> bool {
        matches!(
            self.opcode,
            0x97 | 0xa2 | 0xb7 | 0xc2 | 0xd7 | 0xdf
        )
    }
}

pub fn decode_instructions(insns_bytes: &[u8]) -> Vec<DecodedInsn> {
    let total_units = insns_bytes.len() / 2;
    let mut out = Vec::new();
    let mut u = 0usize;

    let unit_at = |idx: usize| -> u16 {
        let b = idx * 2;
        if b + 2 <= insns_bytes.len() {
            u16::from_le_bytes([insns_bytes[b], insns_bytes[b + 1]])
        } else {
            0
        }
    };

    while u < total_units {
        let w0 = unit_at(u);
        // Handle payload pseudo-instructions
        if w0 == 0x0100 && u + 1 < total_units {
            // packed-switch-payload: size at u+1, targets = size * 2 units + 4 header units
            let size = unit_at(u + 1) as usize;
            u += 4 + size * 2;
            continue;
        } else if w0 == 0x0200 && u + 1 < total_units {
            // sparse-switch-payload: size at u+1, keys + targets = size * 4 units + 2 header units
            let size = unit_at(u + 1) as usize;
            u += 2 + size * 4;
            continue;
        } else if w0 == 0x0300 && u + 3 < total_units {
            // fill-array-data-payload: elem_width at u+1, size (u32) at u+2..u+3
            let elem_width = unit_at(u + 1) as usize;
            let size = (unit_at(u + 2) as usize) | ((unit_at(u + 3) as usize) << 16);
            let data_bytes = elem_width.saturating_mul(size);
            let data_units = (data_bytes + 1) / 2;
            u += 4 + data_units;
            continue;
        }

        let op = (w0 & 0xff) as u8;
        let hi = (w0 >> 8) as u8;
        let info = opcode_info(op);
        let width = info.units();
        if u + width > total_units {
            break;
        }

        let w1 = if width >= 2 { unit_at(u + 1) } else { 0 };
        let w2 = if width >= 3 { unit_at(u + 2) } else { 0 };
        let w3 = if width >= 4 { unit_at(u + 3) } else { 0 };
        let w4 = if width >= 5 { unit_at(u + 4) } else { 0 };

        let mut insn = DecodedInsn {
            offset_units: u as u32,
            opcode: op,
            format: info.format,
            ref_kind: info.ref_kind,
            reg_a: 0,
            reg_b: 0,
            reg_c: 0,
            regs: Vec::new(),
            index: 0,
            proto_index: 0,
            literal: 0,
            target_units: 0,
        };

        match info.format {
            InsnFormat::F10x => {}
            InsnFormat::F12x => {
                insn.reg_a = (hi & 0x0f) as u16;
                insn.reg_b = (hi >> 4) as u16;
            }
            InsnFormat::F11n => {
                insn.reg_a = (hi & 0x0f) as u16;
                let nib = ((hi >> 4) as i8) << 4 >> 4;
                insn.literal = nib as i64;
            }
            InsnFormat::F11x => {
                insn.reg_a = hi as u16;
            }
            InsnFormat::F10t => {
                let off = (hi as i8) as i32;
                insn.target_units = (u as i32) + off;
            }
            InsnFormat::F20t => {
                let off = (w1 as i16) as i32;
                insn.target_units = (u as i32) + off;
            }
            InsnFormat::F20bc => {
                insn.literal = hi as i64;
                insn.index = w1 as u32;
            }
            InsnFormat::F22x => {
                insn.reg_a = hi as u16;
                insn.reg_b = w1;
            }
            InsnFormat::F21t => {
                insn.reg_a = hi as u16;
                insn.target_units = (u as i32) + ((w1 as i16) as i32);
            }
            InsnFormat::F21s => {
                insn.reg_a = hi as u16;
                insn.literal = (w1 as i16) as i64;
            }
            InsnFormat::F21h => {
                insn.reg_a = hi as u16;
                if op == 0x15 {
                    insn.literal = ((w1 as i32) << 16) as i64;
                } else {
                    insn.literal = (w1 as i64) << 48;
                }
            }
            InsnFormat::F21c => {
                insn.reg_a = hi as u16;
                insn.index = w1 as u32;
            }
            InsnFormat::F23x => {
                insn.reg_a = hi as u16;
                insn.reg_b = w1 & 0xff;
                insn.reg_c = w1 >> 8;
            }
            InsnFormat::F22b => {
                insn.reg_a = hi as u16;
                insn.reg_b = w1 & 0xff;
                insn.literal = ((w1 >> 8) as i8) as i64;
            }
            InsnFormat::F22t => {
                insn.reg_a = (hi & 0x0f) as u16;
                insn.reg_b = (hi >> 4) as u16;
                insn.target_units = (u as i32) + ((w1 as i16) as i32);
            }
            InsnFormat::F22s => {
                insn.reg_a = (hi & 0x0f) as u16;
                insn.reg_b = (hi >> 4) as u16;
                insn.literal = (w1 as i16) as i64;
            }
            InsnFormat::F22c => {
                insn.reg_a = (hi & 0x0f) as u16;
                insn.reg_b = (hi >> 4) as u16;
                insn.index = w1 as u32;
            }
            InsnFormat::F30t => {
                let off = ((w1 as u32) | ((w2 as u32) << 16)) as i32;
                insn.target_units = (u as i32) + off;
            }
            InsnFormat::F32x => {
                insn.reg_a = w1;
                insn.reg_b = w2;
            }
            InsnFormat::F31i => {
                insn.reg_a = hi as u16;
                let lit = ((w1 as u32) | ((w2 as u32) << 16)) as i32;
                insn.literal = lit as i64;
            }
            InsnFormat::F31t => {
                insn.reg_a = hi as u16;
                let off = ((w1 as u32) | ((w2 as u32) << 16)) as i32;
                insn.target_units = (u as i32) + off;
            }
            InsnFormat::F31c => {
                insn.reg_a = hi as u16;
                insn.index = (w1 as u32) | ((w2 as u32) << 16);
            }
            InsnFormat::F35c => {
                let argc = (hi >> 4) as usize;
                let reg_g = (hi & 0x0f) as u16;
                insn.index = w1 as u32;
                let r_all = [
                    w2 & 0x0f,
                    (w2 >> 4) & 0x0f,
                    (w2 >> 8) & 0x0f,
                    (w2 >> 12) & 0x0f,
                    reg_g,
                ];
                for r in r_all.iter().take(argc.min(5)) {
                    insn.regs.push(*r);
                }
            }
            InsnFormat::F3rc => {
                let argc = hi as usize;
                insn.index = w1 as u32;
                let start_reg = w2;
                for i in 0..argc {
                    insn.regs.push(start_reg.wrapping_add(i as u16));
                }
            }
            InsnFormat::F45cc => {
                let argc = (hi >> 4) as usize;
                let reg_g = (hi & 0x0f) as u16;
                insn.index = w1 as u32;
                insn.proto_index = w3 as u32;
                let r_all = [
                    w2 & 0x0f,
                    (w2 >> 4) & 0x0f,
                    (w2 >> 8) & 0x0f,
                    (w2 >> 12) & 0x0f,
                    reg_g,
                ];
                for r in r_all.iter().take(argc.min(5)) {
                    insn.regs.push(*r);
                }
            }
            InsnFormat::F4rcc => {
                let argc = hi as usize;
                insn.index = w1 as u32;
                let start_reg = w2;
                insn.proto_index = w3 as u32;
                for i in 0..argc {
                    insn.regs.push(start_reg.wrapping_add(i as u16));
                }
            }
            InsnFormat::F51l => {
                insn.reg_a = hi as u16;
                let lit = (w1 as u64)
                    | ((w2 as u64) << 16)
                    | ((w3 as u64) << 32)
                    | ((w4 as u64) << 48);
                insn.literal = lit as i64;
            }
        }

        out.push(insn);
        u += width;
    }
    out
}

#[derive(Debug, Clone)]
pub struct DexProto {
    pub return_type_idx: u32,
    pub param_type_idxs: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct DexFieldId {
    pub class_idx: u16,
    pub type_idx: u16,
    pub name_idx: u32,
}

#[derive(Debug, Clone)]
pub struct DexMethodId {
    pub class_idx: u16,
    pub proto_idx: u16,
    pub name_idx: u32,
}

#[derive(Debug, Clone)]
pub struct DexFieldDef {
    pub field_idx: u32,
    pub access_flags: u32,
    pub initial_value: Option<EncodedValue>,
}

#[derive(Debug, Clone)]
pub struct TryBlock {
    pub start_unit: u32,
    pub insn_count: u16,
    pub handlers: Vec<(Option<u32>, u32)>, // (Some(type_idx) or None for catch-all, handler_unit_offset)
}

#[derive(Debug, Clone)]
pub struct DexMethodDef {
    pub method_idx: u32,
    pub access_flags: u32,
    pub code_off: u32,
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub insns_off: u32,
    pub insns_size_units: u32,
    pub tries: Vec<TryBlock>,
}

#[derive(Debug, Clone)]
pub enum EncodedValue {
    Byte(i8),
    Short(i16),
    Char(u16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    String(u32),
    Type(u32),
    Field(u32),
    Method(u32),
    Enum(u32),
    Boolean(bool),
    Null,
}

#[derive(Debug, Clone)]
pub struct DexClassDef {
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass_idx: Option<u32>,
    pub interface_idxs: Vec<u32>,
    pub source_file_idx: Option<u32>,
    pub static_fields: Vec<DexFieldDef>,
    pub instance_fields: Vec<DexFieldDef>,
    pub direct_methods: Vec<DexMethodDef>,
    pub virtual_methods: Vec<DexMethodDef>,
    pub annotation_types: Vec<u32>,
    pub method_annotations: HashMap<u32, Vec<u32>>,
    pub field_annotations: HashMap<u32, Vec<u32>>,
    /// Any method_idx or type_idx or string_idx referenced inside class annotations
    pub annotation_type_refs: Vec<u32>,
    pub enclosing_class_idx: Option<u32>,
    pub inner_class_idxs: Vec<u32>,
}

pub struct ParsedDex {
    pub strings: Vec<String>,
    pub type_string_idxs: Vec<u32>,
    pub protos: Vec<DexProto>,
    pub fields: Vec<DexFieldId>,
    pub methods: Vec<DexMethodId>,
    pub classes: Vec<DexClassDef>,
    /// Maps call_site_idx -> target method_idx (e.g. bootstrap lambda target at arg 4)
    pub call_site_targets: HashMap<u32, u32>,
}

impl ParsedDex {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 112 || !data.starts_with(b"dex\n") {
            return Err("Invalid DEX header".to_string());
        }

        let string_ids_size = read_u32(data, 56) as usize;
        let string_ids_off = read_u32(data, 60) as usize;
        let type_ids_size = read_u32(data, 64) as usize;
        let type_ids_off = read_u32(data, 68) as usize;
        let proto_ids_size = read_u32(data, 72) as usize;
        let proto_ids_off = read_u32(data, 76) as usize;
        let field_ids_size = read_u32(data, 80) as usize;
        let field_ids_off = read_u32(data, 84) as usize;
        let method_ids_size = read_u32(data, 88) as usize;
        let method_ids_off = read_u32(data, 92) as usize;
        let class_defs_size = read_u32(data, 96) as usize;
        let class_defs_off = read_u32(data, 100) as usize;
        let map_off = read_u32(data, 52) as usize;

        // 1. Strings
        let mut strings = Vec::with_capacity(string_ids_size);
        for i in 0..string_ids_size {
            let off = string_ids_off + i * 4;
            if off + 4 > data.len() {
                strings.push(String::new());
                continue;
            }
            let str_data_off = read_u32(data, off) as usize;
            strings.push(read_dex_string(data, str_data_off));
        }

        // 2. Types
        let mut type_string_idxs = Vec::with_capacity(type_ids_size);
        for i in 0..type_ids_size {
            let off = type_ids_off + i * 4;
            if off + 4 > data.len() {
                type_string_idxs.push(0);
            } else {
                type_string_idxs.push(read_u32(data, off));
            }
        }

        // 3. Protos
        let mut protos = Vec::with_capacity(proto_ids_size);
        for i in 0..proto_ids_size {
            let off = proto_ids_off + i * 12;
            if off + 12 > data.len() {
                protos.push(DexProto {
                    return_type_idx: 0,
                    param_type_idxs: Vec::new(),
                });
                continue;
            }
            let return_type_idx = read_u32(data, off + 4);
            let params_off = read_u32(data, off + 8) as usize;
            let param_type_idxs = read_type_list(data, params_off);
            protos.push(DexProto {
                return_type_idx,
                param_type_idxs,
            });
        }

        // 4. Fields
        let mut fields = Vec::with_capacity(field_ids_size);
        for i in 0..field_ids_size {
            let off = field_ids_off + i * 8;
            if off + 8 > data.len() {
                fields.push(DexFieldId {
                    class_idx: 0,
                    type_idx: 0,
                    name_idx: 0,
                });
                continue;
            }
            fields.push(DexFieldId {
                class_idx: read_u16(data, off),
                type_idx: read_u16(data, off + 2),
                name_idx: read_u32(data, off + 4),
            });
        }

        // 5. Methods
        let mut methods = Vec::with_capacity(method_ids_size);
        for i in 0..method_ids_size {
            let off = method_ids_off + i * 8;
            if off + 8 > data.len() {
                methods.push(DexMethodId {
                    class_idx: 0,
                    proto_idx: 0,
                    name_idx: 0,
                });
                continue;
            }
            methods.push(DexMethodId {
                class_idx: read_u16(data, off),
                proto_idx: read_u16(data, off + 2),
                name_idx: read_u32(data, off + 4),
            });
        }

        // 6. Optional CallSites & MethodHandles from map_list
        let call_site_targets = parse_call_sites(data, map_off);

        // 7. ClassDefs
        let mut classes = Vec::with_capacity(class_defs_size);
        for i in 0..class_defs_size {
            let off = class_defs_off + i * 32;
            if off + 32 > data.len() {
                break;
            }
            let class_idx = read_u32(data, off);
            let access_flags = read_u32(data, off + 4);
            let superclass_raw = read_u32(data, off + 8);
            let superclass_idx = if superclass_raw == 0xFFFFFFFF {
                None
            } else {
                Some(superclass_raw)
            };
            let interfaces_off = read_u32(data, off + 12) as usize;
            let interface_idxs = read_type_list(data, interfaces_off);
            let source_raw = read_u32(data, off + 16);
            let source_file_idx = if source_raw == 0xFFFFFFFF {
                None
            } else {
                Some(source_raw)
            };
            let annotations_off = read_u32(data, off + 20) as usize;
            let class_data_off = read_u32(data, off + 24) as usize;
            let static_values_off = read_u32(data, off + 28) as usize;

            let static_inits = read_encoded_array(data, static_values_off);
            let (mut static_fields, instance_fields, direct_methods, virtual_methods) =
                if class_data_off > 0 && class_data_off < data.len() {
                    read_class_data(data, class_data_off)
                } else {
                    (Vec::new(), Vec::new(), Vec::new(), Vec::new())
                };

            for (idx, val) in static_inits.into_iter().enumerate() {
                if let Some(sf) = static_fields.get_mut(idx) {
                    sf.initial_value = Some(val);
                }
            }

            let (
                annotation_types,
                method_annotations,
                field_annotations,
                annotation_type_refs,
                enclosing_class_idx,
                inner_class_idxs,
            ) = if annotations_off > 0 && annotations_off < data.len() {
                read_annotations_dir(data, annotations_off, &strings, &type_string_idxs)
            } else {
                (
                    Vec::new(),
                    HashMap::new(),
                    HashMap::new(),
                    Vec::new(),
                    None,
                    Vec::new(),
                )
            };

            classes.push(DexClassDef {
                class_idx,
                access_flags,
                superclass_idx,
                interface_idxs,
                source_file_idx,
                static_fields,
                instance_fields,
                direct_methods,
                virtual_methods,
                annotation_types,
                method_annotations,
                field_annotations,
                annotation_type_refs,
                enclosing_class_idx,
                inner_class_idxs,
            });
        }

        Ok(ParsedDex {
            strings,
            type_string_idxs,
            protos,
            fields,
            methods,
            classes,
            call_site_targets,
        })
    }

    pub fn get_string(&self, idx: u32) -> &str {
        self.strings
            .get(idx as usize)
            .map(|s| s.as_str())
            .unwrap_or("")
    }

    pub fn get_type_desc(&self, type_idx: u32) -> &str {
        let Some(&sidx) = self.type_string_idxs.get(type_idx as usize) else {
            return "";
        };
        self.get_string(sidx)
    }

    pub fn get_proto_descriptor(&self, proto_idx: u16) -> String {
        let Some(proto) = self.protos.get(proto_idx as usize) else {
            return "()V".to_string();
        };
        let mut out = String::from("(");
        for &p in &proto.param_type_idxs {
            out.push_str(self.get_type_desc(p));
        }
        out.push(')');
        out.push_str(self.get_type_desc(proto.return_type_idx));
        out
    }
}

pub fn descriptor_to_raw_class(desc: &str) -> Option<String> {
    if desc.starts_with('L') && desc.ends_with(';') && desc.len() > 2 {
        Some(desc[1..desc.len() - 1].replace('/', "."))
    } else {
        None
    }
}

pub fn descriptor_base_raw_class(desc: &str) -> Option<String> {
    let trimmed = desc.trim_start_matches('[');
    descriptor_to_raw_class(trimmed)
}

pub fn parse_proto_descriptor(proto_desc: &str) -> (&str, Vec<&str>) {
    let Some(rparen) = proto_desc.find(')') else {
        return ("V", Vec::new());
    };
    let ret = &proto_desc[rparen + 1..];
    let args = if proto_desc.starts_with('(') && rparen > 1 {
        &proto_desc[1..rparen]
    } else {
        ""
    };
    let mut params = Vec::new();
    let bytes = args.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        while i < bytes.len() && bytes[i] == b'[' {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'L' {
            while i < bytes.len() && bytes[i] != b';' {
                i += 1;
            }
            if i < bytes.len() {
                i += 1;
            }
        } else if i < bytes.len() {
            i += 1;
        }
        params.push(&args[start..i]);
    }
    (ret, params)
}

pub fn descriptor_to_java_type<F>(desc: &str, mut resolve_display: F) -> String
where
    F: FnMut(&str) -> String,
{
    let mut dims = 0;
    let mut rest = desc;
    while let Some(stripped) = rest.strip_prefix('[') {
        dims += 1;
        rest = stripped;
    }
    let base = match rest {
        "V" => "void".to_string(),
        "Z" => "boolean".to_string(),
        "B" => "byte".to_string(),
        "S" => "short".to_string(),
        "C" => "char".to_string(),
        "I" => "int".to_string(),
        "J" => "long".to_string(),
        "F" => "float".to_string(),
        "D" => "double".to_string(),
        _ if rest.starts_with('L') && rest.ends_with(';') && rest.len() > 2 => {
            let raw = rest[1..rest.len() - 1].replace('/', ".");
            resolve_display(&raw)
        }
        _ => rest.to_string(),
    };
    if dims == 0 {
        base
    } else {
        format!("{}{}", base, "[]".repeat(dims))
    }
}

fn parse_call_sites(data: &[u8], map_off: usize) -> HashMap<u32, u32> {
    let mut result = HashMap::new();
    if map_off == 0 || map_off + 4 > data.len() {
        return result;
    }
    let map_size = read_u32(data, map_off) as usize;
    let mut call_site_ids_off = 0usize;
    let mut call_site_ids_size = 0usize;
    let mut method_handles_off = 0usize;
    let mut method_handles_size = 0usize;

    for i in 0..map_size {
        let moff = map_off + 4 + i * 12;
        if moff + 12 > data.len() {
            break;
        }
        let item_type = read_u16(data, moff);
        let item_size = read_u32(data, moff + 4) as usize;
        let item_off = read_u32(data, moff + 8) as usize;
        if item_type == 0x0007 {
            call_site_ids_size = item_size;
            call_site_ids_off = item_off;
        } else if item_type == 0x0008 {
            method_handles_size = item_size;
            method_handles_off = item_off;
        }
    }

    if call_site_ids_off == 0 || method_handles_off == 0 {
        return result;
    }

    // Parse method_handles: each is 8 bytes: u16 type, u16 unused, u16 field_or_method_id, u16 unused
    let mut handle_to_method: Vec<Option<u32>> = Vec::with_capacity(method_handles_size);
    for i in 0..method_handles_size {
        let hoff = method_handles_off + i * 8;
        if hoff + 8 > data.len() {
            handle_to_method.push(None);
            continue;
        }
        let htype = read_u16(data, hoff);
        let id = read_u16(data, hoff + 4) as u32;
        if htype >= 0x04 && htype <= 0x08 {
            handle_to_method.push(Some(id));
        } else {
            handle_to_method.push(None);
        }
    }

    for cs_idx in 0..call_site_ids_size {
        let coff = call_site_ids_off + cs_idx * 4;
        if coff + 4 > data.len() {
            break;
        }
        let cs_off = read_u32(data, coff) as usize;
        if cs_off == 0 || cs_off >= data.len() {
            continue;
        }
        // call_site_item is an encoded_array_item; 5th element (index 4) is VALUE_METHOD_HANDLE (0x16)
        let mut p = cs_off;
        let count = read_uleb128(data, &mut p) as usize;
        for elem_idx in 0..count {
            if p >= data.len() {
                break;
            }
            let header = data[p];
            p += 1;
            let val_type = header & 0x1f;
            let val_arg = (header >> 5) as usize;
            let byte_count = val_arg + 1;
            if val_type == 0x16 && elem_idx == 4 {
                let handle_idx = read_uint_var(data, p, byte_count) as usize;
                if let Some(Some(m_idx)) = handle_to_method.get(handle_idx) {
                    result.insert(cs_idx as u32, *m_idx);
                }
                break;
            }
            skip_encoded_value_body(data, &mut p, val_type, val_arg);
        }
    }

    result
}

fn read_class_data(
    data: &[u8],
    offset: usize,
) -> (
    Vec<DexFieldDef>,
    Vec<DexFieldDef>,
    Vec<DexMethodDef>,
    Vec<DexMethodDef>,
) {
    let mut p = offset;
    let static_fields_size = read_uleb128(data, &mut p) as usize;
    let instance_fields_size = read_uleb128(data, &mut p) as usize;
    let direct_methods_size = read_uleb128(data, &mut p) as usize;
    let virtual_methods_size = read_uleb128(data, &mut p) as usize;

    let mut static_fields = Vec::with_capacity(static_fields_size.min(65536));
    let mut field_idx = 0u32;
    for _ in 0..static_fields_size {
        if p >= data.len() {
            break;
        }
        field_idx = field_idx.wrapping_add(read_uleb128(data, &mut p));
        let access_flags = read_uleb128(data, &mut p);
        static_fields.push(DexFieldDef {
            field_idx,
            access_flags,
            initial_value: None,
        });
    }

    let mut instance_fields = Vec::with_capacity(instance_fields_size.min(65536));
    field_idx = 0;
    for _ in 0..instance_fields_size {
        if p >= data.len() {
            break;
        }
        field_idx = field_idx.wrapping_add(read_uleb128(data, &mut p));
        let access_flags = read_uleb128(data, &mut p);
        instance_fields.push(DexFieldDef {
            field_idx,
            access_flags,
            initial_value: None,
        });
    }

    let direct_methods = read_encoded_methods(data, &mut p, direct_methods_size);
    let virtual_methods = read_encoded_methods(data, &mut p, virtual_methods_size);

    (
        static_fields,
        instance_fields,
        direct_methods,
        virtual_methods,
    )
}

fn read_encoded_methods(data: &[u8], p: &mut usize, count: usize) -> Vec<DexMethodDef> {
    let mut out = Vec::with_capacity(count.min(65536));
    let mut method_idx = 0u32;
    for _ in 0..count {
        if *p >= data.len() {
            break;
        }
        method_idx = method_idx.wrapping_add(read_uleb128(data, p));
        let access_flags = read_uleb128(data, p);
        let code_off = read_uleb128(data, p);

        let mut registers_size = 0u16;
        let mut ins_size = 0u16;
        let mut outs_size = 0u16;
        let mut insns_off = 0u32;
        let mut insns_size_units = 0u32;
        let mut tries = Vec::new();

        let coff = code_off as usize;
        if coff > 0 && coff + 16 <= data.len() {
            registers_size = read_u16(data, coff);
            ins_size = read_u16(data, coff + 2);
            outs_size = read_u16(data, coff + 4);
            let tries_size = read_u16(data, coff + 6) as usize;
            insns_size_units = read_u32(data, coff + 12);
            insns_off = (coff + 16) as u32;

            if tries_size > 0 {
                let insns_end = coff + 16 + (insns_size_units as usize) * 2;
                let tries_start = if (insns_size_units & 1) != 0 {
                    insns_end + 2
                } else {
                    insns_end
                };
                let handlers_base = tries_start + tries_size * 8;
                if handlers_base <= data.len() {
                    for t in 0..tries_size {
                        let toff = tries_start + t * 8;
                        let start_unit = read_u32(data, toff);
                        let insn_count = read_u16(data, toff + 4);
                        let handler_off = read_u16(data, toff + 6) as usize;
                        let mut hp = handlers_base + handler_off;
                        let mut handlers = Vec::new();
                        if hp < data.len() {
                            let sz = read_sleb128(data, &mut hp);
                            let num_typed = sz.unsigned_abs() as usize;
                            for _ in 0..num_typed.min(64) {
                                if hp >= data.len() {
                                    break;
                                }
                                let tidx = read_uleb128(data, &mut hp);
                                let addr = read_uleb128(data, &mut hp);
                                handlers.push((Some(tidx), addr));
                            }
                            if sz <= 0 && hp < data.len() {
                                let catch_all_addr = read_uleb128(data, &mut hp);
                                handlers.push((None, catch_all_addr));
                            }
                        }
                        tries.push(TryBlock {
                            start_unit,
                            insn_count,
                            handlers,
                        });
                    }
                }
            }
        }

        out.push(DexMethodDef {
            method_idx,
            access_flags,
            code_off,
            registers_size,
            ins_size,
            outs_size,
            insns_off,
            insns_size_units,
            tries,
        });
    }
    out
}

fn read_encoded_array(data: &[u8], offset: usize) -> Vec<EncodedValue> {
    if offset == 0 || offset >= data.len() {
        return Vec::new();
    }
    let mut p = offset;
    let size = read_uleb128(data, &mut p) as usize;
    let mut out = Vec::with_capacity(size.min(4096));
    for _ in 0..size {
        if let Some(val) = read_encoded_value(data, &mut p) {
            out.push(val);
        } else {
            break;
        }
    }
    out
}

fn read_encoded_value(data: &[u8], p: &mut usize) -> Option<EncodedValue> {
    if *p >= data.len() {
        return None;
    }
    let header = data[*p];
    *p += 1;
    let val_type = header & 0x1f;
    let val_arg = (header >> 5) as usize;
    let n = val_arg + 1;

    match val_type {
        0x00 => {
            let v = read_sint_var(data, *p, 1) as i8;
            *p += 1;
            Some(EncodedValue::Byte(v))
        }
        0x02 => {
            let v = read_sint_var(data, *p, n) as i16;
            *p += n;
            Some(EncodedValue::Short(v))
        }
        0x03 => {
            let v = read_uint_var(data, *p, n) as u16;
            *p += n;
            Some(EncodedValue::Char(v))
        }
        0x04 => {
            let v = read_sint_var(data, *p, n) as i32;
            *p += n;
            Some(EncodedValue::Int(v))
        }
        0x06 => {
            let v = read_sint_var(data, *p, n);
            *p += n;
            Some(EncodedValue::Long(v))
        }
        0x10 => {
            let v = read_float_var(data, *p, n);
            *p += n;
            Some(EncodedValue::Float(v))
        }
        0x11 => {
            let v = read_double_var(data, *p, n);
            *p += n;
            Some(EncodedValue::Double(v))
        }
        0x17 => {
            let idx = read_uint_var(data, *p, n) as u32;
            *p += n;
            Some(EncodedValue::String(idx))
        }
        0x18 => {
            let idx = read_uint_var(data, *p, n) as u32;
            *p += n;
            Some(EncodedValue::Type(idx))
        }
        0x19 => {
            let idx = read_uint_var(data, *p, n) as u32;
            *p += n;
            Some(EncodedValue::Field(idx))
        }
        0x1a => {
            let idx = read_uint_var(data, *p, n) as u32;
            *p += n;
            Some(EncodedValue::Method(idx))
        }
        0x1b => {
            let idx = read_uint_var(data, *p, n) as u32;
            *p += n;
            Some(EncodedValue::Enum(idx))
        }
        0x1e => Some(EncodedValue::Null),
        0x1f => Some(EncodedValue::Boolean(val_arg != 0)),
        _ => {
            skip_encoded_value_body(data, p, val_type, val_arg);
            Some(EncodedValue::Null)
        }
    }
}

fn skip_encoded_value_body(data: &[u8], p: &mut usize, val_type: u8, val_arg: usize) {
    match val_type {
        0x00 => *p = (*p + 1).min(data.len()),
        0x02 | 0x03 | 0x04 | 0x06 | 0x10 | 0x11 | 0x15 | 0x16 | 0x17 | 0x18 | 0x19 | 0x1a
        | 0x1b => {
            *p = (*p + val_arg + 1).min(data.len());
        }
        0x1c => {
            let sz = read_uleb128(data, p) as usize;
            for _ in 0..sz {
                if *p >= data.len() {
                    break;
                }
                let h = data[*p];
                *p += 1;
                skip_encoded_value_body(data, p, h & 0x1f, (h >> 5) as usize);
            }
        }
        0x1d => {
            let _type_idx = read_uleb128(data, p);
            let sz = read_uleb128(data, p) as usize;
            for _ in 0..sz {
                let _name_idx = read_uleb128(data, p);
                if *p >= data.len() {
                    break;
                }
                let h = data[*p];
                *p += 1;
                skip_encoded_value_body(data, p, h & 0x1f, (h >> 5) as usize);
            }
        }
        _ => {}
    }
}

fn read_annotations_dir(
    data: &[u8],
    offset: usize,
    strings: &[String],
    type_string_idxs: &[u32],
) -> (
    Vec<u32>,
    HashMap<u32, Vec<u32>>,
    HashMap<u32, Vec<u32>>,
    Vec<u32>,
    Option<u32>,
    Vec<u32>,
) {
    let mut class_ann_types = Vec::new();
    let mut method_annotations = HashMap::new();
    let mut field_annotations = HashMap::new();
    let mut annotation_type_refs = Vec::new();
    let mut enclosing_class_idx = None;
    let mut inner_class_idxs = Vec::new();

    if offset + 16 > data.len() {
        return (
            class_ann_types,
            method_annotations,
            field_annotations,
            annotation_type_refs,
            enclosing_class_idx,
            inner_class_idxs,
        );
    }

    let class_ann_off = read_u32(data, offset) as usize;
    let fields_size = read_u32(data, offset + 4) as usize;
    let methods_size = read_u32(data, offset + 8) as usize;
    let _params_size = read_u32(data, offset + 12) as usize;

    if class_ann_off > 0 && class_ann_off + 4 <= data.len() {
        parse_annotation_set(
            data,
            class_ann_off,
            strings,
            type_string_idxs,
            &mut class_ann_types,
            &mut annotation_type_refs,
            &mut enclosing_class_idx,
            &mut inner_class_idxs,
        );
    }

    let mut pos = offset + 16;
    for _ in 0..fields_size {
        if pos + 8 > data.len() {
            break;
        }
        let f_idx = read_u32(data, pos);
        let ann_set_off = read_u32(data, pos + 4) as usize;
        pos += 8;
        if ann_set_off > 0 && ann_set_off + 4 <= data.len() {
            let mut types = Vec::new();
            let mut dummy_enc = None;
            let mut dummy_inner = Vec::new();
            parse_annotation_set(
                data,
                ann_set_off,
                strings,
                type_string_idxs,
                &mut types,
                &mut annotation_type_refs,
                &mut dummy_enc,
                &mut dummy_inner,
            );
            if !types.is_empty() {
                field_annotations.insert(f_idx, types);
            }
        }
    }

    for _ in 0..methods_size {
        if pos + 8 > data.len() {
            break;
        }
        let m_idx = read_u32(data, pos);
        let ann_set_off = read_u32(data, pos + 4) as usize;
        pos += 8;
        if ann_set_off > 0 && ann_set_off + 4 <= data.len() {
            let mut types = Vec::new();
            let mut dummy_enc = None;
            let mut dummy_inner = Vec::new();
            parse_annotation_set(
                data,
                ann_set_off,
                strings,
                type_string_idxs,
                &mut types,
                &mut annotation_type_refs,
                &mut dummy_enc,
                &mut dummy_inner,
            );
            if !types.is_empty() {
                method_annotations.insert(m_idx, types);
            }
        }
    }

    (
        class_ann_types,
        method_annotations,
        field_annotations,
        annotation_type_refs,
        enclosing_class_idx,
        inner_class_idxs,
    )
}

fn parse_annotation_set(
    data: &[u8],
    set_off: usize,
    strings: &[String],
    type_string_idxs: &[u32],
    ann_types: &mut Vec<u32>,
    type_refs: &mut Vec<u32>,
    enclosing_class: &mut Option<u32>,
    inner_classes: &mut Vec<u32>,
) {
    if set_off + 4 > data.len() {
        return;
    }
    let size = read_u32(data, set_off) as usize;
    for i in 0..size.min(1024) {
        let entry_off = set_off + 4 + i * 4;
        if entry_off + 4 > data.len() {
            break;
        }
        let item_off = read_u32(data, entry_off) as usize;
        if item_off == 0 || item_off + 2 > data.len() {
            continue;
        }
        let mut p = item_off + 1; // skip visibility byte
        let type_idx = read_uleb128(data, &mut p);
        let num_elems = read_uleb128(data, &mut p) as usize;
        ann_types.push(type_idx);
        type_refs.push(type_idx);

        let ann_desc = type_string_idxs
            .get(type_idx as usize)
            .and_then(|&sidx| strings.get(sidx as usize))
            .map(|s| s.as_str())
            .unwrap_or("");

        for _ in 0..num_elems.min(256) {
            if p >= data.len() {
                break;
            }
            let _name_idx = read_uleb128(data, &mut p);
            if p >= data.len() {
                break;
            }
            if ann_desc == "Ldalvik/annotation/EnclosingClass;" {
                if let Some(EncodedValue::Type(t)) = read_encoded_value(data, &mut p) {
                    *enclosing_class = Some(t);
                    type_refs.push(t);
                }
            } else if ann_desc == "Ldalvik/annotation/MemberClasses;" {
                let h = data[p];
                p += 1;
                if (h & 0x1f) == 0x1c {
                    let arr_sz = read_uleb128(data, &mut p) as usize;
                    for _ in 0..arr_sz.min(4096) {
                        if let Some(EncodedValue::Type(t)) = read_encoded_value(data, &mut p) {
                            inner_classes.push(t);
                            type_refs.push(t);
                        }
                    }
                } else {
                    skip_encoded_value_body(data, &mut p, h & 0x1f, (h >> 5) as usize);
                }
            } else {
                let h = data[p];
                p += 1;
                if (h & 0x1f) == 0x18 {
                    let n = ((h >> 5) as usize) + 1;
                    let t = read_uint_var(data, p, n) as u32;
                    p += n;
                    type_refs.push(t);
                } else {
                    skip_encoded_value_body(data, &mut p, h & 0x1f, (h >> 5) as usize);
                }
            }
        }
    }
}

fn read_type_list(data: &[u8], offset: usize) -> Vec<u32> {
    if offset == 0 || offset + 4 > data.len() {
        return Vec::new();
    }
    let size = read_u32(data, offset) as usize;
    let mut out = Vec::with_capacity(size.min(4096));
    for i in 0..size {
        let pos = offset + 4 + i * 2;
        if pos + 2 > data.len() {
            break;
        }
        out.push(read_u16(data, pos) as u32);
    }
    out
}

fn read_dex_string(data: &[u8], offset: usize) -> String {
    if offset == 0 || offset >= data.len() {
        return String::new();
    }
    let mut p = offset;
    let _utf16_len = read_uleb128(data, &mut p);
    let start = p;
    while p < data.len() && data[p] != 0 {
        p += 1;
    }
    decode_mutf8(&data[start..p])
}

fn decode_mutf8(bytes: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }
    // Decode MUTF-8 into UTF-16 code units then String
    let mut u16_units = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i];
        if (b0 & 0x80) == 0 {
            u16_units.push(b0 as u16);
            i += 1;
        } else if (b0 & 0xe0) == 0xc0 && i + 1 < bytes.len() {
            let b1 = bytes[i + 1];
            let ch = (((b0 & 0x1f) as u16) << 6) | ((b1 & 0x3f) as u16);
            u16_units.push(ch);
            i += 2;
        } else if (b0 & 0xf0) == 0xe0 && i + 2 < bytes.len() {
            let b1 = bytes[i + 1];
            let b2 = bytes[i + 2];
            let ch = (((b0 & 0x0f) as u16) << 12)
                | (((b1 & 0x3f) as u16) << 6)
                | ((b2 & 0x3f) as u16);
            u16_units.push(ch);
            i += 3;
        } else {
            u16_units.push(0xFFFD);
            i += 1;
        }
    }
    String::from_utf16_lossy(&u16_units)
}

pub fn read_uleb128(data: &[u8], pos: &mut usize) -> u32 {
    let mut result = 0u32;
    let mut shift = 0;
    while *pos < data.len() {
        let b = data[*pos];
        *pos += 1;
        result |= ((b & 0x7f) as u32) << shift;
        if (b & 0x80) == 0 || shift >= 28 {
            break;
        }
        shift += 7;
    }
    result
}

pub fn read_sleb128(data: &[u8], pos: &mut usize) -> i32 {
    let mut result = 0i32;
    let mut shift = 0;
    let mut last_byte = 0u8;
    while *pos < data.len() {
        last_byte = data[*pos];
        *pos += 1;
        result |= ((last_byte & 0x7f) as i32) << shift;
        shift += 7;
        if (last_byte & 0x80) == 0 || shift >= 32 {
            break;
        }
    }
    if shift < 32 && (last_byte & 0x40) != 0 {
        result |= !0 << shift;
    }
    result
}

fn read_uint_var(data: &[u8], pos: usize, n: usize) -> u64 {
    let mut val = 0u64;
    for i in 0..n.min(8) {
        if pos + i < data.len() {
            val |= (data[pos + i] as u64) << (i * 8);
        }
    }
    val
}

fn read_sint_var(data: &[u8], pos: usize, n: usize) -> i64 {
    let u = read_uint_var(data, pos, n);
    let shift = (8 - n.min(8)) * 8;
    ((u << shift) as i64) >> shift
}

fn read_float_var(data: &[u8], pos: usize, n: usize) -> f32 {
    let mut bytes = [0u8; 4];
    let count = n.min(4);
    for i in 0..count {
        if pos + i < data.len() {
            bytes[4 - count + i] = data[pos + i];
        }
    }
    f32::from_le_bytes(bytes)
}

fn read_double_var(data: &[u8], pos: usize, n: usize) -> f64 {
    let mut bytes = [0u8; 8];
    let count = n.min(8);
    for i in 0..count {
        if pos + i < data.len() {
            bytes[8 - count + i] = data[pos + i];
        }
    }
    f64::from_le_bytes(bytes)
}

fn read_u16(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() {
        0
    } else {
        u16::from_le_bytes([data[off], data[off + 1]])
    }
}

fn read_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        0
    } else {
        u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
    }
}
