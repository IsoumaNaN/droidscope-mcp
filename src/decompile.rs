use std::collections::{BTreeSet, HashMap, HashSet};

use crate::dex::{
    decode_instructions, descriptor_to_raw_class, opcode_info, parse_proto_descriptor, DecodedInsn,
    InsnFormat, RefKind,
};
use crate::index::{ApkIndex, ClassInfoEntry, LiteralValue, MethodInfoEntry};

pub fn disassemble_class_smali(apk: &ApkIndex, cls_id: usize) -> String {
    let mut out = String::with_capacity(4096);
    disassemble_single_class_smali(apk, cls_id, &mut out);
    for &inner_id in &apk.classes[cls_id].inner_cls_ids {
        out.push('\n');
        disassemble_single_class_smali(apk, inner_id, &mut out);
    }
    out
}

fn disassemble_single_class_smali(apk: &ApkIndex, cls_id: usize, out: &mut String) {
    let cls = &apk.classes[cls_id];
    out.push_str(&format!(
        "###### Class {} ({})\n",
        cls.display_name, cls.raw_name
    ));
    out.push_str(&format!(
        ".class {}{}\n",
        smali_access_flags(cls.access_flags, true),
        cls.desc
    ));
    if let Some(ref sr) = cls.super_raw_name {
        out.push_str(&format!(".super L{};\n", sr.replace('.', "/")));
    } else {
        out.push_str(".super Ljava/lang/Object;\n");
    }
    if let Some(ref src) = cls.source_file {
        out.push_str(&format!(".source \"{}\"\n", escape_java_str(src)));
    }
    for ir in &cls.interface_raw_names {
        out.push_str(&format!(".implements L{};\n", ir.replace('.', "/")));
    }

    if !cls.field_ids.is_empty() {
        out.push_str("\n# fields\n");
        for &fid in &cls.field_ids {
            let f = &apk.fields[fid];
            out.push_str(&format!(
                ".field {}{}:{}",
                smali_access_flags(f.access_flags, false),
                f.name,
                f.type_desc
            ));
            if let Some(ref iv) = f.initial_value {
                out.push_str(" = ");
                out.push_str(&format_literal_smali(iv));
            }
            out.push('\n');
        }
    }

    if !cls.method_ids.is_empty() {
        out.push_str("\n# methods\n");
        for &mid in &cls.method_ids {
            let m = &apk.methods[mid];
            out.push('\n');
            disassemble_one_method_smali(apk, m, out);
        }
    }
}

pub fn disassemble_method_smali(
    apk: &ApkIndex,
    cls_id: usize,
    method_name: &str,
    signature: Option<&str>,
) -> Option<String> {
    let targets = apk.resolve_methods(cls_id, method_name, signature);
    if targets.is_empty() {
        return None;
    }
    let mut out = String::new();
    if let Some(amb) = apk.ambiguity_notice(method_name, &targets) {
        out.push_str(&amb);
        out.push_str("\n\n");
    }
    for &mid in &targets {
        let m = &apk.methods[mid];
        disassemble_one_method_smali(apk, m, &mut out);
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn disassemble_one_method_smali(apk: &ApkIndex, mth: &MethodInfoEntry, out: &mut String) {
    out.push_str(&format!(
        ".method {}{}\n",
        smali_method_flags(mth.access_flags),
        mth.short_id()
    ));
    let insns_bytes = apk.method_insns_slice(mth);
    if !insns_bytes.is_empty() {
        out.push_str(&format!("    .registers {}\n\n", mth.registers_size));
        let dt = &apk.dex_tables[mth.dex_idx];
        let insns = decode_instructions(insns_bytes);

        let mut labels = HashSet::new();
        for insn in &insns {
            if matches!(
                insn.format,
                InsnFormat::F10t
                    | InsnFormat::F20t
                    | InsnFormat::F30t
                    | InsnFormat::F21t
                    | InsnFormat::F22t
                    | InsnFormat::F31t
            ) && insn.target_units >= 0
            {
                labels.insert(insn.target_units as u32);
            }
        }
        for tb in &mth.tries {
            labels.insert(tb.start_unit);
            labels.insert(tb.start_unit + (tb.insn_count as u32));
            for (_, h_addr) in &tb.handlers {
                labels.insert(*h_addr);
            }
        }

        for insn in &insns {
            if labels.contains(&insn.offset_units) {
                out.push_str(&format!("    :label_{:x}\n", insn.offset_units));
            }
            for (t_idx, tb) in mth.tries.iter().enumerate() {
                if insn.offset_units == tb.start_unit {
                    out.push_str(&format!("    :try_start_{}\n", t_idx));
                }
            }
            out.push_str("    ");
            format_smali_insn(apk, mth, dt, insn, out);
            out.push('\n');
            let next_unit = insn.offset_units + (opcode_info(insn.opcode).units() as u32);
            for (t_idx, tb) in mth.tries.iter().enumerate() {
                let end_u = tb.start_unit + (tb.insn_count as u32);
                if next_unit == end_u {
                    out.push_str(&format!("    :try_end_{}\n", t_idx));
                    for (exc_type, h_addr) in &tb.handlers {
                        match exc_type {
                            Some(et) => out.push_str(&format!(
                                "    .catch L{}; {{:try_start_{} .. :try_end_{}}} :label_{:x}\n",
                                et.replace('.', "/"),
                                t_idx,
                                t_idx,
                                h_addr
                            )),
                            None => out.push_str(&format!(
                                "    .catchall {{:try_start_{} .. :try_end_{}}} :label_{:x}\n",
                                t_idx, t_idx, h_addr
                            )),
                        }
                    }
                }
            }
        }
    }
    out.push_str(".end method\n");
}

fn format_smali_insn(
    _apk: &ApkIndex,
    mth: &MethodInfoEntry,
    dt: &crate::index::DexTables,
    insn: &DecodedInsn,
    out: &mut String,
) {
    let info = opcode_info(insn.opcode);
    out.push_str(info.name);
    let reg_name = |r: u16| -> String {
        let first_param = mth.registers_size.saturating_sub(mth.ins_size);
        if r >= first_param {
            format!("p{}", r - first_param)
        } else {
            format!("v{}", r)
        }
    };

    let ref_str = match insn.ref_kind {
        RefKind::StringRef => {
            let s = dt
                .strings
                .get(insn.index as usize)
                .map(|s| s.as_str())
                .unwrap_or("");
            format!("\"{}\"", escape_java_str(s))
        }
        RefKind::TypeRef => dt
            .type_descs
            .get(insn.index as usize)
            .cloned()
            .unwrap_or_else(|| "Ljava/lang/Object;".to_string()),
        RefKind::FieldRef => {
            if let Some((cls_raw, ftype, fname)) = dt.fields.get(insn.index as usize) {
                format!("L{};->{}:{}", cls_raw.replace('.', "/"), fname, ftype)
            } else {
                format!("field@{}", insn.index)
            }
        }
        RefKind::MethodRef | RefKind::MethodAndProtoRef => {
            if let Some((cls_raw, mname, pdesc)) = dt.methods.get(insn.index as usize) {
                format!("L{};->{}{}", cls_raw.replace('.', "/"), mname, pdesc)
            } else {
                format!("method@{}", insn.index)
            }
        }
        RefKind::CallSiteRef => format!("call_site@{}", insn.index),
        _ => String::new(),
    };

    match info.format {
        InsnFormat::F10x => {}
        InsnFormat::F12x | InsnFormat::F22x | InsnFormat::F32x => {
            out.push_str(&format!(
                " {}, {}",
                reg_name(insn.reg_a),
                reg_name(insn.reg_b)
            ));
        }
        InsnFormat::F11n | InsnFormat::F21s | InsnFormat::F21h | InsnFormat::F31i | InsnFormat::F51l => {
            out.push_str(&format!(" {}, 0x{:x}", reg_name(insn.reg_a), insn.literal));
        }
        InsnFormat::F11x => {
            out.push_str(&format!(" {}", reg_name(insn.reg_a)));
        }
        InsnFormat::F10t | InsnFormat::F20t | InsnFormat::F30t => {
            out.push_str(&format!(" :label_{:x}", insn.target_units.max(0)));
        }
        InsnFormat::F21t | InsnFormat::F31t => {
            out.push_str(&format!(
                " {}, :label_{:x}",
                reg_name(insn.reg_a),
                insn.target_units.max(0)
            ));
        }
        InsnFormat::F22t => {
            out.push_str(&format!(
                " {}, {}, :label_{:x}",
                reg_name(insn.reg_a),
                reg_name(insn.reg_b),
                insn.target_units.max(0)
            ));
        }
        InsnFormat::F21c | InsnFormat::F31c => {
            out.push_str(&format!(" {}, {}", reg_name(insn.reg_a), ref_str));
        }
        InsnFormat::F22c => {
            out.push_str(&format!(
                " {}, {}, {}",
                reg_name(insn.reg_a),
                reg_name(insn.reg_b),
                ref_str
            ));
        }
        InsnFormat::F23x => {
            out.push_str(&format!(
                " {}, {}, {}",
                reg_name(insn.reg_a),
                reg_name(insn.reg_b),
                reg_name(insn.reg_c)
            ));
        }
        InsnFormat::F22b | InsnFormat::F22s => {
            out.push_str(&format!(
                " {}, {}, 0x{:x}",
                reg_name(insn.reg_a),
                reg_name(insn.reg_b),
                insn.literal
            ));
        }
        InsnFormat::F35c | InsnFormat::F3rc | InsnFormat::F45cc | InsnFormat::F4rcc => {
            let regs_str: Vec<String> = insn.regs.iter().map(|&r| reg_name(r)).collect();
            out.push_str(&format!(" {{{}}}, {}", regs_str.join(", "), ref_str));
        }
        InsnFormat::F20bc => {
            out.push_str(&format!(" {}, {}", insn.literal, ref_str));
        }
    }
}

// =============================================================================
// Structured Dalvik-to-Java Decompiler
// =============================================================================

pub fn decompile_class_java(apk: &ApkIndex, cls_id: usize) -> String {
    let cls = &apk.classes[cls_id];
    let pkg = match cls.display_name.rfind('.') {
        Some(dot) => &cls.display_name[..dot],
        None => "",
    };

    let mut out = String::with_capacity(4096);
    if !pkg.is_empty() {
        out.push_str(&format!("package {};\n\n", pkg));
    }

    // Collect imports from superclass, interfaces, fields, and method signatures
    let mut imports = BTreeSet::new();
    collect_class_imports(apk, cls, pkg, &mut imports);
    for &icid in &cls.inner_cls_ids {
        collect_class_imports(apk, &apk.classes[icid], pkg, &mut imports);
    }
    if !imports.is_empty() {
        for imp in &imports {
            out.push_str(&format!("import {};\n", imp));
        }
        out.push('\n');
    }

    render_java_class_body(apk, cls_id, 0, &mut out);
    out
}

fn collect_class_imports(
    apk: &ApkIndex,
    cls: &ClassInfoEntry,
    current_pkg: &str,
    imports: &mut BTreeSet<String>,
) {
    let mut maybe_add = |raw: &str| {
        let disp = apk.display_name_of_raw(raw);
        if let Some(dot) = disp.rfind('.') {
            let p = &disp[..dot];
            if !p.is_empty() && p != "java.lang" && p != current_pkg && !disp.contains('$') {
                imports.insert(disp);
            }
        }
    };
    if let Some(ref sr) = cls.super_raw_name {
        if sr != "java.lang.Object" {
            maybe_add(sr);
        }
    }
    for ir in &cls.interface_raw_names {
        maybe_add(ir);
    }
    for &fid in &cls.field_ids {
        if let Some(raw) = descriptor_to_raw_class(apk.fields[fid].type_desc.trim_start_matches('['))
        {
            maybe_add(&raw);
        }
    }
    for &mid in &cls.method_ids {
        let m = &apk.methods[mid];
        if let Some(raw) = descriptor_to_raw_class(m.return_type_desc().trim_start_matches('[')) {
            maybe_add(&raw);
        }
        for pd in m.param_type_descs() {
            if let Some(raw) = descriptor_to_raw_class(pd.trim_start_matches('[')) {
                maybe_add(&raw);
            }
        }
    }
}

fn render_java_class_body(apk: &ApkIndex, cls_id: usize, indent: usize, out: &mut String) {
    let cls = &apk.classes[cls_id];
    let pad = "    ".repeat(indent);

    for ann in &cls.annotations {
        if !ann.starts_with("dalvik.annotation.") && !ann.starts_with("kotlin.Metadata") {
            out.push_str(&format!("{}@{}\n", pad, short_type_name(ann)));
        }
    }

    let simple_name = simple_class_name(cls);
    let is_iface = (cls.access_flags & 0x0200) != 0;
    let is_enum = (cls.access_flags & 0x4000) != 0;
    let kw = if is_iface {
        "interface"
    } else if is_enum {
        "enum"
    } else {
        "class"
    };

    out.push_str(&pad);
    out.push_str(&java_class_modifiers(cls.access_flags, is_iface, is_enum));
    out.push_str(kw);
    out.push(' ');
    out.push_str(&simple_name);

    if !is_iface && !is_enum {
        if let Some(ref sr) = cls.super_raw_name {
            if sr != "java.lang.Object" {
                let disp = apk.display_name_of_raw(sr);
                out.push_str(" extends ");
                out.push_str(&short_type_name(&disp));
            }
        }
    }
    if !cls.interface_raw_names.is_empty() {
        let iface_names: Vec<String> = cls
            .interface_raw_names
            .iter()
            .map(|ir| short_type_name(&apk.display_name_of_raw(ir)))
            .collect();
        out.push_str(if is_iface { " extends " } else { " implements " });
        out.push_str(&iface_names.join(", "));
    }
    out.push_str(" {\n");

    let member_pad = "    ".repeat(indent + 1);
    for &fid in &cls.field_ids {
        let f = &apk.fields[fid];
        for ann in &f.annotations {
            if !ann.starts_with("dalvik.annotation.") {
                out.push_str(&format!("{}@{}\n", member_pad, short_type_name(ann)));
            }
        }
        let ftype = short_type_name(&apk.format_java_type(&f.type_desc));
        out.push_str(&member_pad);
        out.push_str(&java_field_modifiers(f.access_flags));
        out.push_str(&ftype);
        out.push(' ');
        out.push_str(&f.alias);
        if let Some(ref iv) = f.initial_value {
            out.push_str(" = ");
            out.push_str(&format_literal_java(iv, &f.type_desc));
        }
        out.push_str(";\n");
    }

    if !cls.field_ids.is_empty() && !cls.method_ids.is_empty() {
        out.push('\n');
    }

    for (idx, &mid) in cls.method_ids.iter().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        let m_src = decompile_method_java_indented(apk, cls_id, mid, indent + 1);
        out.push_str(&m_src);
        if !m_src.ends_with('\n') {
            out.push('\n');
        }
    }

    for &icid in &cls.inner_cls_ids {
        out.push('\n');
        render_java_class_body(apk, icid, indent + 1, out);
    }

    out.push_str(&pad);
    out.push_str("}\n");
}

pub fn decompile_method_java(apk: &ApkIndex, cls_id: usize, mth_id: usize) -> String {
    decompile_method_java_indented(apk, cls_id, mth_id, 1)
}

fn decompile_method_java_indented(
    apk: &ApkIndex,
    cls_id: usize,
    mth_id: usize,
    indent: usize,
) -> String {
    let cls = &apk.classes[cls_id];
    let mth = &apk.methods[mth_id];
    let pad = "    ".repeat(indent);
    let body_pad = "    ".repeat(indent + 1);
    let mut out = String::new();

    for ann in &mth.annotations {
        if !ann.starts_with("dalvik.annotation.") {
            out.push_str(&format!("{}@{}\n", pad, short_type_name(ann)));
        }
    }

    let is_static = (mth.access_flags & 0x0008) != 0;
    let is_native = (mth.access_flags & 0x0100) != 0;
    let is_abstract = (mth.access_flags & 0x0400) != 0;

    // Build parameter register map and declaration signature
    let mut reg_expr: HashMap<u16, String> = HashMap::new();
    let mut declared_regs: HashSet<u16> = HashSet::new();
    let first_in_reg = mth.registers_size.saturating_sub(mth.ins_size);
    let mut cur_reg = first_in_reg;
    if !is_static {
        reg_expr.insert(cur_reg, "this".to_string());
        declared_regs.insert(cur_reg);
        cur_reg += 1;
    }

    let mut param_decls = Vec::new();
    for (p_idx, p_desc) in mth.param_type_descs().into_iter().enumerate() {
        let p_type = short_type_name(&apk.format_java_type(p_desc));
        let p_name = format!("p{}", p_idx);
        param_decls.push(format!("{} {}", p_type, p_name));
        reg_expr.insert(cur_reg, p_name.clone());
        declared_regs.insert(cur_reg);
        let width = if p_desc == "J" || p_desc == "D" { 2 } else { 1 };
        if width == 2 {
            reg_expr.insert(cur_reg + 1, p_name);
            declared_regs.insert(cur_reg + 1);
        }
        cur_reg += width;
    }

    if mth.name == "<clinit>" {
        out.push_str(&format!("{}static {{\n", pad));
    } else if mth.name == "<init>" {
        let simple = simple_class_name(cls);
        out.push_str(&format!(
            "{}{}{}({}) {{\n",
            pad,
            java_method_modifiers(mth.access_flags & !0x10000),
            simple,
            param_decls.join(", ")
        ));
    } else {
        let ret_type = short_type_name(&apk.format_java_type(mth.return_type_desc()));
        out.push_str(&format!(
            "{}{}{} {}({})",
            pad,
            java_method_modifiers(mth.access_flags),
            ret_type,
            mth.alias,
            param_decls.join(", ")
        ));
        if is_native || is_abstract || mth.insns_size_units == 0 {
            out.push_str(";\n");
            return out;
        }
        out.push_str(" {\n");
    }

    let insns_bytes = apk.method_insns_slice(mth);
    if insns_bytes.is_empty() {
        out.push_str(&format!("{}}}\n", pad));
        return out;
    }

    let dt = &apk.dex_tables[mth.dex_idx];
    let insns = decode_instructions(insns_bytes);

    // Find branch targets for label emission
    let mut branch_targets = HashSet::new();
    for insn in &insns {
        if matches!(
            insn.format,
            InsnFormat::F10t
                | InsnFormat::F20t
                | InsnFormat::F30t
                | InsnFormat::F21t
                | InsnFormat::F22t
                | InsnFormat::F31t
        ) && insn.target_units >= 0
        {
            branch_targets.insert(insn.target_units as u32);
        }
    }

    let mut pending_new_instance: HashMap<u16, String> = HashMap::new();
    let mut last_call_result: Option<(String, String)> = None; // (expr, ret_desc)
    let mut idx = 0usize;

    while idx < insns.len() {
        let insn = &insns[idx];
        let next_is_move_result = idx + 1 < insns.len()
            && matches!(insns[idx + 1].opcode, 0x0a | 0x0b | 0x0c);

        if branch_targets.contains(&insn.offset_units) {
            // Preserve register names across control-flow merge points
            out.push_str(&format!("{}// label_{:x}:\n", body_pad, insn.offset_units));
        }

        for tb in &mth.tries {
            if insn.offset_units == tb.start_unit {
                out.push_str(&format!("{}try {{\n", body_pad));
            }
        }

        let get_val = |r: u16, map: &HashMap<u16, String>| -> String {
            map.get(&r).cloned().unwrap_or_else(|| format!("v{}", r))
        };

        let bind_reg = |r: u16,
                            type_str: &str,
                            expr: String,
                            force_stmt: bool,
                            map: &mut HashMap<u16, String>,
                            decls: &mut HashSet<u16>,
                            buf: &mut String| {
            if force_stmt {
                let vname = format!("v{}", r);
                if decls.insert(r) {
                    buf.push_str(&format!("{}{} {} = {};\n", body_pad, type_str, vname, expr));
                } else {
                    buf.push_str(&format!("{}{} = {};\n", body_pad, vname, expr));
                }
                map.insert(r, expr);
            } else {
                map.insert(r, expr);
            }
        };

        match insn.opcode {
            0x00 => {}
            0x01..=0x09 => {
                let rhs = get_val(insn.reg_b, &reg_expr);
                bind_reg(
                    insn.reg_a,
                    "Object",
                    rhs,
                    branch_targets.contains(&insn.offset_units),
                    &mut reg_expr,
                    &mut declared_regs,
                    &mut out,
                );
            }
            0x0a..=0x0c => {
                if let Some((call_expr, ret_desc)) = last_call_result.take() {
                    let jtype = short_type_name(&apk.format_java_type(&ret_desc));
                    let vname = format!("v{}", insn.reg_a);
                    if declared_regs.insert(insn.reg_a) {
                        out.push_str(&format!(
                            "{}{} {} = {};\n",
                            body_pad, jtype, vname, call_expr
                        ));
                    } else {
                        out.push_str(&format!("{}{} = {};\n", body_pad, vname, call_expr));
                    }
                    reg_expr.insert(insn.reg_a, vname);
                }
            }
            0x0d => {
                let vname = format!("e{}", insn.reg_a);
                reg_expr.insert(insn.reg_a, vname);
            }
            0x0e => {
                out.push_str(&format!("{}return;\n", body_pad));
            }
            0x0f..=0x11 => {
                let mut val = get_val(insn.reg_a, &reg_expr);
                if mth.return_type_desc() == "Z" {
                    if val == "0" {
                        val = "false".to_string();
                    } else if val == "1" {
                        val = "true".to_string();
                    }
                }
                out.push_str(&format!("{}return {};\n", body_pad, val));
            }
            0x12..=0x19 => {
                reg_expr.insert(insn.reg_a, format!("{}", insn.literal));
            }
            0x1a | 0x1b => {
                let s = dt
                    .strings
                    .get(insn.index as usize)
                    .map(|s| s.as_str())
                    .unwrap_or("");
                reg_expr.insert(insn.reg_a, format!("\"{}\"", escape_java_str(s)));
            }
            0x1c => {
                let tdesc = dt
                    .type_descs
                    .get(insn.index as usize)
                    .map(|s| s.as_str())
                    .unwrap_or("Ljava/lang/Object;");
                let tname = short_type_name(&apk.format_java_type(tdesc));
                reg_expr.insert(insn.reg_a, format!("{}.class", tname));
            }
            0x1f => {
                let tdesc = dt
                    .type_descs
                    .get(insn.index as usize)
                    .map(|s| s.as_str())
                    .unwrap_or("Ljava/lang/Object;");
                let tname = short_type_name(&apk.format_java_type(tdesc));
                let cur = get_val(insn.reg_a, &reg_expr);
                reg_expr.insert(insn.reg_a, format!("(({}) {})", tname, cur));
            }
            0x20 => {
                let tdesc = dt
                    .type_descs
                    .get(insn.index as usize)
                    .map(|s| s.as_str())
                    .unwrap_or("Ljava/lang/Object;");
                let tname = short_type_name(&apk.format_java_type(tdesc));
                let obj = get_val(insn.reg_b, &reg_expr);
                reg_expr.insert(insn.reg_a, format!("({} instanceof {})", obj, tname));
            }
            0x21 => {
                let arr = get_val(insn.reg_b, &reg_expr);
                reg_expr.insert(insn.reg_a, format!("{}.length", arr));
            }
            0x22 => {
                let tdesc = dt
                    .type_descs
                    .get(insn.index as usize)
                    .map(|s| s.as_str())
                    .unwrap_or("Ljava/lang/Object;");
                let tname = short_type_name(&apk.format_java_type(tdesc));
                pending_new_instance.insert(insn.reg_a, tname);
            }
            0x23 => {
                let tdesc = dt
                    .type_descs
                    .get(insn.index as usize)
                    .map(|s| s.as_str())
                    .unwrap_or("[Ljava/lang/Object;");
                let elem_desc = tdesc.strip_prefix('[').unwrap_or(tdesc);
                let elem_type = short_type_name(&apk.format_java_type(elem_desc));
                let len_val = get_val(insn.reg_b, &reg_expr);
                reg_expr.insert(insn.reg_a, format!("new {}[{}]", elem_type, len_val));
            }
            0x27 => {
                let ex = get_val(insn.reg_a, &reg_expr);
                out.push_str(&format!("{}throw {};\n", body_pad, ex));
            }
            0x32..=0x37 => {
                let op_str = match insn.opcode {
                    0x32 => "==",
                    0x33 => "!=",
                    0x34 => "<",
                    0x35 => ">=",
                    0x36 => ">",
                    _ => "<=",
                };
                let lhs = get_val(insn.reg_a, &reg_expr);
                let rhs = get_val(insn.reg_b, &reg_expr);
                out.push_str(&format!(
                    "{}if ({} {} {}) /* goto label_{:x} */;\n",
                    body_pad,
                    lhs,
                    op_str,
                    rhs,
                    insn.target_units.max(0)
                ));
            }
            0x38..=0x3d => {
                let op_str = match insn.opcode {
                    0x38 => "==",
                    0x39 => "!=",
                    0x3a => "<",
                    0x3b => ">=",
                    0x3c => ">",
                    _ => "<=",
                };
                let lhs = get_val(insn.reg_a, &reg_expr);
                out.push_str(&format!(
                    "{}if ({} {} 0) /* goto label_{:x} */;\n",
                    body_pad,
                    lhs,
                    op_str,
                    insn.target_units.max(0)
                ));
            }
            0x44..=0x4a => {
                let arr = get_val(insn.reg_b, &reg_expr);
                let idx_e = get_val(insn.reg_c, &reg_expr);
                reg_expr.insert(insn.reg_a, format!("{}[{}]", arr, idx_e));
            }
            0x4b..=0x51 => {
                let val = get_val(insn.reg_a, &reg_expr);
                let arr = get_val(insn.reg_b, &reg_expr);
                let idx_e = get_val(insn.reg_c, &reg_expr);
                out.push_str(&format!("{}{}[{}] = {};\n", body_pad, arr, idx_e, val));
            }
            0x52..=0x58 => {
                if let Some((_, _ftype, fname)) = dt.fields.get(insn.index as usize) {
                    let obj = get_val(insn.reg_b, &reg_expr);
                    reg_expr.insert(insn.reg_a, format!("{}.{}", obj, fname));
                }
            }
            0x59..=0x5f => {
                if let Some((_, ftype, fname)) = dt.fields.get(insn.index as usize) {
                    let obj = get_val(insn.reg_b, &reg_expr);
                    let mut val = get_val(insn.reg_a, &reg_expr);
                    if ftype == "Z" {
                        if val == "0" {
                            val = "false".to_string();
                        } else if val == "1" {
                            val = "true".to_string();
                        }
                    }
                    out.push_str(&format!("{}{}.{} = {};\n", body_pad, obj, fname, val));
                }
            }
            0x60..=0x66 => {
                if let Some((fcls_raw, _ftype, fname)) = dt.fields.get(insn.index as usize) {
                    let cshort = short_type_name(&apk.display_name_of_raw(fcls_raw));
                    reg_expr.insert(insn.reg_a, format!("{}.{}", cshort, fname));
                }
            }
            0x67..=0x6d => {
                if let Some((fcls_raw, ftype, fname)) = dt.fields.get(insn.index as usize) {
                    let cshort = short_type_name(&apk.display_name_of_raw(fcls_raw));
                    let mut val = get_val(insn.reg_a, &reg_expr);
                    if ftype == "Z" {
                        if val == "0" {
                            val = "false".to_string();
                        } else if val == "1" {
                            val = "true".to_string();
                        }
                    }
                    out.push_str(&format!("{}{}.{} = {};\n", body_pad, cshort, fname, val));
                }
            }
            0x6e..=0x78 | 0xfa..=0xfd => {
                let resolved_mref = if matches!(insn.opcode, 0xfc | 0xfd) {
                    dt.call_site_targets
                        .get(&insn.index)
                        .and_then(|&t_idx| dt.methods.get(t_idx as usize))
                } else {
                    dt.methods.get(insn.index as usize)
                };
                if let Some((decl_raw, mname, pdesc)) = resolved_mref {
                    let (ret_desc, param_descs) = parse_proto_descriptor(pdesc);
                    let is_static_call = matches!(insn.opcode, 0x71 | 0x77);
                    let is_super_call = matches!(insn.opcode, 0x6f | 0x75);
                    let mut arg_regs_pos = if is_static_call { 0 } else { 1 };
                    let mut args_formatted = Vec::new();
                    for pdesc in param_descs {
                        if let Some(&areg) = insn.regs.get(arg_regs_pos) {
                            let mut aval = get_val(areg, &reg_expr);
                            if pdesc == "Z" {
                                if aval == "0" {
                                    aval = "false".to_string();
                                } else if aval == "1" {
                                    aval = "true".to_string();
                                }
                            }
                            args_formatted.push(aval);
                        }
                        arg_regs_pos += if pdesc == "J" || pdesc == "D" { 2 } else { 1 };
                    }
                    let args_str = args_formatted.join(", ");

                    if mname == "<init>" && !is_static_call {
                        if let Some(&recv_reg) = insn.regs.first() {
                            if let Some(new_type) = pending_new_instance.remove(&recv_reg) {
                                let new_expr = format!("new {}({})", new_type, args_str);
                                let vname = format!("v{}", recv_reg);
                                if declared_regs.insert(recv_reg) {
                                    out.push_str(&format!(
                                        "{}{} {} = {};\n",
                                        body_pad, new_type, vname, new_expr
                                    ));
                                } else {
                                    out.push_str(&format!(
                                        "{}{} = {};\n",
                                        body_pad, vname, new_expr
                                    ));
                                }
                                reg_expr.insert(recv_reg, vname);
                            } else {
                                let recv = get_val(recv_reg, &reg_expr);
                                if recv == "this" {
                                    if !(decl_raw == "java.lang.Object" && args_str.is_empty()) {
                                        out.push_str(&format!("{}super({});\n", body_pad, args_str));
                                    }
                                }
                            }
                        }
                    } else {
                        let call_expr = if is_static_call {
                            let cshort = short_type_name(&apk.display_name_of_raw(decl_raw));
                            format!("{}.{}({})", cshort, mname, args_str)
                        } else if is_super_call {
                            format!("super.{}({})", mname, args_str)
                        } else if let Some(&recv_reg) = insn.regs.first() {
                            let recv = get_val(recv_reg, &reg_expr);
                            if recv == "this" {
                                format!("{}({})", mname, args_str)
                            } else {
                                format!("{}.{}({})", recv, mname, args_str)
                            }
                        } else {
                            format!("{}({})", mname, args_str)
                        };

                        if next_is_move_result {
                            last_call_result = Some((call_expr, ret_desc.to_string()));
                        } else {
                            out.push_str(&format!("{}{};\n", body_pad, call_expr));
                        }
                    }
                }
            }
            0x90..=0xaf => {
                let op_sym = binop_symbol(insn.opcode);
                let lhs = get_val(insn.reg_b, &reg_expr);
                let rhs = get_val(insn.reg_c, &reg_expr);
                let expr = format!("({} {} {})", lhs, op_sym, rhs);
                let vname = format!("v{}", insn.reg_a);
                if declared_regs.insert(insn.reg_a) {
                    out.push_str(&format!("{}int {} = {};\n", body_pad, vname, expr));
                } else {
                    out.push_str(&format!("{}{} = {};\n", body_pad, vname, expr));
                }
                reg_expr.insert(insn.reg_a, vname);
            }
            0xb0..=0xcf => {
                let op_sym = binop_2addr_symbol(insn.opcode);
                let lhs = get_val(insn.reg_a, &reg_expr);
                let rhs = get_val(insn.reg_b, &reg_expr);
                let expr = format!("({} {} {})", lhs, op_sym, rhs);
                let vname = format!("v{}", insn.reg_a);
                if declared_regs.insert(insn.reg_a) {
                    out.push_str(&format!("{}int {} = {};\n", body_pad, vname, expr));
                } else {
                    out.push_str(&format!("{}{} = {};\n", body_pad, vname, expr));
                }
                reg_expr.insert(insn.reg_a, vname);
            }
            0xd0..=0xe2 => {
                let op_sym = binop_lit_symbol(insn.opcode);
                let lhs = get_val(insn.reg_b, &reg_expr);
                let expr = format!("({} {} {})", lhs, op_sym, insn.literal);
                let vname = format!("v{}", insn.reg_a);
                if declared_regs.insert(insn.reg_a) {
                    out.push_str(&format!("{}int {} = {};\n", body_pad, vname, expr));
                } else {
                    out.push_str(&format!("{}{} = {};\n", body_pad, vname, expr));
                }
                reg_expr.insert(insn.reg_a, vname);
            }
            _ => {}
        }

        let next_unit = insn.offset_units + (opcode_info(insn.opcode).units() as u32);
        for tb in &mth.tries {
            let end_u = tb.start_unit + (tb.insn_count as u32);
            if next_unit == end_u {
                let mut catch_types = Vec::new();
                for (et, _) in &tb.handlers {
                    catch_types.push(
                        et.as_ref()
                            .map(|s| short_type_name(s))
                            .unwrap_or_else(|| "Throwable".to_string()),
                    );
                }
                if catch_types.is_empty() {
                    catch_types.push("Throwable".to_string());
                }
                out.push_str(&format!(
                    "{}}} catch ({} e) {{\n{}    // handler\n{}}}\n",
                    body_pad,
                    catch_types.join(" | "),
                    body_pad,
                    body_pad
                ));
            }
        }

        idx += 1;
    }

    out.push_str(&format!("{}}}\n", pad));
    out
}

fn binop_symbol(op: u8) -> &'static str {
    match op {
        0x90 | 0x9b | 0xa6 | 0xab => "+",
        0x91 | 0x9c | 0xa7 | 0xac => "-",
        0x92 | 0x9d | 0xa8 | 0xad => "*",
        0x93 | 0x9e | 0xa9 | 0xae => "/",
        0x94 | 0x9f | 0xaa | 0xaf => "%",
        0x95 | 0xa0 => "&",
        0x96 | 0xa1 => "|",
        0x97 | 0xa2 => "^",
        0x98 | 0xa3 => "<<",
        0x99 | 0xa4 => ">>",
        0x9a | 0xa5 => ">>>",
        _ => "+",
    }
}

fn binop_2addr_symbol(op: u8) -> &'static str {
    binop_symbol(op - 0x20)
}

fn binop_lit_symbol(op: u8) -> &'static str {
    match op {
        0xd0 | 0xd8 => "+",
        0xd1 | 0xd9 => "-",
        0xd2 | 0xda => "*",
        0xd3 | 0xdb => "/",
        0xd4 | 0xdc => "%",
        0xd5 | 0xdd => "&",
        0xd6 | 0xde => "|",
        0xd7 | 0xdf => "^",
        0xe0 => "<<",
        0xe1 => ">>",
        0xe2 => ">>>",
        _ => "+",
    }
}

fn simple_class_name(cls: &ClassInfoEntry) -> String {
    if let Some(dollar) = cls.raw_name.rfind('$') {
        cls.raw_name[dollar + 1..].to_string()
    } else if let Some(dot) = cls.display_name.rfind('.') {
        cls.display_name[dot + 1..].to_string()
    } else {
        cls.display_name.clone()
    }
}

fn short_type_name(full: &str) -> String {
    let mut dims = 0;
    let mut base = full;
    while let Some(stripped) = base.strip_suffix("[]") {
        dims += 1;
        base = stripped;
    }
    let short = match base.rfind('.') {
        Some(dot) => &base[dot + 1..],
        None => base,
    };
    if dims == 0 {
        short.to_string()
    } else {
        format!("{}{}", short, "[]".repeat(dims))
    }
}

fn java_class_modifiers(flags: u32, is_iface: bool, is_enum: bool) -> String {
    let mut s = String::new();
    if (flags & 0x0001) != 0 {
        s.push_str("public ");
    } else if (flags & 0x0004) != 0 {
        s.push_str("protected ");
    } else if (flags & 0x0002) != 0 {
        s.push_str("private ");
    }
    if (flags & 0x0008) != 0 && !is_enum {
        s.push_str("static ");
    }
    if (flags & 0x0400) != 0 && !is_iface && !is_enum {
        s.push_str("abstract ");
    } else if (flags & 0x0010) != 0 && !is_iface && !is_enum {
        s.push_str("final ");
    }
    s
}

fn java_field_modifiers(flags: u32) -> String {
    let mut s = String::new();
    if (flags & 0x0001) != 0 {
        s.push_str("public ");
    } else if (flags & 0x0004) != 0 {
        s.push_str("protected ");
    } else if (flags & 0x0002) != 0 {
        s.push_str("private ");
    }
    if (flags & 0x0008) != 0 {
        s.push_str("static ");
    }
    if (flags & 0x0010) != 0 {
        s.push_str("final ");
    }
    if (flags & 0x0040) != 0 {
        s.push_str("volatile ");
    }
    if (flags & 0x0080) != 0 {
        s.push_str("transient ");
    }
    s
}

fn java_method_modifiers(flags: u32) -> String {
    let mut s = String::new();
    if (flags & 0x0001) != 0 {
        s.push_str("public ");
    } else if (flags & 0x0004) != 0 {
        s.push_str("protected ");
    } else if (flags & 0x0002) != 0 {
        s.push_str("private ");
    }
    if (flags & 0x0008) != 0 {
        s.push_str("static ");
    }
    if (flags & 0x0010) != 0 {
        s.push_str("final ");
    }
    if (flags & 0x0020) != 0 {
        s.push_str("synchronized ");
    }
    if (flags & 0x0100) != 0 {
        s.push_str("native ");
    }
    if (flags & 0x0400) != 0 {
        s.push_str("abstract ");
    }
    s
}

fn smali_access_flags(flags: u32, is_class: bool) -> String {
    let mut s = String::new();
    if (flags & 0x0001) != 0 {
        s.push_str("public ");
    }
    if (flags & 0x0002) != 0 {
        s.push_str("private ");
    }
    if (flags & 0x0004) != 0 {
        s.push_str("protected ");
    }
    if (flags & 0x0008) != 0 {
        s.push_str("static ");
    }
    if (flags & 0x0010) != 0 {
        s.push_str("final ");
    }
    if is_class && (flags & 0x0200) != 0 {
        s.push_str("interface ");
    }
    if (flags & 0x0400) != 0 {
        s.push_str("abstract ");
    }
    if (flags & 0x1000) != 0 {
        s.push_str("synthetic ");
    }
    if is_class && (flags & 0x4000) != 0 {
        s.push_str("enum ");
    }
    s
}

fn smali_method_flags(flags: u32) -> String {
    let mut s = smali_access_flags(flags, false);
    if (flags & 0x0100) != 0 {
        s.push_str("native ");
    }
    if (flags & 0x10000) != 0 {
        s.push_str("constructor ");
    }
    s
}

fn format_literal_smali(lit: &LiteralValue) -> String {
    match lit {
        LiteralValue::String(s) => format!("\"{}\"", escape_java_str(s)),
        LiteralValue::Int(v) => format!("0x{:x}", v),
        LiteralValue::Long(v) => format!("0x{:x}L", v),
        LiteralValue::Float(v) => format!("{}f", v),
        LiteralValue::Double(v) => format!("{}", v),
        LiteralValue::Boolean(v) => format!("{}", v),
        LiteralValue::Char(v) => format!("0x{:x}", v),
        LiteralValue::Type(s) => s.clone(),
        LiteralValue::Null => "null".to_string(),
    }
}

fn format_literal_java(lit: &LiteralValue, type_desc: &str) -> String {
    match lit {
        LiteralValue::String(s) => format!("\"{}\"", escape_java_str(s)),
        LiteralValue::Int(v) => {
            if type_desc == "Z" {
                if *v != 0 {
                    "true".to_string()
                } else {
                    "false".to_string()
                }
            } else {
                format!("{}", v)
            }
        }
        LiteralValue::Long(v) => format!("{}L", v),
        LiteralValue::Float(v) => format!("{}f", v),
        LiteralValue::Double(v) => format!("{}", v),
        LiteralValue::Boolean(v) => format!("{}", v),
        LiteralValue::Char(v) => format!("'\\u{:04x}'", v),
        LiteralValue::Type(s) => format!("{}.class", s),
        LiteralValue::Null => "null".to_string(),
    }
}

pub fn escape_java_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}
