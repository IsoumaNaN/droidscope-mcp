use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use memmap2::Mmap;
use serde_json::{Map, Value};
use zip::ZipArchive;

use crate::axml::{
    decode_axml, extract_application_class, extract_main_activity, get_deeplink_components_list,
    get_exported_components_list, ArscTable, XmlElement,
};
use crate::decompile::{
    decompile_class_java, decompile_method_java, disassemble_class_smali, disassemble_method_smali,
};
use crate::dex::{
    decode_instructions, descriptor_base_raw_class, descriptor_to_java_type,
    descriptor_to_raw_class, parse_proto_descriptor, EncodedValue, ParsedDex, RefKind,
};
use crate::elf::{resolve_so_entry_name, ParsedElf};
use crate::framework::{default_sinks, FrameworkKnowledge};
use crate::guards::*;

#[derive(Debug, Clone)]
pub struct FieldInfoEntry {
    pub id: usize,
    pub parent_cls_id: usize,
    pub name: String,
    pub alias: String,
    pub type_desc: String,
    pub access_flags: u32,
    pub initial_value: Option<LiteralValue>,
    pub annotations: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum LiteralValue {
    String(String),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    Boolean(bool),
    Char(u16),
    Type(String),
    Null,
}

#[derive(Debug, Clone)]
pub struct MethodInfoEntry {
    pub id: usize,
    pub parent_cls_id: usize,
    pub dex_idx: usize,
    pub name: String,
    pub alias: String,
    pub proto_desc: String,
    pub access_flags: u32,
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    /// Offset in the combined DEX mmap buffer where `insns` start
    pub global_insns_off: usize,
    pub insns_size_units: u32,
    pub tries: Vec<TryBlockResolved>,
    pub annotations: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TryBlockResolved {
    pub start_unit: u32,
    pub insn_count: u16,
    pub handlers: Vec<(Option<String>, u32)>,
}

impl MethodInfoEntry {
    pub fn short_id(&self) -> String {
        format!("{}{}", self.name, self.proto_desc)
    }

    pub fn pinned_signature(&self) -> String {
        format!("{}{}", self.alias, self.proto_desc)
    }

    pub fn return_type_desc(&self) -> &str {
        parse_proto_descriptor(&self.proto_desc).0
    }

    pub fn param_type_descs(&self) -> Vec<&str> {
        parse_proto_descriptor(&self.proto_desc).1
    }
}

#[derive(Debug, Clone)]
pub struct ClassInfoEntry {
    pub id: usize,
    pub dex_idx: usize,
    pub desc: String,
    /// Raw DEX name with '$' between outer and inner (e.g. `pkg.Outer$Inner`)
    pub raw_name: String,
    /// Dotted alias name (e.g. `pkg.Outer.Inner`)
    pub alias_full_name: String,
    /// Reported display name (`alias_full_name`, or `raw_name` if `alias_full_name` is ambiguous)
    pub display_name: String,
    /// Optional JADX-style deobfuscated alias (e.g. `pkg.C0303R.styleable`) for backward-compat lookup
    pub jadx_deobf_name: Option<String>,
    pub access_flags: u32,
    pub super_raw_name: Option<String>,
    pub interface_raw_names: Vec<String>,
    pub source_file: Option<String>,
    pub parent_cls_id: Option<usize>,
    pub inner_cls_ids: Vec<usize>,
    pub field_ids: Vec<usize>,
    pub method_ids: Vec<usize>,
    pub annotations: Vec<String>,
    pub annotation_type_refs: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DexTables {
    pub base_offset: usize,
    pub size: usize,
    pub strings: Vec<String>,
    pub type_descs: Vec<String>,
    pub fields: Vec<(String, String, String)>, // (class_raw, type_desc, name)
    pub methods: Vec<(String, String, String)>, // (class_raw, name, proto_desc)
    pub call_site_targets: HashMap<u32, u32>,
}

#[derive(Debug, Clone)]
pub struct CsrGraph {
    pub offsets: Vec<u32>,
    pub edges: Vec<u32>,
}

impl CsrGraph {
    pub fn from_adj(adj: Vec<Vec<u32>>) -> Self {
        let mut offsets = Vec::with_capacity(adj.len() + 1);
        let total_edges: usize = adj.iter().map(|v| v.len()).sum();
        let mut edges = Vec::with_capacity(total_edges);
        let mut cur = 0u32;
        for mut list in adj {
            offsets.push(cur);
            list.sort_unstable();
            list.dedup();
            cur += list.len() as u32;
            edges.extend_from_slice(&list);
        }
        offsets.push(cur);
        CsrGraph { offsets, edges }
    }

    pub fn neighbors(&self, node: usize) -> &[u32] {
        if node + 1 >= self.offsets.len() {
            return &[];
        }
        let start = self.offsets[node] as usize;
        let end = self.offsets[node + 1] as usize;
        &self.edges[start..end]
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

#[derive(Debug, Clone)]
pub struct ReverseIndex {
    pub build_ms: u64,
    pub instructions_scanned: u64,
    pub method_callers: CsrGraph,
    pub field_users: CsrGraph,
    pub class_method_users: CsrGraph,
    pub class_users: CsrGraph,
    /// Unresolved external calls per method: packed `((dex_idx as u32) << 16) | (dex_method_idx as u32)`
    pub unresolved_calls: CsrGraph,
    pub self_calls: Vec<bool>,
}

pub struct ApkIndex {
    pub apk_path: String,
    pub format: String,
    pub package_name: String,
    pub manifest_xml: Option<String>,
    pub manifest_dom: Option<XmlElement>,
    pub arsc: ArscTable,
    pub resource_entries: Vec<(String, u64)>,
    pub dex_mmap: Option<Mmap>,
    pub dex_tables: Vec<DexTables>,
    pub classes: Vec<ClassInfoEntry>,
    pub fields: Vec<FieldInfoEntry>,
    pub methods: Vec<MethodInfoEntry>,
    pub ambiguous_aliases: HashSet<String>,
    pub by_alias_name: HashMap<String, usize>,
    pub by_raw_name: HashMap<String, usize>,
    pub by_jadx_deobf: HashMap<String, usize>,
    pub framework: FrameworkKnowledge,
    pub known_external_types: HashSet<String>,
    pub reverse_index: RwLock<Option<Arc<ReverseIndex>>>,
}

impl ApkIndex {
    pub fn load(apk_path: &str) -> Result<Self, String> {
        let path = Path::new(apk_path);
        if !path.exists() {
            return Err(format!("APK file not found: {}", apk_path));
        }

        let lower = apk_path.to_lowercase();
        let format = if lower.ends_with(".dex") {
            "DEX"
        } else if lower.ends_with(".jar") {
            "JAR"
        } else if lower.ends_with(".aab") {
            "AAB"
        } else {
            "APK"
        }
        .to_string();

        let mut arsc = ArscTable::default();
        let mut manifest_bytes: Option<Vec<u8>> = None;
        let mut resource_entries: Vec<(String, u64)> = Vec::new();
        let mut temp_dex_file = tempfile::tempfile()
            .map_err(|e| format!("Failed to create temporary DEX backing file: {}", e))?;
        let mut dex_ranges: Vec<(usize, usize)> = Vec::new();

        if format == "DEX" {
            let mut f = File::open(path).map_err(|e| format!("Error opening DEX: {}", e))?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)
                .map_err(|e| format!("Error reading DEX: {}", e))?;
            let len = buf.len();
            temp_dex_file
                .write_all(&buf)
                .map_err(|e| format!("Error writing DEX temp: {}", e))?;
            dex_ranges.push((0, len));
        } else {
            let file = File::open(path).map_err(|e| format!("Error opening archive: {}", e))?;
            let mut archive =
                ZipArchive::new(file).map_err(|e| format!("Error reading ZIP archive: {}", e))?;

            let mut dex_entry_names: Vec<(usize, String)> = Vec::new();
            for i in 0..archive.len() {
                let Ok(entry) = archive.by_index_raw(i) else {
                    continue;
                };
                let name = entry.name().to_string();
                let size = entry.size();
                if is_dex_entry(&name) {
                    dex_entry_names.push((i, name));
                } else {
                    resource_entries.push((name, size));
                }
            }

            // Sort classes.dex, classes2.dex, ... in canonical order
            dex_entry_names.sort_by(|a, b| dex_sort_key(&a.1).cmp(&dex_sort_key(&b.1)));

            // Parse resources.arsc if present (only string resources)
            for i in 0..archive.len() {
                let is_arsc = archive
                    .by_index_raw(i)
                    .map(|e| e.name() == "resources.arsc" || e.name().ends_with("/resources.arsc"))
                    .unwrap_or(false);
                if is_arsc {
                    if let Ok(mut entry) = archive.by_index(i) {
                        let mut buf = Vec::with_capacity(entry.size() as usize);
                        if entry.read_to_end(&mut buf).is_ok() {
                            arsc = ArscTable::parse(&buf);
                        }
                    }
                    break;
                }
            }

            // Read AndroidManifest.xml if present
            for i in 0..archive.len() {
                let is_manifest = archive
                    .by_index_raw(i)
                    .map(|e| {
                        e.name() == "AndroidManifest.xml"
                            || e.name() == "base/manifest/AndroidManifest.xml"
                    })
                    .unwrap_or(false);
                if is_manifest {
                    if let Ok(mut entry) = archive.by_index(i) {
                        let mut buf = Vec::with_capacity(entry.size() as usize);
                        if entry.read_to_end(&mut buf).is_ok() {
                            manifest_bytes = Some(buf);
                        }
                    }
                    break;
                }
            }

            // Stream classes*.dex into the temp file so we can mmap it without holding heap copies
            let mut current_offset = 0usize;
            for (zip_idx, _) in dex_entry_names {
                if let Ok(mut entry) = archive.by_index(zip_idx) {
                    let written = std::io::copy(&mut entry, &mut temp_dex_file)
                        .map_err(|e| format!("Failed streaming DEX entry: {}", e))?
                        as usize;
                    if written >= 112 {
                        dex_ranges.push((current_offset, written));
                        current_offset += written;
                    }
                }
            }
        }

        temp_dex_file
            .flush()
            .map_err(|e| format!("Failed flushing temp DEX: {}", e))?;

        let dex_mmap = if !dex_ranges.is_empty() {
            Some(unsafe {
                Mmap::map(&temp_dex_file)
                    .map_err(|e| format!("Failed memory-mapping DEX backing file: {}", e))?
            })
        } else {
            None
        };

        let (manifest_xml, manifest_dom, package_name) = if let Some(mbytes) = manifest_bytes {
            match decode_axml(&mbytes, Some(&arsc)) {
                Ok((xml_str, dom)) => {
                    let pkg = dom.get_attr("package").unwrap_or("").to_string();
                    (Some(xml_str), Some(dom), pkg)
                }
                Err(_) => (None, None, String::new()),
            }
        } else {
            (None, None, String::new())
        };

        let mut classes: Vec<ClassInfoEntry> = Vec::new();
        let mut fields: Vec<FieldInfoEntry> = Vec::new();
        let mut methods: Vec<MethodInfoEntry> = Vec::new();
        let mut dex_tables: Vec<DexTables> = Vec::new();
        let mut known_external_types: HashSet<String> = HashSet::new();

        if let Some(ref mmap) = dex_mmap {
            for (dex_idx, &(base_offset, size)) in dex_ranges.iter().enumerate() {
                let slice = &mmap[base_offset..base_offset + size];
                let parsed = ParsedDex::parse(slice)?;

                let type_descs: Vec<String> = (0..parsed.type_string_idxs.len())
                    .map(|t| parsed.get_type_desc(t as u32).to_string())
                    .collect();

                let proto_descs: Vec<String> = (0..parsed.protos.len())
                    .map(|pidx| parsed.get_proto_descriptor(pidx as u16))
                    .collect();

                let dex_fields: Vec<(String, String, String)> = parsed
                    .fields
                    .iter()
                    .map(|f| {
                        let cls_raw = descriptor_to_raw_class(parsed.get_type_desc(f.class_idx as u32))
                            .unwrap_or_default();
                        let tdesc = parsed.get_type_desc(f.type_idx as u32).to_string();
                        let name = parsed.get_string(f.name_idx).to_string();
                        (cls_raw, tdesc, name)
                    })
                    .collect();

                let dex_methods: Vec<(String, String, String)> = parsed
                    .methods
                    .iter()
                    .map(|m| {
                        let cls_raw = descriptor_to_raw_class(parsed.get_type_desc(m.class_idx as u32))
                            .unwrap_or_default();
                        let name = parsed.get_string(m.name_idx).to_string();
                        let pdesc = proto_descs
                            .get(m.proto_idx as usize)
                            .cloned()
                            .unwrap_or_else(|| "()V".to_string());
                        (cls_raw, name, pdesc)
                    })
                    .collect();

                for (cls_def_idx, cdef) in parsed.classes.iter().enumerate() {
                    let desc = parsed.get_type_desc(cdef.class_idx).to_string();
                    let Some(raw_name) = descriptor_to_raw_class(&desc) else {
                        continue;
                    };

                    let cls_id = classes.len();
                    let alias_full_name = raw_name.replace('$', ".");
                    let jadx_deobf_name = compute_jadx_deobf_class_name(&raw_name, cls_def_idx);

                    let super_raw_name = cdef
                        .superclass_idx
                        .and_then(|ti| descriptor_to_raw_class(parsed.get_type_desc(ti)));
                    if let Some(ref sr) = super_raw_name {
                        known_external_types.insert(sr.clone());
                    }

                    let mut interface_raw_names = Vec::new();
                    for &iti in &cdef.interface_idxs {
                        if let Some(ir) = descriptor_to_raw_class(parsed.get_type_desc(iti)) {
                            known_external_types.insert(ir.clone());
                            interface_raw_names.push(ir);
                        }
                    }

                    let source_file = cdef
                        .source_file_idx
                        .map(|si| parsed.get_string(si).to_string())
                        .filter(|s| !s.is_empty());

                    let mut field_ids = Vec::new();
                    for fdef in cdef.static_fields.iter().chain(cdef.instance_fields.iter()) {
                        let Some((_, ftype_desc, fname)) = dex_fields.get(fdef.field_idx as usize)
                        else {
                            continue;
                        };
                        let fid = fields.len();
                        let init_val = fdef.initial_value.as_ref().map(|ev| match ev {
                            EncodedValue::String(sidx) => {
                                LiteralValue::String(parsed.get_string(*sidx).to_string())
                            }
                            EncodedValue::Int(v) => LiteralValue::Int(*v),
                            EncodedValue::Byte(v) => LiteralValue::Int(*v as i32),
                            EncodedValue::Short(v) => LiteralValue::Int(*v as i32),
                            EncodedValue::Char(v) => LiteralValue::Char(*v),
                            EncodedValue::Long(v) => LiteralValue::Long(*v),
                            EncodedValue::Float(v) => LiteralValue::Float(*v),
                            EncodedValue::Double(v) => LiteralValue::Double(*v),
                            EncodedValue::Boolean(v) => LiteralValue::Boolean(*v),
                            EncodedValue::Type(tidx) => {
                                LiteralValue::Type(parsed.get_type_desc(*tidx).to_string())
                            }
                            _ => LiteralValue::Null,
                        });
                        let f_anns = cdef
                            .field_annotations
                            .get(&fdef.field_idx)
                            .map(|v| {
                                v.iter()
                                    .filter_map(|&ti| {
                                        descriptor_to_raw_class(parsed.get_type_desc(ti))
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();

                        fields.push(FieldInfoEntry {
                            id: fid,
                            parent_cls_id: cls_id,
                            name: fname.clone(),
                            alias: fname.clone(),
                            type_desc: ftype_desc.clone(),
                            access_flags: fdef.access_flags,
                            initial_value: init_val,
                            annotations: f_anns,
                        });
                        field_ids.push(fid);
                    }

                    let mut method_ids = Vec::new();
                    for mdef in cdef.direct_methods.iter().chain(cdef.virtual_methods.iter()) {
                        let Some((_, mname, proto_desc)) =
                            dex_methods.get(mdef.method_idx as usize)
                        else {
                            continue;
                        };
                        let mid = methods.len();
                        let m_anns = cdef
                            .method_annotations
                            .get(&mdef.method_idx)
                            .map(|v| {
                                v.iter()
                                    .filter_map(|&ti| {
                                        descriptor_to_raw_class(parsed.get_type_desc(ti))
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();

                        let tries_resolved = mdef
                            .tries
                            .iter()
                            .map(|tb| TryBlockResolved {
                                start_unit: tb.start_unit,
                                insn_count: tb.insn_count,
                                handlers: tb
                                    .handlers
                                    .iter()
                                    .map(|(opt_t, addr)| {
                                        (
                                            opt_t.and_then(|ti| {
                                                descriptor_to_raw_class(parsed.get_type_desc(ti))
                                            }),
                                            *addr,
                                        )
                                    })
                                    .collect(),
                            })
                            .collect();

                        methods.push(MethodInfoEntry {
                            id: mid,
                            parent_cls_id: cls_id,
                            dex_idx,
                            name: mname.clone(),
                            alias: mname.clone(),
                            proto_desc: proto_desc.clone(),
                            access_flags: mdef.access_flags,
                            registers_size: mdef.registers_size,
                            ins_size: mdef.ins_size,
                            outs_size: mdef.outs_size,
                            global_insns_off: if mdef.insns_off > 0 {
                                base_offset + (mdef.insns_off as usize)
                            } else {
                                0
                            },
                            insns_size_units: mdef.insns_size_units,
                            tries: tries_resolved,
                            annotations: m_anns,
                        });
                        method_ids.push(mid);
                    }

                    let cls_anns = cdef
                        .annotation_types
                        .iter()
                        .filter_map(|&ti| descriptor_to_raw_class(parsed.get_type_desc(ti)))
                        .collect();

                    let ann_type_refs = cdef
                        .annotation_type_refs
                        .iter()
                        .filter_map(|&ti| descriptor_base_raw_class(parsed.get_type_desc(ti)))
                        .collect();

                    classes.push(ClassInfoEntry {
                        id: cls_id,
                        dex_idx,
                        desc,
                        raw_name,
                        alias_full_name,
                        display_name: String::new(),
                        jadx_deobf_name,
                        access_flags: cdef.access_flags,
                        super_raw_name,
                        interface_raw_names,
                        source_file,
                        parent_cls_id: None,
                        inner_cls_ids: Vec::new(),
                        field_ids,
                        method_ids,
                        annotations: cls_anns,
                        annotation_type_refs: ann_type_refs,
                    });
                }

                dex_tables.push(DexTables {
                    base_offset,
                    size,
                    strings: parsed.strings,
                    type_descs,
                    fields: dex_fields,
                    methods: dex_methods,
                    call_site_targets: parsed.call_site_targets,
                });
            }
        }

        // Compute ambiguous alias names and finalize display_name + lookup maps
        let mut alias_counts: HashMap<String, usize> = HashMap::with_capacity(classes.len());
        for cls in &classes {
            *alias_counts.entry(cls.alias_full_name.clone()).or_insert(0) += 1;
        }
        let mut ambiguous_aliases = HashSet::new();
        for (alias, count) in alias_counts {
            if count > 1 {
                ambiguous_aliases.insert(alias);
            }
        }

        let mut by_alias_name = HashMap::with_capacity(classes.len());
        let mut by_raw_name = HashMap::with_capacity(classes.len());
        let mut by_jadx_deobf = HashMap::with_capacity(classes.len());

        for cls in &mut classes {
            if ambiguous_aliases.contains(&cls.alias_full_name) {
                cls.display_name = cls.raw_name.clone();
            } else {
                cls.display_name = cls.alias_full_name.clone();
            }
            by_raw_name.entry(cls.raw_name.clone()).or_insert(cls.id);
            if !ambiguous_aliases.contains(&cls.alias_full_name) {
                by_alias_name
                    .entry(cls.alias_full_name.clone())
                    .or_insert(cls.id);
            }
            if let Some(ref deobf) = cls.jadx_deobf_name {
                by_jadx_deobf.entry(deobf.clone()).or_insert(cls.id);
                by_jadx_deobf
                    .entry(deobf.replace('$', "."))
                    .or_insert(cls.id);
            }
        }

        // Link outer <-> inner classes based on '$' in raw_name
        let mut parent_links: Vec<(usize, usize)> = Vec::new();
        for cls in &classes {
            if let Some(dollar) = cls.raw_name.rfind('$') {
                let outer_raw = &cls.raw_name[..dollar];
                if let Some(&outer_id) = by_raw_name.get(outer_raw) {
                    if outer_id != cls.id {
                        parent_links.push((cls.id, outer_id));
                    }
                }
            }
        }
        for (child_id, outer_id) in parent_links {
            classes[child_id].parent_cls_id = Some(outer_id);
            classes[outer_id].inner_cls_ids.push(child_id);
        }

        Ok(ApkIndex {
            apk_path: apk_path.to_string(),
            format,
            package_name,
            manifest_xml,
            manifest_dom,
            arsc,
            resource_entries,
            dex_mmap,
            dex_tables,
            classes,
            fields,
            methods,
            ambiguous_aliases,
            by_alias_name,
            by_raw_name,
            by_jadx_deobf,
            framework: FrameworkKnowledge::new(),
            known_external_types,
            reverse_index: RwLock::new(None),
        })
    }

    pub fn lookup_method_in_class(
        &self,
        cls_id: usize,
        name: &str,
        proto_desc: &str,
    ) -> Option<usize> {
        self.classes[cls_id]
            .method_ids
            .iter()
            .copied()
            .find(|&mid| {
                let m = &self.methods[mid];
                m.name == name && m.proto_desc == proto_desc
            })
    }

    pub fn lookup_field_in_class(
        &self,
        cls_id: usize,
        name: &str,
        type_desc: &str,
    ) -> Option<usize> {
        self.classes[cls_id]
            .field_ids
            .iter()
            .copied()
            .find(|&fid| {
                let f = &self.fields[fid];
                f.name == name && f.type_desc == type_desc
            })
    }

    pub fn method_insns_slice(&self, mth: &MethodInfoEntry) -> &[u8] {
        if mth.global_insns_off == 0 || mth.insns_size_units == 0 {
            return &[];
        }
        let Some(ref mmap) = self.dex_mmap else {
            return &[];
        };
        let byte_len = (mth.insns_size_units as usize) * 2;
        let end = (mth.global_insns_off + byte_len).min(mmap.len());
        if mth.global_insns_off >= end {
            &[]
        } else {
            &mmap[mth.global_insns_off..end]
        }
    }

    pub fn display_name_of_raw(&self, raw: &str) -> String {
        let norm = raw.replace('/', ".");
        if let Some(&cid) = self.by_raw_name.get(&norm) {
            return self.classes[cid].display_name.clone();
        }
        norm
    }

    pub fn format_java_type(&self, desc: &str) -> String {
        descriptor_to_java_type(desc, |raw| self.display_name_of_raw(raw))
    }

    pub fn resolve_class_nodes(&self, class_name: &str) -> Vec<usize> {
        let query = class_name.trim();
        if query.is_empty() {
            return Vec::new();
        }
        // Tier 1: unique / raw spelling (`$` between outer and inner)
        if let Some(&cid) = self.by_raw_name.get(query) {
            return vec![cid];
        }
        // Tier 2: ambiguous alias spelling
        if self.ambiguous_aliases.contains(query) {
            let mut matches = Vec::new();
            for cls in &self.classes {
                if cls.alias_full_name == query {
                    matches.push(cls.id);
                }
            }
            if !matches.is_empty() {
                return matches;
            }
        }
        // Tier 3: unambiguous alias spelling
        if let Some(&cid) = self.by_alias_name.get(query) {
            return vec![cid];
        }
        // Tier 4: JADX deobfuscated name (`C0303R` -> `R`)
        if let Some(&cid) = self.by_jadx_deobf.get(query) {
            return vec![cid];
        }
        let stripped = strip_jadx_deobf_in_class_query(query);
        if stripped != query {
            if let Some(&cid) = self.by_alias_name.get(&stripped) {
                return vec![cid];
            }
            if let Some(&cid) = self.by_raw_name.get(&stripped) {
                return vec![cid];
            }
        }
        Vec::new()
    }

    pub fn find_class_node(&self, class_name: &str) -> Result<Option<usize>, String> {
        let matches = self.resolve_class_nodes(class_name);
        if matches.is_empty() {
            return Ok(None);
        }
        if matches.len() > 1 {
            let mut spellings: Vec<String> = matches
                .iter()
                .map(|&cid| {
                    let c = &self.classes[cid];
                    format!(
                        "{} ({} methods, {} fields)",
                        c.raw_name,
                        c.method_ids.len(),
                        c.field_ids.len()
                    )
                })
                .collect();
            spellings.sort();
            return Err(marker(
                AMBIGUOUS_MARKER_PREFIX,
                &format!(
                    "\"{}\" names {} different classes in this APK: {}. Ask again with the spelling that uses '$' between an outer class and an inner one.",
                    class_name,
                    matches.len(),
                    spellings.join(", ")
                ),
            ));
        }
        Ok(Some(matches[0]))
    }

    pub fn resolve_methods(
        &self,
        cls_id: usize,
        method_name: &str,
        signature: Option<&str>,
    ) -> Vec<usize> {
        let mut query = method_name;
        let mut sig = signature.unwrap_or("");
        if let Some(paren) = query.find('(') {
            if sig.trim().is_empty() {
                sig = &query[paren..];
            }
            query = &query[..paren];
        }
        let name = match query.rfind('.') {
            Some(dot) => &query[dot + 1..],
            None => query,
        };

        let cls = &self.classes[cls_id];
        let mut targets: Vec<usize> = Vec::new();
        for &mid in &cls.method_ids {
            if self.methods[mid].alias == name {
                targets.push(mid);
            }
        }
        if targets.is_empty() {
            for &mid in &cls.method_ids {
                if self.methods[mid].name == name {
                    targets.push(mid);
                }
            }
        }
        if targets.is_empty() {
            if let Some(stripped) = strip_jadx_method_prefix(name) {
                for &mid in &cls.method_ids {
                    if self.methods[mid].name == stripped {
                        targets.push(mid);
                    }
                }
            }
        }

        let sig_trimmed = sig.trim();
        if !sig_trimmed.is_empty() {
            let wanted_desc = match sig_trimmed.find('(') {
                Some(p) => &sig_trimmed[p..],
                None => sig_trimmed,
            };
            targets.retain(|&mid| self.methods[mid].proto_desc == wanted_desc);
        }
        targets
    }

    pub fn resolve_fields(&self, cls_id: usize, field_name: &str) -> Vec<usize> {
        let query = field_name.trim();
        let (wanted_type, raw_query) = match query.rfind(' ') {
            Some(sp) => (Some(query[..sp].trim()), query[sp + 1..].trim()),
            None => (None, query),
        };
        let name = match raw_query.rfind('.') {
            Some(dot) => &raw_query[dot + 1..],
            None => raw_query,
        };

        let cls = &self.classes[cls_id];
        let mut targets = Vec::new();
        for &fid in &cls.field_ids {
            if self.fields[fid].alias == name {
                targets.push(fid);
            }
        }
        if targets.is_empty() {
            for &fid in &cls.field_ids {
                if self.fields[fid].name == name {
                    targets.push(fid);
                }
            }
        }
        if let Some(wt) = wanted_type {
            targets.retain(|&fid| {
                let f = &self.fields[fid];
                self.format_java_type(&f.type_desc) == wt || f.type_desc == wt
            });
        }
        targets
    }

    pub fn no_such_method(
        &self,
        cls_id: usize,
        method_name: &str,
        signature: Option<&str>,
    ) -> String {
        let cls_display = &self.classes[cls_id].display_name;
        if let Some(sig) = signature {
            if !sig.trim().is_empty() {
                let by_name = self.resolve_methods(cls_id, method_name, None);
                if !by_name.is_empty() {
                    let mut avail: Vec<String> = by_name
                        .iter()
                        .map(|&mid| self.methods[mid].pinned_signature())
                        .collect();
                    avail.sort();
                    return format!(
                        "No method {} with signature {} in class {}. It declares: {}",
                        method_name,
                        sig,
                        cls_display,
                        avail.join(", ")
                    );
                }
            }
        }
        if let Some(ancestor) = self.declaring_ancestor(cls_id, method_name, signature) {
            return format!(
                "Method not found: {} is not declared by {}; it inherits it from {}. Ask about that class instead.",
                method_name, cls_display, ancestor
            );
        }
        format!("Method not found: {} in class {}", method_name, cls_display)
    }

    fn declaring_ancestor(
        &self,
        cls_id: usize,
        method_name: &str,
        signature: Option<&str>,
    ) -> Option<String> {
        let mut seen = HashSet::new();
        let mut queue = VecDeque::new();
        self.push_in_apk_supertypes(cls_id, &mut queue, &mut seen);
        while let Some(next_id) = queue.pop_front() {
            if !self.resolve_methods(next_id, method_name, signature).is_empty() {
                return Some(self.classes[next_id].display_name.clone());
            }
            self.push_in_apk_supertypes(next_id, &mut queue, &mut seen);
        }

        let bare = match method_name.rfind('.') {
            Some(dot) => &method_name[dot + 1..],
            None => method_name,
        };
        let supers = self.transitive_supertypes_raw(&self.classes[cls_id].raw_name);
        for st in supers {
            if self.by_raw_name.contains_key(&st) {
                continue;
            }
            if self.framework.declares_method(&st, bare) {
                return Some(format!("{} (outside this APK)", st));
            }
        }
        None
    }

    fn push_in_apk_supertypes(
        &self,
        cls_id: usize,
        queue: &mut VecDeque<usize>,
        seen: &mut HashSet<usize>,
    ) {
        let cls = &self.classes[cls_id];
        if let Some(ref sraw) = cls.super_raw_name {
            if let Some(&sid) = self.by_raw_name.get(sraw) {
                if seen.insert(sid) {
                    queue.push_back(sid);
                }
            }
        }
        for iraw in &cls.interface_raw_names {
            if let Some(&iid) = self.by_raw_name.get(iraw) {
                if seen.insert(iid) {
                    queue.push_back(iid);
                }
            }
        }
    }

    pub fn transitive_supertypes_raw(&self, raw_class: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let mut queue = vec![raw_class.replace('/', ".")];
        while let Some(curr) = queue.pop() {
            if let Some(&cid) = self.by_raw_name.get(&curr) {
                let c = &self.classes[cid];
                if let Some(ref sr) = c.super_raw_name {
                    if out.insert(sr.clone()) {
                        queue.push(sr.clone());
                    }
                }
                for ir in &c.interface_raw_names {
                    if out.insert(ir.clone()) {
                        queue.push(ir.clone());
                    }
                }
            } else {
                for fsup in self.framework.super_types_of(&curr) {
                    if out.insert(fsup.clone()) {
                        queue.push(fsup);
                    }
                }
            }
        }
        out
    }

    pub fn is_subtype_or_equal(&self, candidate_raw: &str, target_decl: &str) -> bool {
        let norm_cand = candidate_raw.replace('/', ".");
        let norm_target = target_decl.replace('/', ".");
        if norm_cand == norm_target {
            return true;
        }
        if let Some(&cid) = self.by_raw_name.get(&norm_cand) {
            if self.classes[cid].display_name == norm_target
                || self.classes[cid].alias_full_name == norm_target
            {
                return true;
            }
        }
        let supers = self.transitive_supertypes_raw(&norm_cand);
        if supers.contains(&norm_target) {
            return true;
        }
        for s in &supers {
            if let Some(&scid) = self.by_raw_name.get(s) {
                if self.classes[scid].display_name == norm_target
                    || self.classes[scid].alias_full_name == norm_target
                {
                    return true;
                }
            }
        }
        false
    }

    pub fn ensure_reverse_index(&self) -> Arc<ReverseIndex> {
        if let Some(ref idx) = *self.reverse_index.read().unwrap() {
            return Arc::clone(idx);
        }
        let mut guard = self.reverse_index.write().unwrap();
        if let Some(ref idx) = *guard {
            return Arc::clone(idx);
        }
        let built = Arc::new(self.build_reverse_index());
        *guard = Some(Arc::clone(&built));
        built
    }

    fn build_reverse_index(&self) -> ReverseIndex {
        let t0 = Instant::now();
        let num_classes = self.classes.len();
        let num_methods = self.methods.len();
        let num_fields = self.fields.len();

        let mut method_callers_adj: Vec<Vec<u32>> = vec![Vec::new(); num_methods];
        let mut field_users_adj: Vec<Vec<u32>> = vec![Vec::new(); num_fields];
        let mut class_method_users_adj: Vec<Vec<u32>> = vec![Vec::new(); num_classes];
        let mut class_users_adj: Vec<Vec<u32>> = vec![Vec::new(); num_classes];
        let mut unresolved_calls_adj: Vec<Vec<u32>> = vec![Vec::new(); num_methods];
        let mut self_calls: Vec<bool> = vec![false; num_methods];
        let mut instructions_scanned = 0u64;

        let record_class_use =
            |adj: &mut Vec<Vec<u32>>, target_raw: &str, user_cls_id: usize| {
                if let Some(&target_id) = self.by_raw_name.get(target_raw) {
                    if target_id != user_cls_id {
                        adj[target_id].push(user_cls_id as u32);
                    }
                }
            };

        // 1. Class-header & member-signature references
        for cls in &self.classes {
            let cid = cls.id;
            if let Some(ref sr) = cls.super_raw_name {
                record_class_use(&mut class_users_adj, sr, cid);
            }
            for ir in &cls.interface_raw_names {
                record_class_use(&mut class_users_adj, ir, cid);
            }
            if let Some(pid) = cls.parent_cls_id {
                if pid != cid {
                    class_users_adj[cid].push(pid as u32);
                    class_users_adj[pid].push(cid as u32);
                }
            }
            for aref in &cls.annotation_type_refs {
                record_class_use(&mut class_users_adj, aref, cid);
            }
            for &fid in &cls.field_ids {
                let f = &self.fields[fid];
                if let Some(raw) = descriptor_base_raw_class(&f.type_desc) {
                    record_class_use(&mut class_users_adj, &raw, cid);
                }
            }
            for &mid in &cls.method_ids {
                let m = &self.methods[mid];
                if let Some(raw) = descriptor_base_raw_class(m.return_type_desc()) {
                    record_class_use(&mut class_users_adj, &raw, cid);
                }
                for pdesc in m.param_type_descs() {
                    if let Some(raw) = descriptor_base_raw_class(pdesc) {
                        record_class_use(&mut class_users_adj, &raw, cid);
                    }
                }
            }
        }

        // Pre-resolve DEX tables once per DEX so the instruction loop does O(1) array indexing
        struct DexResolvedTables {
            type_cids: Vec<u32>,
            // (decl_cid, target_fid, type_cid)
            fields: Vec<(u32, u32, u32)>,
            // (decl_cid, target_mid, is_obj_init, sig_cids)
            methods: Vec<(u32, u32, bool, Vec<u32>)>,
        }

        let resolved_dex: Vec<DexResolvedTables> = self
            .dex_tables
            .iter()
            .map(|dt| {
                let type_cids: Vec<u32> = dt
                    .type_descs
                    .iter()
                    .map(|tdesc| {
                        descriptor_base_raw_class(tdesc)
                            .and_then(|raw| self.by_raw_name.get(&raw).copied())
                            .map(|cid| cid as u32)
                            .unwrap_or(u32::MAX)
                    })
                    .collect();

                let fields: Vec<(u32, u32, u32)> = dt
                    .fields
                    .iter()
                    .map(|(decl_raw, ftype_desc, fname)| {
                        let decl_cid = self
                            .by_raw_name
                            .get(decl_raw)
                            .copied()
                            .map(|c| c as u32)
                            .unwrap_or(u32::MAX);
                        let target_fid = if decl_cid != u32::MAX {
                            self.lookup_field_in_class(decl_cid as usize, fname, ftype_desc)
                                .map(|f| f as u32)
                                .unwrap_or(u32::MAX)
                        } else {
                            u32::MAX
                        };
                        let type_cid = descriptor_base_raw_class(ftype_desc)
                            .and_then(|raw| self.by_raw_name.get(&raw).copied())
                            .map(|c| c as u32)
                            .unwrap_or(u32::MAX);
                        (decl_cid, target_fid, type_cid)
                    })
                    .collect();

                let methods: Vec<(u32, u32, bool, Vec<u32>)> = dt
                    .methods
                    .iter()
                    .map(|(decl_raw, mname, proto_desc)| {
                        let decl_cid = self
                            .by_raw_name
                            .get(decl_raw)
                            .copied()
                            .map(|c| c as u32)
                            .unwrap_or(u32::MAX);
                        let target_mid = if decl_cid != u32::MAX {
                            self.lookup_method_in_class(decl_cid as usize, mname, proto_desc)
                                .map(|m| m as u32)
                                .unwrap_or(u32::MAX)
                        } else {
                            u32::MAX
                        };
                        let is_obj_init = decl_raw == "java.lang.Object"
                            && mname == "<init>"
                            && proto_desc == "()V";
                        let (ret_desc, param_descs) = parse_proto_descriptor(proto_desc);
                        let mut sig_cids = Vec::new();
                        if let Some(raw) = descriptor_base_raw_class(ret_desc) {
                            if let Some(&tcid) = self.by_raw_name.get(&raw) {
                                sig_cids.push(tcid as u32);
                            }
                        }
                        for pdesc in param_descs {
                            if let Some(raw) = descriptor_base_raw_class(pdesc) {
                                if let Some(&tcid) = self.by_raw_name.get(&raw) {
                                    sig_cids.push(tcid as u32);
                                }
                            }
                        }
                        (decl_cid, target_mid, is_obj_init, sig_cids)
                    })
                    .collect();

                DexResolvedTables {
                    type_cids,
                    fields,
                    methods,
                }
            })
            .collect();

        // 2. Instruction scan across all methods
        for mth in &self.methods {
            let mid = mth.id;
            let enclosing_cid = mth.parent_cls_id;
            let insns_bytes = self.method_insns_slice(mth);
            if insns_bytes.is_empty() {
                continue;
            }
            let dex_idx = mth.dex_idx;
            let dt = &self.dex_tables[dex_idx];
            let rdt = &resolved_dex[dex_idx];
            let insns = decode_instructions(insns_bytes);

            let mut record_method_use_of_class = |target_cid: usize| {
                if target_cid != enclosing_cid {
                    class_method_users_adj[target_cid].push(mid as u32);
                }
            };

            for insn in &insns {
                instructions_scanned += 1;
                match insn.ref_kind {
                    RefKind::MethodRef | RefKind::MethodAndProtoRef | RefKind::CallSiteRef => {
                        let m_idx = if insn.ref_kind == RefKind::CallSiteRef {
                            let Some(&t_idx) = dt.call_site_targets.get(&insn.index) else {
                                continue;
                            };
                            t_idx as usize
                        } else {
                            insn.index as usize
                        };
                        let Some((decl_cid, target_mid, is_obj_init, sig_cids)) =
                            rdt.methods.get(m_idx)
                        else {
                            continue;
                        };
                        if *decl_cid != u32::MAX {
                            record_method_use_of_class(*decl_cid as usize);
                        }
                        if *target_mid != u32::MAX {
                            let callee_mid = *target_mid as usize;
                            if callee_mid == mid {
                                self_calls[mid] = true;
                            } else {
                                method_callers_adj[callee_mid].push(mid as u32);
                            }
                        } else if !*is_obj_init && m_idx <= 0xFFFF {
                            let packed = ((dex_idx as u32) << 16) | (m_idx as u32);
                            unresolved_calls_adj[mid].push(packed);
                        }
                        for &scid in sig_cids {
                            record_method_use_of_class(scid as usize);
                        }
                    }
                    RefKind::FieldRef => {
                        let Some(&(decl_cid, target_fid, type_cid)) =
                            rdt.fields.get(insn.index as usize)
                        else {
                            continue;
                        };
                        if decl_cid != u32::MAX {
                            record_method_use_of_class(decl_cid as usize);
                        }
                        if target_fid != u32::MAX {
                            field_users_adj[target_fid as usize].push(mid as u32);
                        }
                        if type_cid != u32::MAX {
                            record_method_use_of_class(type_cid as usize);
                        }
                    }
                    RefKind::TypeRef => {
                        if let Some(&tcid) = rdt.type_cids.get(insn.index as usize) {
                            if tcid != u32::MAX {
                                record_method_use_of_class(tcid as usize);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        let build_ms = t0.elapsed().as_millis() as u64;
        ReverseIndex {
            build_ms,
            instructions_scanned,
            method_callers: CsrGraph::from_adj(method_callers_adj),
            field_users: CsrGraph::from_adj(field_users_adj),
            class_method_users: CsrGraph::from_adj(class_method_users_adj),
            class_users: CsrGraph::from_adj(class_users_adj),
            unresolved_calls: CsrGraph::from_adj(unresolved_calls_adj),
            self_calls,
        }
    }

    pub fn reverse_index_stats(&self) -> Option<Map<String, Value>> {
        let guard = self.reverse_index.read().unwrap();
        let idx = guard.as_ref()?;
        let mut m = Map::new();
        m.insert("buildMs".to_string(), Value::from(idx.build_ms));
        m.insert(
            "instructionsScanned".to_string(),
            Value::from(idx.instructions_scanned),
        );
        m.insert(
            "methodCallerEdges".to_string(),
            Value::from(idx.method_callers.edge_count()),
        );
        m.insert(
            "fieldUserEdges".to_string(),
            Value::from(idx.field_users.edge_count()),
        );
        m.insert(
            "classMethodUserEdges".to_string(),
            Value::from(idx.class_method_users.edge_count()),
        );
        m.insert(
            "classUserEdges".to_string(),
            Value::from(idx.class_users.edge_count()),
        );
        Some(m)
    }

    pub fn ref_entry_of_method(&self, mid: usize) -> Map<String, Value> {
        let m = &self.methods[mid];
        let c = &self.classes[m.parent_cls_id];
        let mut entry = Map::new();
        entry.insert("className".to_string(), Value::String(c.display_name.clone()));
        entry.insert("methodName".to_string(), Value::String(m.alias.clone()));
        entry.insert(
            "signature".to_string(),
            Value::String(m.pinned_signature()),
        );
        entry
    }

    pub fn ref_entry_of_external(
        &self,
        decl_raw: &str,
        method_name: &str,
        proto_desc: &str,
    ) -> Map<String, Value> {
        let mut entry = Map::new();
        entry.insert(
            "className".to_string(),
            Value::String(self.display_name_of_raw(decl_raw)),
        );
        entry.insert(
            "methodName".to_string(),
            Value::String(method_name.to_string()),
        );
        entry.insert(
            "signature".to_string(),
            Value::String(format!("{}{}", method_name, proto_desc)),
        );
        entry
    }

    pub fn ambiguity_notice(&self, method_name: &str, targets: &[usize]) -> Option<String> {
        if targets.len() < 2 {
            return None;
        }
        let mut sigs: Vec<String> = targets
            .iter()
            .map(|&mid| self.methods[mid].pinned_signature())
            .collect();
        sigs.sort();
        Some(marker(
            AMBIGUOUS_MARKER_PREFIX,
            &format!(
                "\"{}\" names {} methods in this class and this answer covers all of them: {}. Pass signature to ask about one.",
                method_name,
                targets.len(),
                sigs.join(", ")
            ),
        ))
    }

    pub fn field_ambiguity_notice(&self, field_name: &str, targets: &[usize]) -> Option<String> {
        if targets.len() < 2 {
            return None;
        }
        let mut entries: Vec<String> = targets
            .iter()
            .map(|&fid| {
                let f = &self.fields[fid];
                format!("{} {}", self.format_java_type(&f.type_desc), f.alias)
            })
            .collect();
        entries.sort();
        Some(marker(
            AMBIGUOUS_MARKER_PREFIX,
            &format!(
                "\"{}\" names {} fields in this class and this answer covers all of them: {}. Pass the full \"type name\" entry from get_fields_of_class to ask about one.",
                field_name,
                targets.len(),
                entries.join(", ")
            ),
        ))
    }

    // =========================================================================
    // Public API Tool Methods
    // =========================================================================

    pub fn get_apk_info(&self) -> Map<String, Value> {
        let exported_count = self
            .manifest_dom
            .as_ref()
            .map(|dom| get_exported_components_list(dom, &self.arsc).len())
            .unwrap_or(0);
        let main_act = self.get_main_activity_class();
        let mut info = Map::new();
        info.insert("apkPath".to_string(), Value::String(self.apk_path.clone()));
        info.insert(
            "packageName".to_string(),
            Value::String(self.package_name.clone()),
        );
        info.insert(
            "totalClasses".to_string(),
            Value::from(self.classes.len()),
        );
        info.insert(
            "exportedComponents".to_string(),
            Value::from(exported_count),
        );
        info.insert(
            "mainActivity".to_string(),
            main_act.map(Value::String).unwrap_or(Value::Null),
        );
        info
    }

    pub fn get_android_manifest(&self) -> Result<String, String> {
        let Some(ref xml) = self.manifest_xml else {
            return Err("AndroidManifest.xml not available".to_string());
        };
        Ok(guarded_text(
            xml.clone(),
            DEFAULT_MAX_BYTES,
            "getAndroidManifest",
            "AndroidManifest.xml",
            "get_deeplink_components and get_exported_components read the same declarations as structured data.",
        ))
    }

    pub fn get_main_activity_class(&self) -> Option<String> {
        let dom = self.manifest_dom.as_ref()?;
        extract_main_activity(dom, &self.package_name)
    }

    pub fn get_all_classes(&self, package_prefix: Option<&str>, limit: i32) -> Vec<String> {
        let prefix = package_prefix
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_lowercase());

        let mut names: Vec<String> = self
            .classes
            .iter()
            .map(|c| c.display_name.clone())
            .filter(|name| match &prefix {
                Some(p) => name.to_lowercase().starts_with(p),
                None => true,
            })
            .collect();
        names.sort();

        let scope = match &prefix {
            Some(p) => format!("packagePrefix={}", p),
            None => "no packagePrefix".to_string(),
        };
        let advice = "Pass packagePrefix or limit, or use search-classes, which answers the same question narrowly.";

        let lim = if limit > 0 { limit as usize } else { 0 };
        if lim > 0 && names.len() > lim {
            let total = names.len();
            let mut capped: Vec<String> = names.into_iter().take(lim).collect();
            let scope_suffix = match package_prefix.filter(|s| !s.is_empty()) {
                Some(raw_p) => format!(" under \"{}\"", raw_p),
                None => String::new(),
            };
            capped.push(marker(
                TRUNCATION_MARKER_PREFIX,
                &format!(
                    "showing {} of {} classes{}. Raise limit, narrow packagePrefix, or use search_classes_by_keyword for a name you already know part of.",
                    lim, total, scope_suffix
                ),
            ));
            if let Some(cut_notice) = oversized_notice(
                "getAllClasses",
                lim as i64,
                "class names",
                json_bytes_strings(&capped),
                &scope,
                advice,
            ) {
                capped.push(cut_notice);
            }
            return capped;
        }

        if let Some(notice) = oversized_notice(
            "getAllClasses",
            names.len() as i64,
            "class names",
            json_bytes_strings(&names),
            &scope,
            advice,
        ) {
            names.push(notice);
        }
        names
    }

    pub fn get_methods_of_class(&self, class_name: &str, limit: i32) -> Result<Vec<String>, String> {
        let Some(cid) = self.find_class_node(class_name)? else {
            return Err(format!("Class not found: {}", class_name));
        };
        let cls = &self.classes[cid];
        let mut by_name: HashMap<&str, usize> = HashMap::new();
        for &mid in &cls.method_ids {
            *by_name.entry(self.methods[mid].alias.as_str()).or_insert(0) += 1;
        }
        let mut out: Vec<String> = cls
            .method_ids
            .iter()
            .map(|&mid| {
                let m = &self.methods[mid];
                if by_name.get(m.alias.as_str()).copied().unwrap_or(0) > 1 {
                    format!("{}.{}", cls.display_name, m.pinned_signature())
                } else {
                    format!("{}.{}", cls.display_name, m.alias)
                }
            })
            .collect();
        out.sort();
        Ok(guarded_names(
            out,
            limit,
            "getMethodsOfClass",
            "methods",
            &format!("className={}", class_name),
            MEMBER_ADVICE,
        ))
    }

    pub fn get_fields_of_class(&self, class_name: &str, limit: i32) -> Result<Vec<String>, String> {
        let Some(cid) = self.find_class_node(class_name)? else {
            return Err(format!("Class not found: {}", class_name));
        };
        let cls = &self.classes[cid];
        let mut f_list: Vec<(String, String)> = cls
            .field_ids
            .iter()
            .map(|&fid| {
                let f = &self.fields[fid];
                (f.alias.clone(), self.format_java_type(&f.type_desc))
            })
            .collect();
        f_list.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let out: Vec<String> = f_list
            .into_iter()
            .map(|(name, tname)| format!("{} {}", tname, name))
            .collect();
        Ok(guarded_names(
            out,
            limit,
            "getFieldsOfClass",
            "fields",
            &format!("className={}", class_name),
            MEMBER_ADVICE,
        ))
    }

    pub fn get_class_source(&self, class_name: &str, max_bytes: i32) -> Result<String, String> {
        let Some(cid) = self.find_class_node(class_name)? else {
            return Err(format!("Class not found: {}", class_name));
        };
        // Follow inner class up to top-level parent class, matching JADX's codeOf(javaClass)
        let mut top_cid = cid;
        while let Some(pid) = self.classes[top_cid].parent_cls_id {
            if pid == top_cid {
                break;
            }
            top_cid = pid;
        }

        let source = decompile_class_java(self, top_cid);
        if max_bytes > 0 && json_cost(&source) > max_bytes as i64 {
            return self.outline_of(class_name, &source, max_bytes);
        }
        Ok(guarded_text(
            source,
            max_bytes,
            "getClassSource",
            &format!("\"{}\"", class_name),
            "A class this size is generated -- a resource table or a Kotlin stdlib facade. Use get_methods_of_class or get_fields_of_class to see what it declares, or get_method_by_name for the one member you want.",
        ))
    }

    fn outline_of(
        &self,
        class_name: &str,
        source: &str,
        max_bytes: i32,
    ) -> Result<String, String> {
        let fields = self.get_fields_of_class(class_name, DEFAULT_RESULT_LIMIT)?;
        let methods = self.get_methods_of_class(class_name, DEFAULT_RESULT_LIMIT)?;
        let mut body = String::new();
        body.push_str(&format!("fields ({}):\n", fields.len()));
        for f in &fields {
            body.push_str("  ");
            body.push_str(f);
            body.push('\n');
        }
        body.push_str(&format!("\nmethods ({}):\n", methods.len()));
        for m in &methods {
            body.push_str("  ");
            body.push_str(m);
            body.push('\n');
        }
        let char_count = source.chars().count();
        let notice = format!(
            "{}\n\n",
            marker(
                OUTLINE_MARKER_PREFIX,
                &format!(
                    "getClassSource returned the outline of \"{}\" instead of its source: the source is {} characters, over maxBytes={}. What it declares follows. Call get_method_by_name(className, methodName) for a body, or get_class_source with maxBytes=0 for the whole file.",
                    class_name, char_count, max_bytes
                )
            )
        );
        let left = budget_left_after(&notice, max_bytes) as i32;
        let guarded_body = guarded_text(
            body,
            left,
            "getClassSource",
            &format!("the outline of \"{}\"", class_name),
            "A class declaring this many members is generated -- an R table or a Kotlin stdlib facade -- so the member you want is better found with search_method_by_name.",
        );
        Ok(format!("{}{}", notice, guarded_body))
    }

    pub fn get_method_by_name(
        &self,
        class_name: &str,
        method_name: &str,
        signature: Option<&str>,
    ) -> Result<String, String> {
        let Some(cid) = self.find_class_node(class_name)? else {
            return Err(format!("Class not found: {}", class_name));
        };
        let targets = self.resolve_methods(cid, method_name, signature);
        if targets.is_empty() {
            return Err(self.no_such_method(cid, method_name, signature));
        }

        let mut code = String::new();
        if let Some(amb) = self.ambiguity_notice(method_name, &targets) {
            code.push_str(&amb);
            code.push_str("\n\n");
        }
        for (i, &mid) in targets.iter().enumerate() {
            if i > 0 {
                code.push_str("\n\n");
            }
            let src = decompile_method_java(self, cid, mid);
            code.push_str(&src);
        }
        Ok(guarded_text(
            code,
            DEFAULT_MAX_BYTES,
            "getMethodByName",
            &format!("\"{}.{}\"", class_name, method_name),
            "Pass signature to ask about one overload.",
        ))
    }

    pub fn search_classes_by_keyword(&self, keyword: Option<&str>, limit: i32) -> Vec<String> {
        if let Some(rej) = short_query_rejection("keyword", keyword, CLASS_SEARCH_COST) {
            return vec![rej];
        }
        let kw = keyword.unwrap_or("");
        let needle = kw.to_lowercase();
        let mut matches = BTreeSet::new();
        for cls in &self.classes {
            if cls.display_name.to_lowercase().contains(&needle) {
                matches.insert(cls.display_name.clone());
            }
        }
        let mut hits: Vec<String> = matches.into_iter().collect();
        let advice = "Pass limit, or a longer keyword.";
        let lim = if limit > 0 { limit as usize } else { 0 };
        if lim > 0 && hits.len() > lim {
            let total = hits.len();
            let mut capped: Vec<String> = hits.into_iter().take(lim).collect();
            capped.push(marker(
                TRUNCATION_MARKER_PREFIX,
                &format!(
                    "showing {} of {} classes matching \"{}\". Raise limit, or use a longer keyword -- this matches anywhere in the name, so one more character narrows it sharply.",
                    lim, total, kw
                ),
            ));
            if let Some(cut_notice) = oversized_notice(
                "searchClassesByKeyword",
                lim as i64,
                "class names",
                json_bytes_strings(&capped),
                &format!("keyword={}", kw),
                advice,
            ) {
                capped.push(cut_notice);
            }
            return capped;
        }
        if let Some(notice) = oversized_notice(
            "searchClassesByKeyword",
            hits.len() as i64,
            "class names",
            json_bytes_strings(&hits),
            &format!("keyword={}", kw),
            advice,
        ) {
            hits.push(notice);
        }
        hits
    }

    pub fn search_method_by_name(
        &self,
        method_name: Option<&str>,
        limit: i32,
    ) -> Map<String, Value> {
        let empty = method_name.map(|s| s.trim().is_empty()).unwrap_or(true);
        let cost_msg = format!(
            "{}{}",
            if empty {
                EMPTY_METHOD_SEARCH_COST
            } else {
                ONE_CHAR_METHOD_SEARCH_COST
            },
            METHOD_SEARCH_FLOOR_REASON
        );
        if let Some(rej) = short_query_rejection("methodName", method_name, &cost_msg) {
            let mut refused = Map::new();
            refused.insert(
                REJECTED_MARKER_PREFIX.to_string(),
                Value::Array(vec![Value::String(rej)]),
            );
            return refused;
        }
        let mname = method_name.unwrap_or("");
        let mut sorted_classes: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut matched_methods = 0usize;

        for cls in &self.classes {
            let mut seen = HashSet::new();
            let mut mlist = Vec::new();
            for &mid in &cls.method_ids {
                let m = &self.methods[mid];
                if m.alias.contains(mname) {
                    let full = format!("{}.{}", cls.display_name, m.alias);
                    if seen.insert(full.clone()) {
                        mlist.push(full);
                    }
                }
            }
            if !mlist.is_empty() {
                matched_methods += mlist.len();
                sorted_classes.insert(cls.display_name.clone(), mlist);
            }
        }

        let advice = "Pass limit, or a longer methodName.";
        let lim = if limit > 0 { limit as usize } else { 0 };
        if lim > 0 && sorted_classes.len() > lim {
            let total_classes = sorted_classes.len();
            let mut capped = Map::new();
            let mut capped_methods = 0i64;
            for (k, v) in sorted_classes.into_iter().take(lim) {
                capped_methods += v.len() as i64;
                capped.insert(
                    k,
                    Value::Array(v.into_iter().map(Value::String).collect()),
                );
            }
            capped.insert(
                TRUNCATION_MARKER_PREFIX.to_string(),
                Value::Array(vec![Value::String(marker(
                    TRUNCATION_MARKER_PREFIX,
                    &format!(
                        "showing {} of {} classes ({} methods) matching \"{}\". Raise limit, or use a longer methodName -- this matches anywhere in the name, so one more character narrows it sharply.",
                        lim, total_classes, matched_methods, mname
                    ),
                ))]),
            );
            let bytes = json_cost_of_value(&Value::Object(capped.clone()));
            if let Some(cut_notice) = oversized_notice(
                "searchMethodByName",
                capped_methods,
                "method names",
                bytes,
                &format!("methodName={}", mname),
                advice,
            ) {
                capped.insert(
                    OVERSIZED_MARKER_PREFIX.to_string(),
                    Value::Array(vec![Value::String(cut_notice)]),
                );
            }
            return capped;
        }

        let mut out = Map::new();
        for (k, v) in sorted_classes {
            out.insert(
                k,
                Value::Array(v.into_iter().map(Value::String).collect()),
            );
        }
        let bytes = json_cost_of_value(&Value::Object(out.clone()));
        if let Some(notice) = oversized_notice(
            "searchMethodByName",
            matched_methods as i64,
            "method names",
            bytes,
            &format!("methodName={}", mname),
            advice,
        ) {
            out.insert(
                OVERSIZED_MARKER_PREFIX.to_string(),
                Value::Array(vec![Value::String(notice)]),
            );
        }
        out
    }

    pub fn get_xrefs_to_class(
        &self,
        class_name: &str,
        limit: i32,
    ) -> Result<Vec<Map<String, Value>>, String> {
        let Some(cid) = self.find_class_node(class_name)? else {
            return Err(format!("Class not found: {}", class_name));
        };
        let ridx = self.ensure_reverse_index();
        let mut xrefs = Vec::new();
        let mut covered_classes = HashSet::new();
        for &mid in ridx.class_method_users.neighbors(cid) {
            let entry = self.ref_entry_of_method(mid as usize);
            if let Some(cn) = entry.get("className").and_then(|v| v.as_str()) {
                covered_classes.insert(cn.to_string());
            }
            xrefs.push(entry);
        }
        for &ucid in ridx.class_users.neighbors(cid) {
            let cname = &self.classes[ucid as usize].display_name;
            if covered_classes.insert(cname.clone()) {
                let mut entry = Map::new();
                entry.insert("className".to_string(), Value::String(cname.clone()));
                entry.insert("methodName".to_string(), Value::String(String::new()));
                entry.insert("signature".to_string(), Value::String(String::new()));
                xrefs.push(entry);
            }
        }
        sort_refs(&mut xrefs);
        Ok(guarded_refs(
            xrefs,
            limit,
            "getXrefsToClass",
            "references",
            &format!("className={}", class_name),
            XREF_ADVICE,
        ))
    }

    pub fn get_xrefs_to_method(
        &self,
        class_name: &str,
        method_name: &str,
        signature: Option<&str>,
        limit: i32,
    ) -> Result<Vec<Map<String, Value>>, String> {
        let Some(cid) = self.find_class_node(class_name)? else {
            return Err(format!("Class not found: {}", class_name));
        };
        let targets = self.resolve_methods(cid, method_name, signature);
        if targets.is_empty() {
            return Err(self.no_such_method(cid, method_name, signature));
        }
        let ridx = self.ensure_reverse_index();
        let mut raw_refs = Vec::new();
        for &tmid in &targets {
            for &caller_mid in ridx.method_callers.neighbors(tmid) {
                raw_refs.push(self.ref_entry_of_method(caller_mid as usize));
            }
        }
        let mut deduped = dedupe_refs(raw_refs);
        sort_refs(&mut deduped);
        let mut result = guarded_refs(
            deduped,
            limit,
            "getXrefsToMethod",
            "callers",
            &format!("{}.{}", class_name, method_name),
            XREF_ADVICE,
        );
        if let Some(amb) = self.ambiguity_notice(method_name, &targets) {
            let mut m = Map::new();
            m.insert(AMBIGUOUS_MARKER_PREFIX.to_string(), Value::String(amb));
            result.push(m);
        }
        Ok(result)
    }

    pub fn get_xrefs_to_field(
        &self,
        class_name: &str,
        field_name: &str,
        limit: i32,
    ) -> Result<Vec<Map<String, Value>>, String> {
        let Some(cid) = self.find_class_node(class_name)? else {
            return Err(format!("Class not found: {}", class_name));
        };
        let targets = self.resolve_fields(cid, field_name);
        if targets.is_empty() {
            return Err(format!(
                "Field not found: {} in class {}",
                field_name, self.classes[cid].display_name
            ));
        }
        let ridx = self.ensure_reverse_index();
        let mut raw_refs = Vec::new();
        for &tfid in &targets {
            for &user_mid in ridx.field_users.neighbors(tfid) {
                raw_refs.push(self.ref_entry_of_method(user_mid as usize));
            }
        }
        let mut deduped = dedupe_refs(raw_refs);
        sort_refs(&mut deduped);
        let mut result = guarded_refs(
            deduped,
            limit,
            "getXrefsToField",
            "users",
            &format!("{}.{}", class_name, field_name),
            XREF_ADVICE,
        );
        if let Some(amb) = self.field_ambiguity_notice(field_name, &targets) {
            let mut m = Map::new();
            m.insert(AMBIGUOUS_MARKER_PREFIX.to_string(), Value::String(amb));
            result.push(m);
        }
        Ok(result)
    }

    pub fn get_callees(
        &self,
        class_name: &str,
        method_name: &str,
        signature: Option<&str>,
        limit: i32,
    ) -> Result<Map<String, Value>, String> {
        let Some(cid) = self.find_class_node(class_name)? else {
            return Err(format!("Class not found: {}", class_name));
        };
        let targets = self.resolve_methods(cid, method_name, signature);
        if targets.is_empty() {
            return Err(self.no_such_method(cid, method_name, signature));
        }

        let mut internal = Vec::new();
        let mut external = Vec::new();
        let mut calls_self = false;

        for &tmid in &targets {
            let mth = &self.methods[tmid];
            let insns_bytes = self.method_insns_slice(mth);
            if insns_bytes.is_empty() {
                continue;
            }
            let dt = &self.dex_tables[mth.dex_idx];
            for insn in decode_instructions(insns_bytes) {
                let resolved_mref = match insn.ref_kind {
                    RefKind::MethodRef | RefKind::MethodAndProtoRef => {
                        dt.methods.get(insn.index as usize)
                    }
                    RefKind::CallSiteRef => dt
                        .call_site_targets
                        .get(&insn.index)
                        .and_then(|&t_idx| dt.methods.get(t_idx as usize)),
                    _ => None,
                };
                let Some((decl_raw, mname, proto_desc)) = resolved_mref else {
                    continue;
                };
                if let Some(&decl_cid) = self.by_raw_name.get(decl_raw) {
                    if let Some(callee_mid) =
                        self.lookup_method_in_class(decl_cid, mname, proto_desc)
                    {
                        if callee_mid == tmid {
                            calls_self = true;
                        } else {
                            internal.push(self.ref_entry_of_method(callee_mid));
                        }
                        continue;
                    }
                }
                if !(decl_raw == "java.lang.Object" && mname == "<init>" && proto_desc == "()V") {
                    external.push(self.ref_entry_of_external(decl_raw, mname, proto_desc));
                }
            }
        }

        let mut int_dedup = dedupe_refs(internal);
        sort_refs(&mut int_dedup);
        let mut ext_dedup = dedupe_refs(external);
        sort_refs(&mut ext_dedup);

        let scope = format!("{}.{}", class_name, method_name);
        let callees = guarded_refs(
            int_dedup,
            limit,
            "getCallees",
            "callees",
            &scope,
            CALLEE_ADVICE,
        );
        let externals = guarded_refs(
            ext_dedup,
            limit,
            "getCallees",
            "external calls",
            &scope,
            CALLEE_ADVICE,
        );
        let total_returned = (callees.len() + externals.len()) as i64;

        let mut result = Map::new();
        result.insert(
            "callees".to_string(),
            Value::Array(callees.into_iter().map(Value::Object).collect()),
        );
        result.insert(
            "external".to_string(),
            Value::Array(externals.into_iter().map(Value::Object).collect()),
        );
        result.insert("callsSelf".to_string(), Value::Bool(calls_self));
        if let Some(amb) = self.ambiguity_notice(method_name, &targets) {
            result.insert(
                AMBIGUOUS_MARKER_PREFIX.to_string(),
                Value::Array(vec![Value::String(amb)]),
            );
        }
        whole_response_notice(
            &mut result,
            "getCallees",
            total_returned,
            "calls",
            &scope,
            CALLEE_ADVICE,
        );
        Ok(result)
    }

    pub fn find_sink_call_sites(&self, sinks: Option<&[String]>, limit: i32) -> Map<String, Value> {
        let catalog: HashMap<&str, Vec<&str>> = default_sinks().into_iter().collect();
        let requested_tokens: Vec<String> = match sinks {
            Some(list) => {
                let filtered: Vec<String> = list
                    .iter()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if filtered.is_empty() {
                    default_sinks()
                        .into_iter()
                        .map(|(k, _)| k.to_string())
                        .collect()
                } else {
                    filtered
                }
            }
            None => default_sinks()
                .into_iter()
                .map(|(k, _)| k.to_string())
                .collect(),
        };

        struct SinkMatcher {
            key: String,
            decl_class: Option<String>,
        }

        let mut found: Vec<(String, BTreeMap<String, Map<String, Value>>)> = Vec::new();
        let mut key_to_idx: HashMap<String, usize> = HashMap::new();
        let mut by_method_name: HashMap<String, Vec<SinkMatcher>> = HashMap::new();

        for token in &requested_tokens {
            if !key_to_idx.contains_key(token) {
                let idx = found.len();
                key_to_idx.insert(token.clone(), idx);
                found.push((token.clone(), BTreeMap::new()));
            }
            let apis: Vec<String> = if let Some(cat_apis) = catalog.get(token.as_str()) {
                cat_apis.iter().map(|s| (*s).to_string()).collect()
            } else {
                vec![token.clone()]
            };
            for api in apis {
                let (decl_class, mname) = match api.rfind('.') {
                    Some(dot) => (Some(api[..dot].to_string()), api[dot + 1..].to_string()),
                    None => (None, api),
                };
                if mname.is_empty() {
                    continue;
                }
                by_method_name
                    .entry(mname)
                    .or_default()
                    .push(SinkMatcher {
                        key: token.clone(),
                        decl_class,
                    });
            }
        }

        let ridx = self.ensure_reverse_index();
        let mut resolved_in_apk: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        // Pre-match DEX method table entries once so scanning unresolved_calls is O(1) integer lookup
        let mut subtype_cache: HashMap<(String, String), bool> = HashMap::new();
        let mut check_subtype = |cand: &str, dc: &str, is_init: bool| -> bool {
            if is_init {
                return cand == dc;
            }
            if cand == dc {
                return true;
            }
            let key = (cand.to_string(), dc.to_string());
            if let Some(&cached) = subtype_cache.get(&key) {
                return cached;
            }
            let ok = self.is_subtype_or_equal(cand, dc);
            subtype_cache.insert(key, ok);
            ok
        };

        let mut matched_dex_methods: HashMap<u32, Vec<usize>> = HashMap::new();
        for (dex_idx, dt) in self.dex_tables.iter().enumerate() {
            for (m_idx, (decl_raw, callee_name, _proto)) in dt.methods.iter().enumerate() {
                if m_idx > 0xFFFF {
                    break;
                }
                if let Some(matchers) = by_method_name.get(callee_name) {
                    let is_init = callee_name == "<init>" || callee_name == "<clinit>";
                    let mut fidxs = Vec::new();
                    for matcher in matchers {
                        let recv_ok = match &matcher.decl_class {
                            Some(dc) => check_subtype(decl_raw.as_str(), dc.as_str(), is_init),
                            None => true,
                        };
                        if recv_ok {
                            fidxs.push(key_to_idx[&matcher.key]);
                        }
                    }
                    if !fidxs.is_empty() {
                        let packed = ((dex_idx as u32) << 16) | (m_idx as u32);
                        matched_dex_methods.insert(packed, fidxs);
                    }
                }
            }
        }

        for cls in &self.classes {
            for &mid in &cls.method_ids {
                let mth = &self.methods[mid];
                // 1. In-APK implementation resolution
                if let Some(matchers) = by_method_name.get(&mth.name) {
                    let is_init = mth.name == "<init>" || mth.name == "<clinit>";
                    for matcher in matchers {
                        let owner_ok = match &matcher.decl_class {
                            Some(dc) => check_subtype(cls.raw_name.as_str(), dc.as_str(), is_init),
                            None => true,
                        };
                        if !owner_ok {
                            continue;
                        }
                        let callers = ridx.method_callers.neighbors(mid);
                        if callers.is_empty() {
                            continue;
                        }
                        resolved_in_apk
                            .entry(matcher.key.clone())
                            .or_default()
                            .insert(cls.display_name.clone());
                        let fidx = key_to_idx[&matcher.key];
                        for &caller_mid in callers {
                            let entry = self.ref_entry_of_method(caller_mid as usize);
                            let dedup_key = format!(
                                "{}#{}",
                                entry.get("className").and_then(|v| v.as_str()).unwrap_or(""),
                                entry.get("signature").and_then(|v| v.as_str()).unwrap_or("")
                            );
                            found[fidx].1.entry(dedup_key).or_insert(entry);
                        }
                    }
                }

                // 2. Unresolved calls leaving the DEX
                for &packed_call in ridx.unresolved_calls.neighbors(mid) {
                    if let Some(fidxs) = matched_dex_methods.get(&packed_call) {
                        let entry = self.ref_entry_of_method(mid);
                        let dedup_key = format!(
                            "{}#{}",
                            entry.get("className").and_then(|v| v.as_str()).unwrap_or(""),
                            entry.get("signature").and_then(|v| v.as_str()).unwrap_or("")
                        );
                        for &fidx in fidxs {
                            found[fidx].1.entry(dedup_key.clone()).or_insert_with(|| entry.clone());
                        }
                    }
                }
            }
        }

        let mut result = Map::new();
        let mut truncated = Vec::new();
        let mut returned_sites = 0i64;
        let lim = if limit > 0 { limit as usize } else { 0 };

        for (sink_key, site_map) in found {
            let mut sites: Vec<Map<String, Value>> = site_map.into_values().collect();
            sort_refs(&mut sites);
            if lim > 0 && sites.len() > lim {
                truncated.push(Value::String(marker(
                    TRUNCATION_MARKER_PREFIX,
                    &format!(
                        "showing {} of {} call sites for \"{}\". Ask for this sink alone with limit 0 for the rest.",
                        lim,
                        sites.len(),
                        sink_key
                    ),
                )));
                sites.truncate(lim);
            }
            returned_sites += sites.len() as i64;
            result.insert(
                sink_key,
                Value::Array(sites.into_iter().map(Value::Object).collect()),
            );
        }

        if !truncated.is_empty() {
            result.insert(TRUNCATION_MARKER_PREFIX.to_string(), Value::Array(truncated));
        }

        let named_resolved = if !resolved_in_apk.is_empty() {
            let mut m = Map::new();
            for (k, set) in resolved_in_apk {
                let list: Vec<String> = set.into_iter().collect();
                let capped = capped_names(
                    list,
                    limit,
                    "in-APK types",
                    "Ask for this sink alone with limit 0 for the rest.",
                );
                m.insert(
                    k,
                    Value::Array(capped.into_iter().map(Value::String).collect()),
                );
            }
            Some(Value::Object(m))
        } else {
            None
        };

        let cost = json_cost_of_value(&Value::Object(result.clone()))
            + named_resolved
                .as_ref()
                .map(json_cost_of_value)
                .unwrap_or(0);
        let scope = match sinks {
            Some(s) if !s.is_empty() => format!("sinks={}", s.join(",")),
            _ => "the default catalogue".to_string(),
        };
        if let Some(notice) = oversized_notice(
            "findSinkCallSites",
            returned_sites,
            "call sites",
            cost,
            &scope,
            "Name the one sink you are reading and keep the default limit; a bare method name matches every receiver in the APK.",
        ) {
            result.insert(
                OVERSIZED_MARKER_PREFIX.to_string(),
                Value::Array(vec![Value::String(notice)]),
            );
        }
        if let Some(nr) = named_resolved {
            result.insert(RESOLVED_IN_APK_KEY.to_string(), nr);
        }
        result
    }

    pub fn get_type_hierarchy(&self, class_name: &str) -> Result<Map<String, Value>, String> {
        let hierarchy_advice = "This tool takes no limit; use get_all_classes with a packagePrefix, or search_classes_by_keyword, to enumerate.";
        let opt_cid = self.find_class_node(class_name)?;

        let mut result = Map::new();
        if let Some(cid) = opt_cid {
            let cls = &self.classes[cid];
            result.insert(
                "className".to_string(),
                Value::String(cls.display_name.clone()),
            );
            result.insert("inApk".to_string(), Value::Bool(true));
            result.insert(
                "superClass".to_string(),
                cls.super_raw_name
                    .as_ref()
                    .map(|sr| Value::String(self.display_name_of_raw(sr)))
                    .unwrap_or(Value::Null),
            );
            let ifaces: Vec<String> = cls
                .interface_raw_names
                .iter()
                .map(|ir| self.display_name_of_raw(ir))
                .collect();
            let ifaces_capped =
                capped_names(ifaces, DEFAULT_RESULT_LIMIT, "interfaces", hierarchy_advice);
            result.insert(
                "interfaces".to_string(),
                Value::Array(ifaces_capped.into_iter().map(Value::String).collect()),
            );

            let mut supers_display: BTreeSet<String> = BTreeSet::new();
            for sraw in self.transitive_supertypes_raw(&cls.raw_name) {
                supers_display.insert(self.display_name_of_raw(&sraw));
            }
            let supers_capped = capped_names(
                supers_display.into_iter().collect(),
                DEFAULT_RESULT_LIMIT,
                "supertypes",
                hierarchy_advice,
            );
            result.insert(
                "superTypes".to_string(),
                Value::Array(supers_capped.into_iter().map(Value::String).collect()),
            );

            let inners: Vec<String> = cls
                .inner_cls_ids
                .iter()
                .map(|&icid| self.classes[icid].display_name.clone())
                .collect();
            let inners_capped = capped_names(
                inners,
                DEFAULT_RESULT_LIMIT,
                "inner classes",
                hierarchy_advice,
            );
            result.insert(
                "innerClasses".to_string(),
                Value::Array(inners_capped.into_iter().map(Value::String).collect()),
            );

            let outer = cls
                .parent_cls_id
                .filter(|&pid| pid != cid)
                .map(|pid| Value::String(self.classes[pid].display_name.clone()))
                .unwrap_or(Value::Null);
            result.insert("outerClass".to_string(), outer);

            let subs = self.find_direct_subclasses(Some(cid), &cls.raw_name);
            let subs_capped = capped_names(
                subs,
                DEFAULT_RESULT_LIMIT,
                "direct subclasses",
                hierarchy_advice,
            );
            result.insert(
                "subClasses".to_string(),
                Value::Array(subs_capped.into_iter().map(Value::String).collect()),
            );
        } else {
            // Check if known framework or external type
            let is_known = !class_name.contains('/')
                && (self.framework.is_known(class_name)
                    || self.known_external_types.contains(class_name));
            if !is_known {
                return Err(format!("Class not found: {}", class_name));
            }
            result.insert("className".to_string(), Value::String(class_name.to_string()));
            result.insert("inApk".to_string(), Value::Bool(false));
            result.insert("superClass".to_string(), Value::Null);
            result.insert("interfaces".to_string(), Value::Array(Vec::new()));

            let mut supers_display: BTreeSet<String> = BTreeSet::new();
            for sraw in self.framework.super_types_of(class_name) {
                supers_display.insert(self.display_name_of_raw(&sraw));
            }
            let supers_capped = capped_names(
                supers_display.into_iter().collect(),
                DEFAULT_RESULT_LIMIT,
                "supertypes",
                hierarchy_advice,
            );
            result.insert(
                "superTypes".to_string(),
                Value::Array(supers_capped.into_iter().map(Value::String).collect()),
            );
            result.insert("innerClasses".to_string(), Value::Array(Vec::new()));
            result.insert("outerClass".to_string(), Value::Null);

            let subs = self.find_direct_subclasses(None, class_name);
            let subs_capped = capped_names(
                subs,
                DEFAULT_RESULT_LIMIT,
                "direct subclasses",
                hierarchy_advice,
            );
            result.insert(
                "subClasses".to_string(),
                Value::Array(subs_capped.into_iter().map(Value::String).collect()),
            );
        }

        let count_names = count_hierarchy_names(&result);
        let bytes = json_cost_of_value(&Value::Object(result.clone()));
        if let Some(notice) = oversized_notice(
            "getTypeHierarchy",
            count_names,
            "type names",
            bytes,
            &format!("className={}", class_name),
            hierarchy_advice,
        ) {
            result.insert(
                OVERSIZED_MARKER_PREFIX.to_string(),
                Value::Array(vec![Value::String(notice)]),
            );
        }
        Ok(result)
    }

    fn find_direct_subclasses(&self, target_cid: Option<usize>, target_raw: &str) -> Vec<String> {
        let mut subs = BTreeSet::new();
        for cand in &self.classes {
            let mut matched = false;
            if let Some(ref sr) = cand.super_raw_name {
                if let Some(tcid) = target_cid {
                    if self.by_raw_name.get(sr) == Some(&tcid) {
                        matched = true;
                    }
                } else if sr == target_raw {
                    matched = true;
                }
            }
            if !matched {
                for ir in &cand.interface_raw_names {
                    if let Some(tcid) = target_cid {
                        if self.by_raw_name.get(ir) == Some(&tcid) {
                            matched = true;
                            break;
                        }
                    } else if ir == target_raw {
                        matched = true;
                        break;
                    }
                }
            }
            if matched {
                subs.insert(cand.display_name.clone());
            }
        }
        subs.into_iter().collect()
    }

    pub fn get_overrides(
        &self,
        class_name: &str,
        method_name: &str,
        signature: Option<&str>,
        limit: i32,
    ) -> Result<Map<String, Value>, String> {
        let opt_cid = self.find_class_node(class_name)?;
        let bare_method = match method_name.rfind('.') {
            Some(dot) => &method_name[dot + 1..],
            None => method_name,
        };

        let mut base_methods = BTreeSet::new();
        let mut overridden_by = BTreeSet::new();
        let mut attribute_present = false;
        let mut reported_name = class_name.to_string();
        let mut reported_method = bare_method.to_string();
        let mut ambiguity = None;
        let mut target_raw_name = class_name.to_string();

        if let Some(cid) = opt_cid {
            let cls = &self.classes[cid];
            reported_name = cls.display_name.clone();
            target_raw_name = cls.raw_name.clone();
            let targets = self.resolve_methods(cid, method_name, signature);
            if targets.is_empty() {
                return Err(self.no_such_method(cid, method_name, signature));
            }
            reported_method = self.methods[targets[0]].alias.clone();
            ambiguity = self.ambiguity_notice(method_name, &targets);

            // Find base methods in supertypes
            if reported_method != "<init>" && reported_method != "<clinit>" {
                for sraw in self.transitive_supertypes_raw(&cls.raw_name) {
                    if let Some(&scid) = self.by_raw_name.get(&sraw) {
                        for &smid in &self.classes[scid].method_ids {
                            let sm = &self.methods[smid];
                            if sm.name == reported_method
                                && (sm.access_flags & 0x000a) == 0 // not private or static
                            {
                                attribute_present = true;
                                base_methods.insert(format!(
                                    "{}.{}",
                                    self.classes[scid].display_name, sm.alias
                                ));
                            }
                        }
                    } else if self.framework.declares_method(&sraw, &reported_method) {
                        attribute_present = true;
                        base_methods.insert(format!("{}.{}", sraw, reported_method));
                    }
                }
            }
        } else {
            let is_known = !class_name.contains('/')
                && (self.framework.is_known(class_name)
                    || self.known_external_types.contains(class_name));
            if !is_known {
                return Err(format!("Class not found: {}", class_name));
            }
        }

        // Sweep all classes in APK that are subtypes of target_raw_name and declare reported_method
        if reported_method != "<init>" && reported_method != "<clinit>" {
            for cand in &self.classes {
                if Some(cand.id) == opt_cid {
                    continue;
                }
                let has_method = cand.method_ids.iter().any(|&mid| {
                    let m = &self.methods[mid];
                    (m.alias == reported_method || m.name == reported_method)
                        && (m.access_flags & 0x000a) == 0
                });
                if !has_method {
                    continue;
                }
                if self.is_subtype_or_equal(&cand.raw_name, &target_raw_name) {
                    attribute_present = true;
                    overridden_by.insert(format!("{}.{}", cand.display_name, reported_method));
                }
            }
        }

        let scope = format!("{}.{}", reported_name, reported_method);
        let bases = guarded_names(
            base_methods.into_iter().collect(),
            limit,
            "getOverrides",
            "base methods",
            &scope,
            OVERRIDE_ADVICE,
        );
        let impls = guarded_names(
            overridden_by.into_iter().collect(),
            limit,
            "getOverrides",
            "implementations",
            &scope,
            OVERRIDE_ADVICE,
        );
        let total_names = (bases.len() + impls.len()) as i64;

        let mut result = Map::new();
        result.insert("className".to_string(), Value::String(reported_name));
        result.insert("methodName".to_string(), Value::String(reported_method));
        result.insert("inApk".to_string(), Value::Bool(opt_cid.is_some()));
        result.insert(
            "attributePresent".to_string(),
            Value::Bool(attribute_present),
        );
        result.insert(
            "baseMethods".to_string(),
            Value::Array(bases.into_iter().map(Value::String).collect()),
        );
        result.insert(
            "overriddenBy".to_string(),
            Value::Array(impls.into_iter().map(Value::String).collect()),
        );
        if let Some(amb) = ambiguity {
            result.insert(
                AMBIGUOUS_MARKER_PREFIX.to_string(),
                Value::Array(vec![Value::String(amb)]),
            );
        }
        whole_response_notice(
            &mut result,
            "getOverrides",
            total_names,
            "method names",
            &scope,
            OVERRIDE_ADVICE,
        );
        Ok(result)
    }

    pub fn get_exported_components(&self) -> Result<Vec<Map<String, Value>>, String> {
        let Some(ref dom) = self.manifest_dom else {
            return Err("AndroidManifest.xml not loaded".to_string());
        };
        Ok(get_exported_components_list(dom, &self.arsc))
    }

    pub fn get_deeplink_components(&self) -> Result<Vec<Map<String, Value>>, String> {
        let Some(ref dom) = self.manifest_dom else {
            return Err("AndroidManifest.xml not loaded".to_string());
        };
        Ok(get_deeplink_components_list(dom, &self.arsc))
    }

    pub fn get_all_resource_file_names(
        &self,
        path_prefix: Option<&str>,
        limit: i32,
    ) -> Vec<String> {
        let prefix = path_prefix
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_lowercase());

        let mut names: Vec<String> = self
            .resource_entries
            .iter()
            .map(|(n, _)| n.clone())
            .filter(|n| match &prefix {
                Some(p) => n.to_lowercase().starts_with(p),
                None => true,
            })
            .collect();
        names.sort();

        let scope = match &prefix {
            Some(p) => format!("pathPrefix={}", p),
            None => "no pathPrefix".to_string(),
        };
        guarded_names(
            names,
            limit,
            "getAllResourceFileNames",
            "resource file names",
            &scope,
            "Pass a pathPrefix -- res/xml is 24 of a large production APK's 16,559 names and holds the security config, the FileProvider paths and the App Links declaration.",
        )
    }

    pub fn get_resource_file(&self, file_name: &str, max_bytes: i32) -> Result<String, String> {
        if file_name == "AndroidManifest.xml" {
            if let Some(ref xml) = self.manifest_xml {
                return Ok(guarded_text(
                    xml.clone(),
                    max_bytes,
                    "getResourceFile",
                    &format!("\"{}\"", file_name),
                    RESOURCE_TOO_BIG,
                ));
            }
        }
        let file = File::open(&self.apk_path)
            .map_err(|e| format!("Error opening APK for resource: {}", e))?;
        let mut archive =
            ZipArchive::new(file).map_err(|e| format!("Error reading ZIP: {}", e))?;
        let Ok(mut entry) = archive.by_name(file_name) else {
            return Err(format!("Resource file not found or empty: {}", file_name));
        };
        let total = entry.size();
        let scope = format!("\"{}\"", file_name);

        if max_bytes <= 0 {
            let mut data = Vec::with_capacity(total as usize);
            entry
                .read_to_end(&mut data)
                .map_err(|e| format!("Error reading resource: {}", e))?;
            let whole = if data.len() >= 8 && data.starts_with(&[0x03, 0x00, 0x08, 0x00]) {
                decode_axml(&data, Some(&self.arsc))
                    .map(|(s, _)| s)
                    .unwrap_or_else(|_| String::from_utf8_lossy(&data).into_owned())
            } else {
                String::from_utf8_lossy(&data).into_owned()
            };
            let cost = json_cost(&whole);
            return Ok(with_oversized_notice(
                whole,
                cost,
                "getResourceFile",
                total as i64,
                "bytes",
                &scope,
                RESOURCE_TOO_BIG,
            ));
        }

        let want = (max_bytes as u64).saturating_add(4);
        let mut head = Vec::with_capacity(want.min(total) as usize);
        entry
            .take(want)
            .read_to_end(&mut head)
            .map_err(|e| format!("Error reading resource: {}", e))?;

        let text = if head.len() as u64 >= total
            && head.len() >= 8
            && head.starts_with(&[0x03, 0x00, 0x08, 0x00])
        {
            decode_axml(&head, Some(&self.arsc))
                .map(|(s, _)| s)
                .unwrap_or_else(|_| String::from_utf8_lossy(&head).into_owned())
        } else {
            String::from_utf8_lossy(&head).into_owned()
        };

        if (head.len() as u64) >= total && json_cost(&text) <= max_bytes as i64 {
            return Ok(text);
        }
        let notice = text_truncation_marker(
            "getResourceFile",
            max_bytes,
            &format!("{} bytes", total),
            &scope,
            RESOURCE_TOO_BIG,
        );
        let left = budget_left_after(&notice, max_bytes);
        Ok(format!("{}{}", notice, cut_to_json_budget(&text, left)))
    }

    pub fn get_smali_of_class(&self, class_name: &str, max_bytes: i32) -> Result<String, String> {
        let Some(cid) = self.find_class_node(class_name)? else {
            return Err(format!(
                "Class not found or smali not available: {}",
                class_name
            ));
        };
        let smali = disassemble_class_smali(self, cid);
        Ok(guarded_text(
            smali,
            max_bytes,
            "getSmaliOfClass",
            &format!("\"{}\"", class_name),
            "Smali runs several times the size of the source it came from; use get_smali_of_method for the one method you are reading.",
        ))
    }

    pub fn get_smali_of_method(
        &self,
        class_name: &str,
        method_name: &str,
        signature: Option<&str>,
    ) -> Result<String, String> {
        let Some(cid) = self.find_class_node(class_name)? else {
            return Err(format!(
                "Method not found or smali not available: {}.{}",
                class_name, method_name
            ));
        };
        let Some(smali) = disassemble_method_smali(self, cid, method_name, signature) else {
            return Err(format!(
                "Method not found or smali not available: {}.{}",
                class_name, method_name
            ));
        };
        Ok(guarded_text(
            smali,
            DEFAULT_MAX_BYTES,
            "getSmaliOfMethod",
            &format!("\"{}.{}\"", class_name, method_name),
            "Pass signature to ask about one overload.",
        ))
    }

    // =========================================================================
    // 4 Super RE Tools
    // =========================================================================

    pub fn search_strings_in_dex(
        &self,
        query: Option<&str>,
        package_prefix: Option<&str>,
        limit: i32,
    ) -> Vec<Map<String, Value>> {
        let q = query.unwrap_or("");
        if q.trim().chars().count() < MIN_QUERY_LENGTH {
            let mut m = Map::new();
            m.insert(
                REJECTED_MARKER_PREFIX.to_string(),
                Value::String(marker(
                    REJECTED_MARKER_PREFIX,
                    &format!(
                        "query \"{}\" is shorter than {} characters. Pass at least {} characters.",
                        q, MIN_QUERY_LENGTH, MIN_QUERY_LENGTH
                    ),
                )),
            );
            return vec![m];
        }

        let needle = q.to_lowercase();
        let pkg_prefix = package_prefix
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_lowercase());

        let mut hits: Vec<Map<String, Value>> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        for cls in &self.classes {
            if let Some(ref p) = pkg_prefix {
                if !cls.display_name.to_lowercase().starts_with(p) {
                    continue;
                }
            }

            // 1. Static String field initializers
            for &fid in &cls.field_ids {
                let fld = &self.fields[fid];
                if let Some(LiteralValue::String(ref s)) = fld.initial_value {
                    if s.to_lowercase().contains(&needle) {
                        let key = format!("{}#<field:{}>#{}", cls.display_name, fld.alias, s);
                        if seen.insert(key) {
                            let mut entry = Map::new();
                            entry.insert(
                                "className".to_string(),
                                Value::String(cls.display_name.clone()),
                            );
                            entry.insert("methodName".to_string(), Value::String(String::new()));
                            entry.insert(
                                "signature".to_string(),
                                Value::String(format!(
                                    "{} {}",
                                    self.format_java_type(&fld.type_desc),
                                    fld.alias
                                )),
                            );
                            entry.insert("value".to_string(), Value::String(s.clone()));
                            hits.push(entry);
                        }
                    }
                }
            }

            // 2. Method bytecode STRING_REF instructions
            for &mid in &cls.method_ids {
                let mth = &self.methods[mid];
                let insns_bytes = self.method_insns_slice(mth);
                if insns_bytes.is_empty() {
                    continue;
                }
                let dt = &self.dex_tables[mth.dex_idx];
                for insn in decode_instructions(insns_bytes) {
                    if insn.ref_kind != RefKind::StringRef {
                        continue;
                    }
                    let Some(s) = dt.strings.get(insn.index as usize) else {
                        continue;
                    };
                    if s.to_lowercase().contains(&needle) {
                        let sig = mth.pinned_signature();
                        let key = format!("{}#{}#{}", cls.display_name, sig, s);
                        if seen.insert(key) {
                            let mut entry = Map::new();
                            entry.insert(
                                "className".to_string(),
                                Value::String(cls.display_name.clone()),
                            );
                            entry.insert(
                                "methodName".to_string(),
                                Value::String(mth.alias.clone()),
                            );
                            entry.insert("signature".to_string(), Value::String(sig));
                            entry.insert("value".to_string(), Value::String(s.clone()));
                            hits.push(entry);
                        }
                    }
                }
            }
        }

        hits.sort_by(|a, b| {
            let ca = a.get("className").and_then(|v| v.as_str()).unwrap_or("");
            let cb = b.get("className").and_then(|v| v.as_str()).unwrap_or("");
            ca.cmp(cb)
                .then_with(|| {
                    let ma = a.get("methodName").and_then(|v| v.as_str()).unwrap_or("");
                    let mb = b.get("methodName").and_then(|v| v.as_str()).unwrap_or("");
                    ma.cmp(mb)
                })
                .then_with(|| {
                    let va = a.get("value").and_then(|v| v.as_str()).unwrap_or("");
                    let vb = b.get("value").and_then(|v| v.as_str()).unwrap_or("");
                    va.cmp(vb)
                })
        });

        guarded_refs(
            hits,
            limit,
            "searchStringsInDex",
            "string literals",
            &format!("query={}", q),
            "Narrow with packagePrefix or a longer query substring.",
        )
    }

    pub fn find_call_paths(
        &self,
        from_class: &str,
        from_method: &str,
        to_class: &str,
        to_method: &str,
        max_depth: i32,
        limit: i32,
    ) -> Result<Map<String, Value>, String> {
        let depth_cap = max_depth.clamp(1, 15) as usize;
        let path_cap = if limit <= 0 {
            20usize
        } else {
            (limit as usize).min(200)
        };

        let Some(to_cid) = self.find_class_node(to_class)? else {
            return Err(format!("Target class not found: {}", to_class));
        };
        let to_targets = self.resolve_methods(to_cid, to_method, None);
        if to_targets.is_empty() {
            return Err(self.no_such_method(to_cid, to_method, None));
        }

        let mut from_set: HashSet<usize> = HashSet::new();
        let has_from = !from_class.trim().is_empty() && !from_method.trim().is_empty();
        if has_from {
            let Some(from_cid) = self.find_class_node(from_class)? else {
                return Err(format!("Source class not found: {}", from_class));
            };
            let resolved = self.resolve_methods(from_cid, from_method, None);
            if resolved.is_empty() {
                return Err(self.no_such_method(from_cid, from_method, None));
            }
            from_set.extend(resolved);
        }

        let ridx = self.ensure_reverse_index();
        let mut paths: Vec<Value> = Vec::new();
        let mut queue: VecDeque<Vec<usize>> = VecDeque::new();
        let mut seen_endpoints: HashSet<usize> = HashSet::new();

        for &t in &to_targets {
            queue.push_back(vec![t]);
        }

        while let Some(chain) = queue.pop_front() {
            if paths.len() >= path_cap {
                break;
            }
            let head = chain[0];
            if chain.len() > 1 && has_from && from_set.contains(&head) {
                paths.push(Value::Array(
                    chain
                        .iter()
                        .map(|&m| Value::String(self.format_call_path_node(m)))
                        .collect(),
                ));
                continue;
            }
            if chain.len() > depth_cap {
                continue;
            }
            let callers = ridx.method_callers.neighbors(head);
            if callers.is_empty() && !has_from && chain.len() > 1 && seen_endpoints.insert(head) {
                paths.push(Value::Array(
                    chain
                        .iter()
                        .map(|&m| Value::String(self.format_call_path_node(m)))
                        .collect(),
                ));
                continue;
            }
            for &caller_u32 in callers {
                let caller = caller_u32 as usize;
                if chain.contains(&caller) {
                    continue;
                }
                let mut next = Vec::with_capacity(chain.len() + 1);
                next.push(caller);
                next.extend_from_slice(&chain);
                if !has_from && next.len() == depth_cap + 1 && seen_endpoints.insert(caller) {
                    paths.push(Value::Array(
                        next.iter()
                            .map(|&m| Value::String(self.format_call_path_node(m)))
                            .collect(),
                    ));
                    if paths.len() >= path_cap {
                        break;
                    }
                } else {
                    queue.push_back(next);
                }
            }
        }

        let mut out = Map::new();
        out.insert(
            "from".to_string(),
            Value::String(if has_from {
                format!("{}.{}", from_class, from_method)
            } else {
                "<any entry>".to_string()
            }),
        );
        out.insert(
            "to".to_string(),
            Value::String(format!("{}.{}", to_class, to_method)),
        );
        out.insert("maxDepth".to_string(), Value::from(depth_cap));
        out.insert("pathsFound".to_string(), Value::from(paths.len()));
        out.insert("paths".to_string(), Value::Array(paths));
        Ok(out)
    }

    fn format_call_path_node(&self, mid: usize) -> String {
        let m = &self.methods[mid];
        format!(
            "{}.{}",
            self.classes[m.parent_cls_id].display_name,
            m.pinned_signature()
        )
    }

    pub fn get_native_methods(
        &self,
        package_prefix: Option<&str>,
        limit: i32,
    ) -> Vec<Map<String, Value>> {
        let pkg_prefix = package_prefix
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_lowercase());

        let mut natives: Vec<Map<String, Value>> = Vec::new();
        for cls in &self.classes {
            if let Some(ref p) = pkg_prefix {
                if !cls.display_name.to_lowercase().starts_with(p) {
                    continue;
                }
            }

            let mut native_count: HashMap<&str, usize> = HashMap::new();
            for &mid in &cls.method_ids {
                let m = &self.methods[mid];
                if (m.access_flags & 0x0100) != 0 {
                    *native_count.entry(m.name.as_str()).or_insert(0) += 1;
                }
            }
            if native_count.is_empty() {
                continue;
            }

            let libs = self.scan_load_library_in_class(cls.id);
            for &mid in &cls.method_ids {
                let m = &self.methods[mid];
                if (m.access_flags & 0x0100) == 0 {
                    continue;
                }
                let overloaded = native_count.get(m.name.as_str()).copied().unwrap_or(0) > 1;
                let jni_sym = jni_mangle_symbol(&cls.raw_name, &m.name, &m.proto_desc, overloaded);
                let mut item = Map::new();
                item.insert(
                    "className".to_string(),
                    Value::String(cls.display_name.clone()),
                );
                item.insert("methodName".to_string(), Value::String(m.alias.clone()));
                item.insert(
                    "signature".to_string(),
                    Value::String(m.pinned_signature()),
                );
                item.insert("jniSymbol".to_string(), Value::String(jni_sym));
                item.insert(
                    "libraries".to_string(),
                    Value::Array(libs.iter().cloned().map(Value::String).collect()),
                );
                natives.push(item);
            }
        }

        natives.sort_by(|a, b| {
            let ca = a.get("className").and_then(|v| v.as_str()).unwrap_or("");
            let cb = b.get("className").and_then(|v| v.as_str()).unwrap_or("");
            ca.cmp(cb).then_with(|| {
                let sa = a.get("signature").and_then(|v| v.as_str()).unwrap_or("");
                let sb = b.get("signature").and_then(|v| v.as_str()).unwrap_or("");
                sa.cmp(sb)
            })
        });

        let lim = if limit > 0 { limit as usize } else { 0 };
        if lim > 0 && natives.len() > lim {
            let total = natives.len();
            let mut capped: Vec<Map<String, Value>> = natives.into_iter().take(lim).collect();
            let mut trunc = Map::new();
            trunc.insert(
                TRUNCATION_MARKER_PREFIX.to_string(),
                Value::String(marker(
                    TRUNCATION_MARKER_PREFIX,
                    &truncation_text(lim, total, "native methods", RAISE_LIMIT),
                )),
            );
            capped.push(trunc);
            return capped;
        }
        natives
    }

    fn scan_load_library_in_class(&self, cid: usize) -> Vec<String> {
        let cls = &self.classes[cid];
        let mut libs = BTreeSet::new();
        for &mid in &cls.method_ids {
            let mth = &self.methods[mid];
            let insns_bytes = self.method_insns_slice(mth);
            if insns_bytes.is_empty() {
                continue;
            }
            let dt = &self.dex_tables[mth.dex_idx];
            let mut last_string: Option<String> = None;
            for insn in decode_instructions(insns_bytes) {
                if insn.ref_kind == RefKind::StringRef {
                    last_string = dt.strings.get(insn.index as usize).cloned();
                } else if insn.ref_kind == RefKind::MethodRef {
                    if let Some((_, mname, _)) = dt.methods.get(insn.index as usize) {
                        if mname == "loadLibrary" || mname == "load" {
                            if let Some(ref s) = last_string {
                                if !s.is_empty() {
                                    libs.insert(s.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
        libs.into_iter().collect()
    }

    pub fn get_re_recon(&self, package_prefix: Option<&str>) -> Map<String, Value> {
        let pkg_prefix = package_prefix
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_lowercase());

        let mut total_classes = 0usize;
        let mut scoped_classes = 0usize;
        let mut total_methods = 0usize;
        let mut native_method_count = 0usize;
        let mut short_named_classes = 0usize;

        let mut crypto_classes = BTreeSet::new();
        let mut network_classes = BTreeSet::new();
        let mut auth_classes = BTreeSet::new();
        let mut native_bridge_classes = BTreeSet::new();
        let mut reflection_classes = BTreeSet::new();
        let mut xor_heavy_methods = BTreeSet::new();
        let mut frameworks = BTreeSet::new();
        let mut protections = BTreeSet::new();

        for cls in &self.classes {
            total_classes += 1;
            let name = &cls.display_name;
            let lower = name.to_lowercase();

            if lower.starts_with("kotlin.") || lower.starts_with("kotlinx.") {
                frameworks.insert("Kotlin".to_string());
            } else if lower.starts_with("okhttp3.") || lower.starts_with("com.squareup.okhttp") {
                frameworks.insert("OkHttp".to_string());
            } else if lower.starts_with("retrofit2.") {
                frameworks.insert("Retrofit".to_string());
            } else if lower.starts_with("io.flutter.") {
                frameworks.insert("Flutter".to_string());
            } else if lower.starts_with("com.facebook.react.") {
                frameworks.insert("ReactNative".to_string());
            } else if lower.starts_with("com.unity3d.") {
                frameworks.insert("Unity".to_string());
            } else if lower.starts_with("org.cocos2dx.") {
                frameworks.insert("Cocos2d-x".to_string());
            } else if lower.starts_with("com.google.gson.") {
                frameworks.insert("Gson".to_string());
            } else if lower.starts_with("com.google.protobuf.") {
                frameworks.insert("Protobuf".to_string());
            } else if lower.starts_with("io.reactivex.") || lower.starts_with("rx.") {
                frameworks.insert("RxJava".to_string());
            }

            if lower.contains("qihoo.util") || lower.contains("stub.stubapp") {
                protections.insert("360 Jiagu / StubApp".to_string());
            } else if lower.contains("secneo") || lower.contains("bangcle") {
                protections.insert("Bangcle / SecNeo".to_string());
            } else if lower.contains("ijiami") {
                protections.insert("iJiami".to_string());
            } else if lower.contains("tencent.stub") || lower.contains(" wrapperproxyapplication")
            {
                protections.insert("Tencent Legu".to_string());
            }

            let simple = match cls.raw_name.rfind('.') {
                Some(dot) => &cls.raw_name[dot + 1..],
                None => cls.raw_name.as_str(),
            };
            if simple.len() <= 2
                || cls.raw_name.starts_with("X.")
                || simple
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_digit())
                    .unwrap_or(false)
            {
                short_named_classes += 1;
            }

            let in_scope = match &pkg_prefix {
                Some(p) => lower.starts_with(p),
                None => true,
            };
            if !in_scope {
                continue;
            }
            scoped_classes += 1;

            if (lower.contains("crypt")
                || lower.contains("cipher")
                || lower.contains("aes")
                || lower.contains("rsa")
                || lower.contains("hmac")
                || lower.contains("sign")
                || lower.contains("digest"))
                && crypto_classes.len() < 40
            {
                crypto_classes.insert(name.clone());
            }
            if (lower.contains("http")
                || lower.contains("socket")
                || lower.contains("interceptor")
                || lower.contains("request")
                || lower.contains("api")
                || lower.contains("client")
                || lower.contains("packet"))
                && network_classes.len() < 40
            {
                network_classes.insert(name.clone());
            }
            if (lower.contains("auth")
                || lower.contains("token")
                || lower.contains("login")
                || lower.contains("session")
                || lower.contains("credential")
                || lower.contains("license")
                || lower.contains("vip")
                || lower.contains("verify"))
                && auth_classes.len() < 40
            {
                auth_classes.insert(name.clone());
            }

            for &mid in &cls.method_ids {
                let mth = &self.methods[mid];
                total_methods += 1;
                if (mth.access_flags & 0x0100) != 0 {
                    native_method_count += 1;
                    if native_bridge_classes.len() < 40 {
                        native_bridge_classes.insert(name.clone());
                    }
                }
                if crypto_classes.len() >= 40
                    && reflection_classes.len() >= 40
                    && xor_heavy_methods.len() >= 40
                {
                    continue;
                }
                let insns_bytes = self.method_insns_slice(mth);
                if insns_bytes.is_empty() {
                    continue;
                }
                let dt = &self.dex_tables[mth.dex_idx];
                let mut xor_count = 0usize;
                for insn in decode_instructions(insns_bytes) {
                    if insn.is_xor() {
                        xor_count += 1;
                    } else if insn.ref_kind == RefKind::MethodRef {
                        if let Some((decl_raw, _, _)) = dt.methods.get(insn.index as usize) {
                            if decl_raw.starts_with("javax.crypto.")
                                || decl_raw.starts_with("java.security.")
                            {
                                if crypto_classes.len() < 40 {
                                    crypto_classes.insert(name.clone());
                                }
                            } else if (decl_raw == "java.lang.Class"
                                || decl_raw.starts_with("java.lang.reflect.")
                                || decl_raw.starts_with("dalvik.system."))
                                && reflection_classes.len() < 40
                            {
                                reflection_classes.insert(name.clone());
                            }
                        }
                    }
                }
                if xor_count >= 4 && xor_heavy_methods.len() < 40 {
                    xor_heavy_methods.insert(format!(
                        "{}.{} (xor={})",
                        name, mth.alias, xor_count
                    ));
                }
            }
        }

        if total_classes > 10 && short_named_classes * 100 / total_classes >= 25 {
            protections.insert(format!(
                "Identifier obfuscation (ProGuard/R8: {}% short class names)",
                short_named_classes * 100 / total_classes
            ));
        }

        let mut native_libs = BTreeSet::new();
        for (res_name, _) in &self.resource_entries {
            if res_name.ends_with(".so") && native_libs.len() < 100 {
                native_libs.insert(res_name.clone());
            }
            if res_name.contains("libil2cpp.so") {
                frameworks.insert("Unity IL2CPP".to_string());
            } else if res_name.contains("libflutter.so") || res_name.contains("libapp.so") {
                frameworks.insert("Flutter AOT".to_string());
            } else if res_name.contains("libhermes.so") {
                frameworks.insert("ReactNative Hermes".to_string());
            }
        }

        let app_class = self
            .manifest_dom
            .as_ref()
            .and_then(|dom| extract_application_class(dom, &self.package_name));

        let mut counts = Map::new();
        counts.insert("totalClasses".to_string(), Value::from(total_classes));
        counts.insert("scopedClasses".to_string(), Value::from(scoped_classes));
        counts.insert("scopedMethods".to_string(), Value::from(total_methods));
        counts.insert(
            "nativeMethods".to_string(),
            Value::from(native_method_count),
        );
        counts.insert(
            "exportedComponents".to_string(),
            Value::from(
                self.manifest_dom
                    .as_ref()
                    .map(|dom| get_exported_components_list(dom, &self.arsc).len())
                    .unwrap_or(0),
            ),
        );

        let mut targets = Map::new();
        targets.insert(
            "cryptoAndSigning".to_string(),
            Value::Array(crypto_classes.into_iter().map(Value::String).collect()),
        );
        targets.insert(
            "networkAndProtocol".to_string(),
            Value::Array(network_classes.into_iter().map(Value::String).collect()),
        );
        targets.insert(
            "authAndSession".to_string(),
            Value::Array(auth_classes.into_iter().map(Value::String).collect()),
        );
        targets.insert(
            "nativeBridges".to_string(),
            Value::Array(
                native_bridge_classes
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        );
        targets.insert(
            "reflectionAndDynamicLoad".to_string(),
            Value::Array(reflection_classes.into_iter().map(Value::String).collect()),
        );
        targets.insert(
            "xorHeavyMethods".to_string(),
            Value::Array(xor_heavy_methods.into_iter().map(Value::String).collect()),
        );

        let mut out = Map::new();
        out.insert("apkPath".to_string(), Value::String(self.apk_path.clone()));
        out.insert("format".to_string(), Value::String(self.format.clone()));
        out.insert(
            "packageName".to_string(),
            Value::String(self.package_name.clone()),
        );
        out.insert(
            "mainActivity".to_string(),
            self.get_main_activity_class()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        out.insert(
            "applicationClass".to_string(),
            app_class.map(Value::String).unwrap_or(Value::Null),
        );
        out.insert("counts".to_string(), Value::Object(counts));
        out.insert(
            "nativeLibraries".to_string(),
            Value::Array(native_libs.into_iter().map(Value::String).collect()),
        );
        out.insert(
            "frameworks".to_string(),
            Value::Array(frameworks.into_iter().map(Value::String).collect()),
        );
        out.insert(
            "protections".to_string(),
            Value::Array(protections.into_iter().map(Value::String).collect()),
        );
        out.insert("highValueTargets".to_string(), Value::Object(targets));
        out
    }

    fn read_raw_zip_entry(&self, entry_name: &str) -> Result<Vec<u8>, String> {
        let file = File::open(&self.apk_path)
            .map_err(|e| format!("Error opening APK for native entry {}: {}", entry_name, e))?;
        let mut archive =
            ZipArchive::new(file).map_err(|e| format!("Error reading APK ZIP: {}", e))?;
        let mut entry = archive
            .by_name(entry_name)
            .map_err(|_| format!("Entry not found in APK: {}", entry_name))?;
        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry
            .read_to_end(&mut buf)
            .map_err(|e| format!("Error reading {}: {}", entry_name, e))?;
        Ok(buf)
    }

    fn build_dex_native_lookup(
        &self,
    ) -> (
        HashMap<(String, String), Vec<String>>,
        HashMap<String, (String, String, String)>,
    ) {
        let mut dex_native_map: HashMap<(String, String), Vec<String>> = HashMap::new();
        let mut dex_jni_sym_map: HashMap<String, (String, String, String)> = HashMap::new();

        for cls in &self.classes {
            let mut native_count: HashMap<&str, usize> = HashMap::new();
            for &mid in &cls.method_ids {
                let m = &self.methods[mid];
                if (m.access_flags & 0x0100) != 0 {
                    *native_count.entry(m.name.as_str()).or_insert(0) += 1;
                }
            }
            if native_count.is_empty() {
                continue;
            }
            for &mid in &cls.method_ids {
                let m = &self.methods[mid];
                if (m.access_flags & 0x0100) == 0 {
                    continue;
                }
                dex_native_map
                    .entry((m.name.clone(), m.proto_desc.clone()))
                    .or_default()
                    .push(cls.display_name.clone());

                let overloaded = native_count.get(m.name.as_str()).copied().unwrap_or(0) > 1;
                let jni_sym = jni_mangle_symbol(&cls.raw_name, &m.name, &m.proto_desc, overloaded);
                dex_jni_sym_map.insert(
                    jni_sym,
                    (
                        cls.display_name.clone(),
                        m.name.clone(),
                        m.proto_desc.clone(),
                    ),
                );
                if overloaded {
                    let base_sym = jni_mangle_symbol(&cls.raw_name, &m.name, &m.proto_desc, false);
                    dex_jni_sym_map.entry(base_sym).or_insert_with(|| {
                        (
                            cls.display_name.clone(),
                            m.name.clone(),
                            m.proto_desc.clone(),
                        )
                    });
                }
            }
        }
        (dex_native_map, dex_jni_sym_map)
    }

    pub fn get_native_lib_info(&self, lib_name: &str) -> Result<Map<String, Value>, String> {
        let Some(entry_name) = resolve_so_entry_name(&self.resource_entries, lib_name) else {
            return Err(format!(
                "Native library not found in APK matching: {}",
                lib_name
            ));
        };
        let bytes = self.read_raw_zip_entry(&entry_name)?;
        let elf = ParsedElf::parse(&bytes)?;
        Ok(elf.build_info_report(&entry_name))
    }

    pub fn resolve_register_natives(
        &self,
        lib_name: Option<&str>,
        class_name: Option<&str>,
        limit: i32,
    ) -> Result<Vec<Map<String, Value>>, String> {
        let class_filter = class_name
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_lowercase());

        let (dex_native_map, dex_jni_sym_map) = self.build_dex_native_lookup();

        // Determine candidate `.so` entries to inspect
        let so_entries: Vec<String> = if let Some(ln) =
            lib_name.map(|s| s.trim()).filter(|s| !s.is_empty())
        {
            let Some(resolved) = resolve_so_entry_name(&self.resource_entries, ln) else {
                return Err(format!("Native library not found in APK matching: {}", ln));
            };
            vec![resolved]
        } else {
            // If className is given and calls System.loadLibrary, prioritize those libraries first
            let mut hinted_entries = Vec::new();
            if let Some(cls_q) = class_name.map(|s| s.trim()).filter(|s| !s.is_empty()) {
                if let Ok(Some(cid)) = self.find_class_node(cls_q) {
                    for lib in self.scan_load_library_in_class(cid) {
                        if let Some(res) = resolve_so_entry_name(&self.resource_entries, &lib) {
                            if !hinted_entries.contains(&res) {
                                hinted_entries.push(res);
                            }
                        }
                    }
                }
            }
            if !hinted_entries.is_empty() {
                hinted_entries
            } else {
                // Collect unique `.so` libraries preferring arm64-v8a
                let mut by_basename: BTreeMap<String, String> = BTreeMap::new();
                for (name, _) in &self.resource_entries {
                    if !name.ends_with(".so") {
                        continue;
                    }
                    let base = match name.rfind('/') {
                        Some(idx) => &name[idx + 1..],
                        None => name.as_str(),
                    };
                    let replace = match by_basename.get(base) {
                        None => true,
                        Some(existing) => !existing.contains("arm64-v8a") && name.contains("arm64-v8a"),
                    };
                    if replace {
                        by_basename.insert(base.to_string(), name.clone());
                    }
                }
                by_basename.into_values().take(40).collect()
            }
        };

        let mut out: Vec<Map<String, Value>> = Vec::new();
        let lim = if limit > 0 { limit as usize } else { 0 };

        for entry_name in so_entries {
            let Ok(bytes) = self.read_raw_zip_entry(&entry_name) else {
                continue;
            };
            let Ok(elf) = ParsedElf::parse(&bytes) else {
                continue;
            };
            for reg in elf.resolve_register_natives(&dex_native_map, &dex_jni_sym_map) {
                if let Some(ref cf) = class_filter {
                    let matches_cls = reg
                        .matched_java_classes
                        .iter()
                        .any(|c| c.to_lowercase().contains(cf))
                        || reg.method_name.to_lowercase().contains(cf);
                    if !matches_cls {
                        continue;
                    }
                }
                let mut m = Map::new();
                m.insert("library".to_string(), Value::String(entry_name.clone()));
                m.insert(
                    "methodName".to_string(),
                    Value::String(reg.method_name.clone()),
                );
                m.insert(
                    "signature".to_string(),
                    Value::String(reg.signature.clone()),
                );
                m.insert(
                    "fnVaddr".to_string(),
                    Value::String(format!("0x{:x}", reg.fn_vaddr)),
                );
                m.insert("resolution".to_string(), Value::String(reg.source));
                if let Some(tv) = reg.table_vaddr {
                    m.insert(
                        "tableOrCodeVaddr".to_string(),
                        Value::String(format!("0x{:x}", tv)),
                    );
                }
                m.insert(
                    "matchedJavaClasses".to_string(),
                    Value::Array(
                        reg.matched_java_classes
                            .into_iter()
                            .map(Value::String)
                            .collect(),
                    ),
                );
                out.push(m);
            }
        }

        if lim > 0 && out.len() > lim {
            out.truncate(lim);
        }
        Ok(out)
    }

    pub fn search_native_strings(
        &self,
        lib_name: &str,
        query: Option<&str>,
        limit: i32,
    ) -> Result<Vec<Map<String, Value>>, String> {
        let Some(entry_name) = resolve_so_entry_name(&self.resource_entries, lib_name) else {
            return Err(format!(
                "Native library not found in APK matching: {}",
                lib_name
            ));
        };
        let bytes = self.read_raw_zip_entry(&entry_name)?;
        let elf = ParsedElf::parse(&bytes)?;
        let lim = if limit > 0 { limit as usize } else { 100 };
        Ok(elf.search_strings_with_xrefs(query, lim))
    }

    pub fn disassemble_native_arm64(
        &self,
        lib_name: &str,
        target: &str,
        instructions: i32,
    ) -> Result<Map<String, Value>, String> {
        let Some(entry_name) = resolve_so_entry_name(&self.resource_entries, lib_name) else {
            return Err(format!(
                "Native library not found in APK matching: {}",
                lib_name
            ));
        };
        let bytes = self.read_raw_zip_entry(&entry_name)?;
        let elf = ParsedElf::parse(&bytes)?;
        let count = if instructions > 0 {
            instructions as usize
        } else {
            64
        };
        let mut res = elf.disassemble_arm64(target, count)?;
        res.insert("library".to_string(), Value::String(entry_name));
        Ok(res)
    }

    pub fn analyze_native_function(
        &self,
        lib_name: &str,
        target: &str,
        max_instructions: i32,
    ) -> Result<Map<String, Value>, String> {
        let Some(entry_name) = resolve_so_entry_name(&self.resource_entries, lib_name) else {
            return Err(format!(
                "Native library not found in APK matching: {}",
                lib_name
            ));
        };
        let bytes = self.read_raw_zip_entry(&entry_name)?;
        let elf = ParsedElf::parse(&bytes)?;
        let budget = if max_instructions > 0 {
            max_instructions as usize
        } else {
            256
        };
        let mut res = elf.analyze_function_arm64(target, budget)?;
        res.insert("library".to_string(), Value::String(entry_name));
        Ok(res)
    }
}

fn is_dex_entry(name: &str) -> bool {
    let base = match name.rfind('/') {
        Some(idx) => &name[idx + 1..],
        None => name,
    };
    base.starts_with("classes") && base.ends_with(".dex") && !name.starts_with("assets/")
}

fn dex_sort_key(name: &str) -> (u32, String) {
    let base = match name.rfind('/') {
        Some(idx) => &name[idx + 1..],
        None => name,
    };
    let num_part = base
        .trim_start_matches("classes")
        .trim_end_matches(".dex");
    let idx = if num_part.is_empty() {
        1
    } else {
        num_part.parse::<u32>().unwrap_or(999)
    };
    (idx, name.to_string())
}

fn compute_jadx_deobf_class_name(raw_name: &str, cls_def_idx: usize) -> Option<String> {
    // Check if top-level short name is 1 character (like `R`), which JADX renames to `C0303R`
    let (pkg, cls_part) = match raw_name.rfind('.') {
        Some(dot) => (&raw_name[..dot], &raw_name[dot + 1..]),
        None => ("", raw_name),
    };
    let mut segments: Vec<String> = Vec::new();
    let mut changed = false;
    for (i, seg) in cls_part.split('$').enumerate() {
        if i == 0 && seg.len() < 2 {
            changed = true;
            segments.push(format!("C{:04}{}", cls_def_idx, seg));
        } else {
            segments.push(seg.to_string());
        }
    }
    if !changed {
        return None;
    }
    if pkg.is_empty() {
        Some(segments.join("$"))
    } else {
        Some(format!("{}.{}", pkg, segments.join("$")))
    }
}

fn strip_jadx_deobf_in_class_query(query: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    for seg in query.split('.') {
        let mut sub_parts = Vec::new();
        for s in seg.split('$') {
            if let Some(rest) = s.strip_prefix('C') {
                let digits = rest.chars().take_while(|c| c.is_ascii_digit()).count();
                if digits >= 4 && rest.len() > digits {
                    sub_parts.push(rest[digits..].to_string());
                    continue;
                }
            }
            sub_parts.push(s.to_string());
        }
        parts.push(sub_parts.join("$"));
    }
    parts.join(".")
}

fn strip_jadx_method_prefix(name: &str) -> Option<&str> {
    let rest = name.strip_prefix('m')?;
    let digits = rest.chars().take_while(|c| c.is_ascii_digit()).count();
    if digits >= 1 && rest.len() > digits {
        Some(&rest[digits..])
    } else {
        None
    }
}

fn dedupe_refs(xrefs: Vec<Map<String, Value>>) -> Vec<Map<String, Value>> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(xrefs.len());
    for x in xrefs {
        let key = format!(
            "{}#{}",
            x.get("className").and_then(|v| v.as_str()).unwrap_or(""),
            x.get("signature").and_then(|v| v.as_str()).unwrap_or("")
        );
        if seen.insert(key) {
            out.push(x);
        }
    }
    out
}

fn sort_refs(xrefs: &mut [Map<String, Value>]) {
    xrefs.sort_by(|a, b| {
        let ca = a.get("className").and_then(|v| v.as_str()).unwrap_or("");
        let cb = b.get("className").and_then(|v| v.as_str()).unwrap_or("");
        ca.cmp(cb).then_with(|| {
            let ma = a.get("methodName").and_then(|v| v.as_str()).unwrap_or("");
            let mb = b.get("methodName").and_then(|v| v.as_str()).unwrap_or("");
            ma.cmp(mb)
        })
    });
}

fn count_hierarchy_names(result: &Map<String, Value>) -> i64 {
    let mut count = 0i64;
    for v in result.values() {
        if let Value::Array(arr) = v {
            for elem in arr {
                if let Value::String(s) = elem {
                    if !s.starts_with('@') {
                        count += 1;
                    }
                }
            }
        }
    }
    count
}

pub fn jni_mangle_symbol(
    raw_class: &str,
    method_name: &str,
    proto_desc: &str,
    overloaded: bool,
) -> String {
    let mut sb = String::from("Java_");
    sb.push_str(&jni_escape(&raw_class.replace('/', ".")));
    sb.push('_');
    sb.push_str(&jni_escape(method_name));
    if overloaded {
        if let Some(rparen) = proto_desc.find(')') {
            if proto_desc.starts_with('(') && rparen > 1 {
                let args = &proto_desc[1..rparen];
                sb.push_str("__");
                sb.push_str(&jni_escape(&args.replace('/', ".")));
            }
        }
    }
    sb
}

fn jni_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '.' | '/' => out.push('_'),
            '_' => out.push_str("_1"),
            ';' => out.push_str("_2"),
            '[' => out.push_str("_3"),
            '$' => out.push_str("_00024"),
            c if c.is_ascii_alphanumeric() => out.push(c),
            c => out.push_str(&format!("_0{:04x}", c as u32)),
        }
    }
    out
}
