use std::collections::HashMap;
use serde_json::{Map, Value};
use crate::guards::{
    json_cost_of_value, marker, oversized_notice, truncation_text, DEFAULT_RESULT_LIMIT,
    OVERSIZED_MARKER_PREFIX, TRUNCATION_MARKER_PREFIX,
};

#[derive(Debug, Clone, Default)]
pub struct ArscTable {
    /// Maps "key" (for type == "string" in default config) -> literal string value
    pub string_values: HashMap<String, String>,
    /// Maps resource ID (e.g. 0x7f040001) -> (type_name, entry_key_name)
    pub id_to_ref: HashMap<u32, (String, String)>,
}

impl ArscTable {
    pub fn parse(data: &[u8]) -> Self {
        let mut table = ArscTable::default();
        if data.len() < 12 || read_u16(data, 0) != 0x0002 {
            return table;
        }
        let header_size = read_u16(data, 2) as usize;
        let file_size = (read_u32(data, 4) as usize).min(data.len());
        let mut pos = header_size;
        let mut global_strings: Vec<String> = Vec::new();

        while pos + 8 <= file_size {
            let chunk_type = read_u16(data, pos);
            let chunk_header_size = read_u16(data, pos + 2) as usize;
            let chunk_size = read_u32(data, pos + 4) as usize;
            if chunk_size < 8 || pos + chunk_size > file_size {
                break;
            }
            match chunk_type {
                0x0001 => {
                    global_strings = parse_string_pool(&data[pos..pos + chunk_size]);
                }
                0x0200 => {
                    parse_package_chunk(
                        &data[pos..pos + chunk_size],
                        chunk_header_size,
                        &global_strings,
                        &mut table,
                    );
                }
                _ => {}
            }
            pos += chunk_size;
        }
        table
    }

    pub fn format_ref(&self, res_id: u32) -> String {
        if let Some((type_name, key_name)) = self.id_to_ref.get(&res_id) {
            format!("@{}/{}", type_name, key_name)
        } else if (res_id >> 24) == 0x01 {
            format!("@android:0x{:08x}", res_id)
        } else {
            format!("@0x{:08x}", res_id)
        }
    }

    pub fn resolve_string_ref(&self, value: &str) -> String {
        if !value.starts_with('@') {
            return value.to_string();
        }
        if let Some(slash) = value.find('/') {
            let rtype = &value[1..slash];
            let key = &value[slash + 1..];
            if rtype == "string" {
                if let Some(resolved) = self.string_values.get(key) {
                    return resolved.clone();
                }
            }
            return value.to_string();
        }
        // Check hex @0x7f... or @7F...
        let hex_part = value.trim_start_matches('@').trim_start_matches("0x").trim_start_matches("0X");
        if let Ok(res_id) = u32::from_str_radix(hex_part, 16) {
            if let Some((rtype, key)) = self.id_to_ref.get(&res_id) {
                if rtype == "string" {
                    if let Some(resolved) = self.string_values.get(key) {
                        return resolved.clone();
                    }
                }
            }
        }
        value.to_string()
    }
}

fn parse_package_chunk(
    pkg_data: &[u8],
    header_size: usize,
    global_strings: &[String],
    table: &mut ArscTable,
) {
    if pkg_data.len() < 284 || header_size < 284 {
        return;
    }
    let pkg_id = read_u32(pkg_data, 8) & 0xff;
    let type_strings_off = read_u32(pkg_data, 268) as usize;
    let key_strings_off = read_u32(pkg_data, 276) as usize;

    let type_strings = if type_strings_off > 0 && type_strings_off + 8 <= pkg_data.len() {
        let sz = read_u32(pkg_data, type_strings_off + 4) as usize;
        if type_strings_off + sz <= pkg_data.len() {
            parse_string_pool(&pkg_data[type_strings_off..type_strings_off + sz])
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let key_strings = if key_strings_off > 0 && key_strings_off + 8 <= pkg_data.len() {
        let sz = read_u32(pkg_data, key_strings_off + 4) as usize;
        if key_strings_off + sz <= pkg_data.len() {
            parse_string_pool(&pkg_data[key_strings_off..key_strings_off + sz])
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let mut pos = header_size;
    while pos + 8 <= pkg_data.len() {
        let ctype = read_u16(pkg_data, pos);
        let cheader = read_u16(pkg_data, pos + 2) as usize;
        let csize = read_u32(pkg_data, pos + 4) as usize;
        if csize < 8 || pos + csize > pkg_data.len() {
            break;
        }
        if ctype == 0x0201 && cheader >= 20 && csize >= cheader {
            let type_id = pkg_data[pos + 8] as usize;
            let flags = pkg_data[pos + 9];
            let entry_count = read_u32(pkg_data, pos + 12) as usize;
            let entries_start = read_u32(pkg_data, pos + 16) as usize;
            let type_name = if type_id >= 1 && type_id - 1 < type_strings.len() {
                type_strings[type_id - 1].clone()
            } else {
                String::new()
            };

            // Check if config is default locale (language & country bytes at pos + 20 + 8..12)
            let is_default_locale = if cheader >= 32 {
                let lang0 = pkg_data[pos + 28];
                let lang1 = pkg_data[pos + 29];
                let cnt0 = pkg_data[pos + 30];
                let cnt1 = pkg_data[pos + 31];
                lang0 == 0 && lang1 == 0 && cnt0 == 0 && cnt1 == 0
            } else {
                true
            };

            let is_sparse = (flags & 0x01) != 0;
            let is_offset16 = (flags & 0x02) != 0;
            let offsets_base = pos + cheader;
            let data_base = pos + entries_start;

            if !is_sparse && data_base <= pos + csize {
                for idx in 0..entry_count {
                    let entry_off = if is_offset16 {
                        if offsets_base + idx * 2 + 2 > pkg_data.len() {
                            break;
                        }
                        let off16 = read_u16(pkg_data, offsets_base + idx * 2);
                        if off16 == 0xFFFF {
                            continue;
                        }
                        (off16 as usize) * 4
                    } else {
                        if offsets_base + idx * 4 + 4 > pkg_data.len() {
                            break;
                        }
                        let off32 = read_u32(pkg_data, offsets_base + idx * 4);
                        if off32 == 0xFFFFFFFF {
                            continue;
                        }
                        off32 as usize
                    };

                    let epos = data_base + entry_off;
                    if epos + 8 > pos + csize {
                        continue;
                    }
                    let eflags = read_u16(pkg_data, epos + 2);
                    let key_idx = read_u32(pkg_data, epos + 4) as usize;
                    let Some(key_name) = key_strings.get(key_idx) else {
                        continue;
                    };
                    let res_id = (pkg_id << 24) | (((type_id as u32) & 0xff) << 16) | (idx as u32);
                    if !type_name.is_empty() && !key_name.is_empty() {
                        table
                            .id_to_ref
                            .entry(res_id)
                            .or_insert_with(|| (type_name.clone(), key_name.clone()));
                    }
                    if type_name == "string" && (eflags & 0x0001) == 0 && epos + 16 <= pos + csize {
                        let val_type = pkg_data[epos + 11];
                        let val_data = read_u32(pkg_data, epos + 12) as usize;
                        if val_type == 0x03 {
                            if let Some(s) = global_strings.get(val_data) {
                                if is_default_locale || !table.string_values.contains_key(key_name) {
                                    table.string_values.insert(key_name.clone(), s.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
        pos += csize;
    }
}

#[derive(Debug, Clone)]
pub struct XmlElement {
    pub name: String,
    pub attributes: Vec<(String, String)>,
    pub children: Vec<XmlElement>,
    pub text: String,
}

impl XmlElement {
    pub fn get_attr(&self, attr_name: &str) -> Option<&str> {
        let bare = attr_name.strip_prefix("android:").unwrap_or(attr_name);
        for (k, v) in &self.attributes {
            if k == attr_name || k == bare {
                return Some(v.as_str());
            }
        }
        None
    }

    pub fn find_all<'a>(&'a self, tag: &str, out: &mut Vec<&'a XmlElement>) {
        if self.name == tag {
            out.push(self);
        }
        for child in &self.children {
            child.find_all(tag, out);
        }
    }
}

pub fn decode_axml(data: &[u8], arsc: Option<&ArscTable>) -> Result<(String, XmlElement), String> {
    // Handle plain text XML if not binary AXML
    if data.len() >= 5 && (data.starts_with(b"<?xml") || data.starts_with(b"<manifest")) {
        let text = String::from_utf8_lossy(data).into_owned();
        let root = parse_text_xml(&text);
        return Ok((text, root));
    }
    if data.len() < 8 || read_u16(data, 0) != 0x0003 {
        return Err("Not a valid binary Android XML document".to_string());
    }

    let header_size = read_u16(data, 2) as usize;
    let file_size = (read_u32(data, 4) as usize).min(data.len());
    let mut pos = header_size;

    let mut strings: Vec<String> = Vec::new();
    let mut res_ids: Vec<u32> = Vec::new();
    let mut ns_uri_to_prefix: HashMap<u32, String> = HashMap::new();
    let mut pending_namespaces: Vec<(String, String)> = Vec::new();

    let mut stack: Vec<XmlElement> = Vec::new();
    let mut root_elem: Option<XmlElement> = None;

    while pos + 8 <= file_size {
        let chunk_type = read_u16(data, pos);
        let chunk_header_size = read_u16(data, pos + 2) as usize;
        let chunk_size = read_u32(data, pos + 4) as usize;
        if chunk_size < 8 || pos + chunk_size > file_size {
            break;
        }
        let chunk = &data[pos..pos + chunk_size];

        match chunk_type {
            0x0001 => {
                strings = parse_string_pool(chunk);
            }
            0x0180 => {
                let count = (chunk_size.saturating_sub(chunk_header_size)) / 4;
                for i in 0..count {
                    res_ids.push(read_u32(chunk, chunk_header_size + i * 4));
                }
            }
            0x0100 => {
                // RES_XML_START_NAMESPACE_TYPE
                if chunk.len() >= 24 {
                    let prefix_idx = read_u32(chunk, 16) as usize;
                    let uri_idx = read_u32(chunk, 20);
                    let prefix = strings.get(prefix_idx).cloned().unwrap_or_default();
                    let uri = strings.get(uri_idx as usize).cloned().unwrap_or_default();
                    if !prefix.is_empty() && !uri.is_empty() {
                        ns_uri_to_prefix.insert(uri_idx, prefix.clone());
                        pending_namespaces.push((format!("xmlns:{}", prefix), uri));
                    }
                }
            }
            0x0102 => {
                // RES_XML_START_ELEMENT_TYPE
                if chunk.len() >= chunk_header_size + 20 {
                    let ext = &chunk[chunk_header_size..];
                    let _ns_idx = read_u32(ext, 0);
                    let name_idx = read_u32(ext, 4) as usize;
                    let attr_start = read_u16(ext, 8) as usize;
                    let attr_size = (read_u16(ext, 10) as usize).max(20);
                    let attr_count = read_u16(ext, 12) as usize;

                    let elem_name = strings
                        .get(name_idx)
                        .cloned()
                        .unwrap_or_else(|| "element".to_string());

                    let mut attributes = Vec::new();
                    for (k, v) in pending_namespaces.drain(..) {
                        attributes.push((k, v));
                    }

                    for i in 0..attr_count {
                        let aoff = attr_start + i * attr_size;
                        if aoff + 20 > ext.len() {
                            break;
                        }
                        let ans_idx = read_u32(ext, aoff);
                        let aname_idx = read_u32(ext, aoff + 4) as usize;
                        let raw_val_idx = read_u32(ext, aoff + 8);
                        let data_type = ext[aoff + 15];
                        let data_val = read_u32(ext, aoff + 16);

                        let mut attr_name = strings.get(aname_idx).cloned().unwrap_or_default();
                        let res_id = res_ids.get(aname_idx).copied().unwrap_or(0);
                        if attr_name.is_empty() && res_id != 0 {
                            attr_name = android_attr_name(res_id).to_string();
                        }
                        let prefix = if ans_idx != 0xFFFFFFFF {
                            ns_uri_to_prefix
                                .get(&ans_idx)
                                .cloned()
                                .or_else(|| {
                                    strings.get(ans_idx as usize).and_then(|u| {
                                        if u.contains("schemas.android.com/apk/res/android") {
                                            Some("android".to_string())
                                        } else {
                                            None
                                        }
                                    })
                                })
                        } else if (res_id >> 24) == 0x01 {
                            Some("android".to_string())
                        } else {
                            None
                        };

                        let full_attr_name = if let Some(p) = prefix {
                            if !p.is_empty() && !attr_name.contains(':') {
                                format!("{}:{}", p, attr_name)
                            } else {
                                attr_name
                            }
                        } else {
                            attr_name
                        };

                        let attr_val = format_attr_value(
                            raw_val_idx,
                            data_type,
                            data_val,
                            &strings,
                            arsc,
                            &full_attr_name,
                        );
                        attributes.push((full_attr_name, attr_val));
                    }

                    stack.push(XmlElement {
                        name: elem_name,
                        attributes,
                        children: Vec::new(),
                        text: String::new(),
                    });
                }
            }
            0x0103 => {
                // RES_XML_END_ELEMENT_TYPE
                if let Some(elem) = stack.pop() {
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(elem);
                    } else {
                        root_elem = Some(elem);
                    }
                }
            }
            0x0104 => {
                // RES_XML_CDATA_TYPE
                if chunk.len() >= 20 {
                    let data_idx = read_u32(chunk, 16) as usize;
                    if let Some(s) = strings.get(data_idx) {
                        if let Some(curr) = stack.last_mut() {
                            curr.text.push_str(s);
                        }
                    }
                }
            }
            _ => {}
        }
        pos += chunk_size;
    }

    while let Some(elem) = stack.pop() {
        if let Some(parent) = stack.last_mut() {
            parent.children.push(elem);
        } else {
            root_elem = Some(elem);
        }
    }

    let root = root_elem.ok_or_else(|| "Empty binary XML document".to_string())?;
    let mut xml_out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    render_xml_element(&root, 0, &mut xml_out);
    Ok((xml_out, root))
}

fn render_xml_element(elem: &XmlElement, indent: usize, out: &mut String) {
    let pad = "    ".repeat(indent);
    out.push_str(&pad);
    out.push('<');
    out.push_str(&elem.name);
    for (k, v) in &elem.attributes {
        out.push(' ');
        out.push_str(k);
        out.push_str("=\"");
        out.push_str(&escape_xml(v));
        out.push('"');
    }
    if elem.children.is_empty() && elem.text.is_empty() {
        out.push_str("/>\n");
        return;
    }
    out.push('>');
    if elem.children.is_empty() {
        out.push_str(&escape_xml(&elem.text));
        out.push_str("</");
        out.push_str(&elem.name);
        out.push_str(">\n");
        return;
    }
    out.push('\n');
    for child in &elem.children {
        render_xml_element(child, indent + 1, out);
    }
    out.push_str(&pad);
    out.push_str("</");
    out.push_str(&elem.name);
    out.push_str(">\n");
}

fn escape_xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

fn format_attr_value(
    raw_val_idx: u32,
    data_type: u8,
    data_val: u32,
    strings: &[String],
    arsc: Option<&ArscTable>,
    _attr_name: &str,
) -> String {
    match data_type {
        0x03 => {
            if let Some(s) = strings.get(data_val as usize) {
                return s.clone();
            }
            if raw_val_idx != 0xFFFFFFFF {
                if let Some(s) = strings.get(raw_val_idx as usize) {
                    return s.clone();
                }
            }
            String::new()
        }
        0x01 => {
            if data_val == 0 {
                return "@null".to_string();
            }
            if let Some(table) = arsc {
                table.format_ref(data_val)
            } else {
                format!("@0x{:08x}", data_val)
            }
        }
        0x02 => format!("?0x{:08x}", data_val),
        0x04 => format!("{}", f32::from_bits(data_val)),
        0x10 => format!("{}", data_val as i32),
        0x11 => format!("0x{:x}", data_val),
        0x12 => {
            if data_val != 0 {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        0x1c..=0x1f => format!("#{:08x}", data_val),
        _ => {
            if raw_val_idx != 0xFFFFFFFF {
                if let Some(s) = strings.get(raw_val_idx as usize) {
                    return s.clone();
                }
            }
            format!("0x{:x}", data_val)
        }
    }
}

fn android_attr_name(res_id: u32) -> &'static str {
    match res_id {
        0x01010000 => "theme",
        0x01010001 => "label",
        0x01010002 => "icon",
        0x01010003 => "name",
        0x01010006 => "permission",
        0x01010007 => "readPermission",
        0x01010008 => "writePermission",
        0x0101000e => "enabled",
        0x0101000f => "debuggable",
        0x01010010 => "exported",
        0x01010011 => "process",
        0x01010012 => "taskAffinity",
        0x01010013 => "multiprocess",
        0x01010018 => "authorities",
        0x0101001b => "grantUriPermissions",
        0x0101001c => "priority",
        0x0101001d => "launchMode",
        0x0101001e => "screenOrientation",
        0x0101001f => "configChanges",
        0x01010020 => "description",
        0x01010024 => "value",
        0x01010025 => "resource",
        0x01010026 => "mimeType",
        0x01010027 => "scheme",
        0x01010028 => "host",
        0x01010029 => "port",
        0x0101002a => "path",
        0x0101002b => "pathPrefix",
        0x0101002c => "pathPattern",
        0x01010202 => "targetActivity",
        0x0101020c => "minSdkVersion",
        0x01010270 => "targetSdkVersion",
        0x01010271 => "maxSdkVersion",
        0x01010280 => "allowBackup",
        0x010103f2 => "supportsRtl",
        0x010104ea => "autoVerify",
        0x010104ec => "roundIcon",
        0x010104ee => "pathSuffix",
        0x0101052c => "networkSecurityConfig",
        0x01010540 => "compileSdkVersion",
        0x01010572 => "compileSdkVersionCodename",
        0x01010590 => "appComponentFactory",
        _ => "attr",
    }
}

fn parse_string_pool(chunk: &[u8]) -> Vec<String> {
    if chunk.len() < 28 {
        return Vec::new();
    }
    let header_size = read_u16(chunk, 2) as usize;
    let string_count = read_u32(chunk, 8) as usize;
    let flags = read_u32(chunk, 16);
    let strings_start = read_u32(chunk, 20) as usize;
    let is_utf8 = (flags & (1 << 8)) != 0;

    let mut out = Vec::with_capacity(string_count.min(65536));
    for i in 0..string_count {
        let off_pos = header_size + i * 4;
        if off_pos + 4 > chunk.len() {
            break;
        }
        let rel_off = read_u32(chunk, off_pos) as usize;
        let spos = strings_start + rel_off;
        if spos >= chunk.len() {
            out.push(String::new());
            continue;
        }
        if is_utf8 {
            let mut p = spos;
            if p >= chunk.len() {
                out.push(String::new());
                continue;
            }
            let b0 = chunk[p];
            p += if (b0 & 0x80) != 0 { 2 } else { 1 };
            if p >= chunk.len() {
                out.push(String::new());
                continue;
            }
            let l0 = chunk[p] as usize;
            let byte_len = if (l0 & 0x80) != 0 {
                if p + 1 >= chunk.len() {
                    0
                } else {
                    p += 1;
                    ((l0 & 0x7f) << 8) | (chunk[p] as usize)
                }
            } else {
                l0
            };
            p += 1;
            let end = (p + byte_len).min(chunk.len());
            out.push(String::from_utf8_lossy(&chunk[p..end]).into_owned());
        } else {
            let mut p = spos;
            if p + 2 > chunk.len() {
                out.push(String::new());
                continue;
            }
            let w0 = read_u16(chunk, p) as usize;
            let char_len = if (w0 & 0x8000) != 0 {
                if p + 4 > chunk.len() {
                    0
                } else {
                    p += 2;
                    ((w0 & 0x7fff) << 16) | (read_u16(chunk, p) as usize)
                }
            } else {
                w0
            };
            p += 2;
            let mut u16_buf = Vec::with_capacity(char_len.min(4096));
            for c in 0..char_len {
                let cp = p + c * 2;
                if cp + 2 > chunk.len() {
                    break;
                }
                u16_buf.push(read_u16(chunk, cp));
            }
            out.push(String::from_utf16_lossy(&u16_buf));
        }
    }
    out
}

/// Minimal text XML parser fallback in case a test APK has plain-text AndroidManifest.xml
fn parse_text_xml(xml: &str) -> XmlElement {
    let mut stack: Vec<XmlElement> = Vec::new();
    let mut root: Option<XmlElement> = None;
    let bytes = xml.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            if i + 1 < bytes.len() && (bytes[i + 1] == b'?' || bytes[i + 1] == b'!') {
                if let Some(end) = xml[i..].find('>') {
                    i += end + 1;
                    continue;
                }
                break;
            }
            if i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                if let Some(end) = xml[i..].find('>') {
                    if let Some(elem) = stack.pop() {
                        if let Some(parent) = stack.last_mut() {
                            parent.children.push(elem);
                        } else {
                            root = Some(elem);
                        }
                    }
                    i += end + 1;
                    continue;
                }
                break;
            }
            if let Some(end) = xml[i..].find('>') {
                let tag_body = xml[i + 1..i + end].trim();
                let self_closing = tag_body.ends_with('/');
                let clean = tag_body.trim_end_matches('/').trim();
                let mut parts = clean.splitn(2, char::is_whitespace);
                let name = parts.next().unwrap_or("").to_string();
                let attr_str = parts.next().unwrap_or("");
                let attributes = parse_text_attrs(attr_str);
                let elem = XmlElement {
                    name,
                    attributes,
                    children: Vec::new(),
                    text: String::new(),
                };
                if self_closing {
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(elem);
                    } else {
                        root = Some(elem);
                    }
                } else {
                    stack.push(elem);
                }
                i += end + 1;
                continue;
            }
        }
        i += 1;
    }
    while let Some(elem) = stack.pop() {
        if let Some(parent) = stack.last_mut() {
            parent.children.push(elem);
        } else {
            root = Some(elem);
        }
    }
    root.unwrap_or_else(|| XmlElement {
        name: "manifest".to_string(),
        attributes: Vec::new(),
        children: Vec::new(),
        text: String::new(),
    })
}

fn parse_text_attrs(s: &str) -> Vec<(String, String)> {
    let mut attrs = Vec::new();
    let mut rest = s.trim();
    while let Some(eq) = rest.find('=') {
        let key = rest[..eq].trim().to_string();
        rest = rest[eq + 1..].trim_start();
        if let Some(quote) = rest.chars().next() {
            if quote == '"' || quote == '\'' {
                rest = &rest[1..];
                if let Some(end_q) = rest.find(quote) {
                    let val = rest[..end_q].to_string();
                    attrs.push((key, val));
                    rest = rest[end_q + 1..].trim_start();
                    continue;
                }
            }
        }
        break;
    }
    attrs
}

pub const DATA_ATTRS: [&str; 8] = [
    "scheme",
    "host",
    "port",
    "path",
    "pathPrefix",
    "pathPattern",
    "pathSuffix",
    "mimeType",
];

pub fn qualify_component_name(name: &str, pkg: &str) -> String {
    if name.is_empty() {
        return String::new();
    }
    if name.starts_with('.') {
        format!("{}{}", pkg, name)
    } else if !name.contains('.') && !pkg.is_empty() {
        format!("{}.{}", pkg, name)
    } else {
        name.to_string()
    }
}

pub fn extract_main_activity(manifest: &XmlElement, pkg: &str) -> Option<String> {
    for tag in ["activity", "activity-alias"] {
        let mut nodes = Vec::new();
        manifest.find_all(tag, &mut nodes);
        for activity in nodes {
            let mut filters = Vec::new();
            activity.find_all("intent-filter", &mut filters);
            for filter in filters {
                let mut actions = Vec::new();
                filter.find_all("action", &mut actions);
                let mut categories = Vec::new();
                filter.find_all("category", &mut categories);
                let has_main = actions
                    .iter()
                    .any(|a| a.get_attr("android:name") == Some("android.intent.action.MAIN"));
                let has_launcher = categories
                    .iter()
                    .any(|c| c.get_attr("android:name") == Some("android.intent.category.LAUNCHER"));
                if has_main && has_launcher {
                    let target = activity.get_attr("android:targetActivity").unwrap_or("");
                    let raw = if !target.is_empty() {
                        target
                    } else {
                        activity.get_attr("android:name").unwrap_or("")
                    };
                    let qualified = qualify_component_name(raw, pkg);
                    if !qualified.is_empty() {
                        return Some(qualified);
                    }
                }
            }
        }
    }
    None
}

pub fn extract_application_class(manifest: &XmlElement, pkg: &str) -> Option<String> {
    let mut apps = Vec::new();
    manifest.find_all("application", &mut apps);
    for app in apps {
        if let Some(name) = app.get_attr("android:name") {
            if !name.is_empty() {
                return Some(qualify_component_name(name, pkg));
            }
        }
    }
    None
}

pub fn parse_all_components(manifest: &XmlElement, arsc: &ArscTable) -> Vec<Map<String, Value>> {
    let pkg = manifest.get_attr("package").unwrap_or("");
    let tags = ["activity", "activity-alias", "service", "receiver", "provider"];
    let mut components = Vec::new();

    for tag in tags {
        let mut nodes = Vec::new();
        manifest.find_all(tag, &mut nodes);
        for el in nodes {
            let raw_name = el.get_attr("android:name").unwrap_or("");
            let name = qualify_component_name(raw_name, pkg);
            if name.is_empty() {
                continue;
            }
            let filters = read_intent_filters(el, arsc);
            let is_main = check_is_main(&filters);
            let is_browsable = check_is_browsable(&filters);

            let explicit = el.get_attr("android:exported").unwrap_or("");
            let (exported, reason) = if !explicit.is_empty() {
                (
                    explicit.eq_ignore_ascii_case("true"),
                    "explicit android:exported",
                )
            } else if tag == "provider" {
                (
                    true,
                    "provider with no android:exported (implicit, pre-API-17)",
                )
            } else if !filters.is_empty() {
                (true, "default exported via intent-filter (pre-API-31)")
            } else {
                (false, "no intent-filter and no android:exported")
            };

            let mut c = Map::new();
            c.insert("name".to_string(), Value::String(name));
            c.insert("type".to_string(), Value::String(tag.to_string()));
            c.insert("is_main".to_string(), Value::Bool(is_main));
            c.insert("is_browsable".to_string(), Value::Bool(is_browsable));
            c.insert("exported".to_string(), Value::Bool(exported));
            c.insert(
                "exported_reason".to_string(),
                Value::String(reason.to_string()),
            );

            if let Some(perm) = el.get_attr("android:permission") {
                if !perm.is_empty() {
                    c.insert(
                        "permission".to_string(),
                        Value::String(arsc.resolve_string_ref(perm)),
                    );
                }
            }
            if tag == "activity-alias" {
                if let Some(target) = el.get_attr("android:targetActivity") {
                    if !target.is_empty() {
                        c.insert(
                            "alias_of".to_string(),
                            Value::String(qualify_component_name(target, pkg)),
                        );
                    }
                }
            }
            c.insert(
                "intent_filters".to_string(),
                Value::Array(filters.into_iter().map(Value::Object).collect()),
            );
            components.push(c);
        }
    }
    components
}

fn read_intent_filters(component: &XmlElement, arsc: &ArscTable) -> Vec<Map<String, Value>> {
    let mut filters = Vec::new();
    let mut filter_nodes = Vec::new();
    component.find_all("intent-filter", &mut filter_nodes);

    for f in filter_nodes {
        let auto_verify = f
            .get_attr("android:autoVerify")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let mut action_nodes = Vec::new();
        f.find_all("action", &mut action_nodes);
        let mut actions = Vec::new();
        for a in action_nodes {
            if let Some(n) = a.get_attr("android:name") {
                if !n.is_empty() {
                    actions.push(Value::String(n.to_string()));
                }
            }
        }

        let mut cat_nodes = Vec::new();
        f.find_all("category", &mut cat_nodes);
        let mut categories = Vec::new();
        for c in cat_nodes {
            if let Some(n) = c.get_attr("android:name") {
                if !n.is_empty() {
                    categories.push(Value::String(n.to_string()));
                }
            }
        }

        let mut data_nodes = Vec::new();
        f.find_all("data", &mut data_nodes);
        let mut data_list = Vec::new();
        for d in data_nodes {
            let mut entry = Map::new();
            let mut declares_something = false;
            for attr in DATA_ATTRS {
                let full_attr = format!("android:{}", attr);
                let val = d.get_attr(&full_attr).unwrap_or("");
                if val.is_empty() {
                    entry.insert(attr.to_string(), Value::String(String::new()));
                } else {
                    declares_something = true;
                    entry.insert(
                        attr.to_string(),
                        Value::String(arsc.resolve_string_ref(val)),
                    );
                }
            }
            if !declares_something {
                continue;
            }
            entry.insert("autoVerify".to_string(), Value::Bool(auto_verify));
            data_list.push(Value::Object(entry));
        }

        let mut filter_map = Map::new();
        filter_map.insert("actions".to_string(), Value::Array(actions));
        filter_map.insert("categories".to_string(), Value::Array(categories));
        filter_map.insert("data".to_string(), Value::Array(data_list));
        filters.push(filter_map);
    }
    filters
}

fn check_is_main(filters: &[Map<String, Value>]) -> bool {
    for f in filters {
        let has_main = f
            .get("actions")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .any(|x| x.as_str() == Some("android.intent.action.MAIN"))
            })
            .unwrap_or(false);
        let has_launcher = f
            .get("categories")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .any(|x| x.as_str() == Some("android.intent.category.LAUNCHER"))
            })
            .unwrap_or(false);
        if has_main && has_launcher {
            return true;
        }
    }
    false
}

fn check_is_browsable(filters: &[Map<String, Value>]) -> bool {
    for f in filters {
        let has_browsable = f
            .get("categories")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .any(|x| x.as_str() == Some("android.intent.category.BROWSABLE"))
            })
            .unwrap_or(false);
        if has_browsable {
            return true;
        }
    }
    false
}

fn is_rogue_app_reachable(c: &Map<String, Value>) -> bool {
    let is_main = c.get("is_main").and_then(|v| v.as_bool()).unwrap_or(false);
    let is_browsable = c
        .get("is_browsable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let exported = c.get("exported").and_then(|v| v.as_bool()).unwrap_or(false);
    if is_main || is_browsable || !exported {
        return false;
    }
    let Some(filters) = c.get("intent_filters").and_then(|v| v.as_array()) else {
        return false;
    };
    if filters.is_empty() {
        return true;
    }
    let mut has_non_main_action = false;
    for f in filters {
        if let Some(actions) = f.get("actions").and_then(|v| v.as_array()) {
            for a in actions {
                if let Some(s) = a.as_str() {
                    if s != "android.intent.action.MAIN" {
                        has_non_main_action = true;
                    }
                }
            }
        }
    }
    has_non_main_action
}

pub fn get_exported_components_list(
    manifest: &XmlElement,
    arsc: &ArscTable,
) -> Vec<Map<String, Value>> {
    let all = parse_all_components(manifest, arsc);
    let exported: Vec<Map<String, Value>> = all
        .into_iter()
        .filter(|c| c.get("exported").and_then(|v| v.as_bool()).unwrap_or(false))
        .collect();
    capped_components(exported, "getExportedComponents", "exported components")
}

pub fn get_deeplink_components_list(
    manifest: &XmlElement,
    arsc: &ArscTable,
) -> Vec<Map<String, Value>> {
    let all = parse_all_components(manifest, arsc);
    let mut kept = Vec::new();
    let mut kept_names = std::collections::HashSet::new();

    for c in &all {
        let is_main = c.get("is_main").and_then(|v| v.as_bool()).unwrap_or(false);
        let is_browsable = c
            .get("is_browsable")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if is_main || is_browsable {
            if let Some(name) = c.get("name").and_then(|v| v.as_str()) {
                kept_names.insert(name.to_string());
                kept.push(c.clone());
            }
        }
    }
    for c in &all {
        if let Some(alias_of) = c.get("alias_of").and_then(|v| v.as_str()) {
            if kept_names.contains(alias_of) {
                if let Some(name) = c.get("name").and_then(|v| v.as_str()) {
                    if kept_names.insert(name.to_string()) {
                        kept.push(c.clone());
                    }
                }
            }
        }
    }
    for c in &all {
        let Some(name) = c.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        if kept_names.contains(name) {
            continue;
        }
        if is_rogue_app_reachable(c) {
            kept_names.insert(name.to_string());
            kept.push(c.clone());
        }
    }
    capped_components(kept, "getDeeplinkComponents", "link-reachable components")
}

fn capped_components(
    all: Vec<Map<String, Value>>,
    tool: &str,
    unit: &str,
) -> Vec<Map<String, Value>> {
    let advice = "This tool takes no limit; read get_android_manifest for the declaration itself.";
    let lim = DEFAULT_RESULT_LIMIT as usize;
    if all.len() > lim {
        let total = all.len();
        let mut capped: Vec<Map<String, Value>> = all.into_iter().take(lim).collect();
        let mut trunc_entry = Map::new();
        trunc_entry.insert(
            TRUNCATION_MARKER_PREFIX.to_string(),
            Value::String(marker(
                TRUNCATION_MARKER_PREFIX,
                &truncation_text(lim, total, unit, advice),
            )),
        );
        capped.push(trunc_entry);
        let arr_val = Value::Array(capped.iter().cloned().map(Value::Object).collect());
        if let Some(cut_notice) = oversized_notice(
            tool,
            lim as i64,
            unit,
            json_cost_of_value(&arr_val),
            "the manifest",
            advice,
        ) {
            let mut over_entry = Map::new();
            over_entry.insert(OVERSIZED_MARKER_PREFIX.to_string(), Value::String(cut_notice));
            capped.push(over_entry);
        }
        return capped;
    }
    let arr_val = Value::Array(all.iter().cloned().map(Value::Object).collect());
    if let Some(notice) = oversized_notice(
        tool,
        all.len() as i64,
        unit,
        json_cost_of_value(&arr_val),
        "the manifest",
        advice,
    ) {
        let mut annotated = all;
        let mut over_entry = Map::new();
        over_entry.insert(OVERSIZED_MARKER_PREFIX.to_string(), Value::String(notice));
        annotated.push(over_entry);
        return annotated;
    }
    all
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
