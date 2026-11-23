pub mod axml;
pub mod decompile;
pub mod dex;
pub mod elf;
pub mod framework;
pub mod guards;
pub mod index;
pub mod mcp;

use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::UNIX_EPOCH;

use serde_json::{Map, Value};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};
use url::Url;

use crate::guards::{
    DEFAULT_CALL_SITE_LIMIT, DEFAULT_MAX_BYTES, DEFAULT_RESULT_LIMIT, DEFAULT_SOFT_BYTES,
};
use crate::index::ApkIndex;

#[derive(Clone)]
pub struct SessionEntry {
    pub session_id: String,
    pub canonical_path: String,
    pub index: Arc<ApkIndex>,
    pub loaded_at_ms: u64,
}

pub struct RegistryState {
    pub max_capacity: usize,
    pub evictions: u64,
    pub order: Vec<String>,
    pub analyzers: HashMap<String, Arc<ApkIndex>>,
    pub sessions: HashMap<String, SessionEntry>,
    pub active_key: Option<String>,
}

impl RegistryState {
    pub fn new(max_capacity: usize) -> Self {
        RegistryState {
            max_capacity: max_capacity.max(1),
            evictions: 0,
            order: Vec::new(),
            analyzers: HashMap::new(),
            sessions: HashMap::new(),
            active_key: None,
        }
    }

    fn clean_canonical(raw_path: &str) -> String {
        let canonical = std::fs::canonicalize(raw_path)
            .unwrap_or_else(|_| PathBuf::from(raw_path))
            .to_string_lossy()
            .into_owned();
        canonical
            .strip_prefix(r"\\?\")
            .unwrap_or(&canonical)
            .to_string()
    }

    fn unique_session_id(&self, desired: &str, self_key: &str) -> String {
        let base = if desired.trim().is_empty() {
            "apk"
        } else {
            desired.trim()
        };
        let collides = |cand: &str| -> bool {
            self.sessions
                .iter()
                .any(|(k, v)| k != self_key && v.session_id.eq_ignore_ascii_case(cand))
        };
        if !collides(base) {
            return base.to_string();
        }
        let mut idx = 2usize;
        loop {
            let cand = format!("{}-{}", base, idx);
            if !collides(&cand) {
                return cand;
            }
            idx += 1;
        }
    }

    fn derive_session_id(&self, clean_key: &str, apk: &ApkIndex, preferred: Option<&str>) -> String {
        if let Some(pref) = preferred {
            let trimmed = pref.trim();
            if !trimmed.is_empty() {
                return self.unique_session_id(trimmed, clean_key);
            }
        }
        let path_obj = std::path::Path::new(clean_key);
        let stem = path_obj
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("apk");
        let base = if stem.len() > 36 && !apk.package_name.is_empty() {
            apk.package_name.as_str()
        } else {
            stem
        };
        self.unique_session_id(base, clean_key)
    }

    pub fn open_session_ids(&self) -> Vec<String> {
        self.order
            .iter()
            .filter_map(|k| self.sessions.get(k).map(|s| s.session_id.clone()))
            .collect()
    }

    pub fn active_session_id(&self) -> Option<String> {
        self.active_key
            .as_ref()
            .and_then(|k| self.sessions.get(k).map(|s| s.session_id.clone()))
    }

    pub fn find_key(&self, query: &str) -> Result<String, String> {
        let q = query.trim();
        if q.is_empty() {
            return self
                .active_key
                .clone()
                .ok_or_else(|| "No APK loaded. Please load an APK first using /load-apk".to_string());
        }
        let q_canon = Self::clean_canonical(q);

        // 1. Exact session_id or canonical_path or raw apk_path match
        for k in &self.order {
            if let Some(entry) = self.sessions.get(k) {
                if entry.session_id == q
                    || entry.canonical_path == q
                    || entry.canonical_path == q_canon
                    || entry.index.apk_path == q
                {
                    return Ok(k.clone());
                }
            }
        }

        // 2. Case-insensitive exact session_id match
        for k in &self.order {
            if let Some(entry) = self.sessions.get(k) {
                if entry.session_id.eq_ignore_ascii_case(q) {
                    return Ok(k.clone());
                }
            }
        }

        // 3. Exact package_name or file_name / file_stem match (if unambiguous)
        let mut exact_pkg_or_file = Vec::new();
        for k in &self.order {
            if let Some(entry) = self.sessions.get(k) {
                let p = std::path::Path::new(&entry.canonical_path);
                let fname = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
                let fstem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                if (!entry.index.package_name.is_empty()
                    && entry.index.package_name.eq_ignore_ascii_case(q))
                    || fname.eq_ignore_ascii_case(q)
                    || fstem.eq_ignore_ascii_case(q)
                {
                    exact_pkg_or_file.push(k.clone());
                }
            }
        }
        if exact_pkg_or_file.len() == 1 {
            return Ok(exact_pkg_or_file.remove(0));
        }

        // 4. Case-insensitive substring match across session_id, package_name, and path
        let q_lower = q.to_lowercase();
        let mut sub_matches = Vec::new();
        for k in &self.order {
            if let Some(entry) = self.sessions.get(k) {
                if entry.session_id.to_lowercase().contains(&q_lower)
                    || entry.index.package_name.to_lowercase().contains(&q_lower)
                    || entry.canonical_path.to_lowercase().contains(&q_lower)
                {
                    sub_matches.push((k.clone(), entry.session_id.clone()));
                }
            }
        }
        if sub_matches.len() == 1 {
            return Ok(sub_matches.remove(0).0);
        }
        if sub_matches.len() > 1 {
            let names: Vec<String> = sub_matches.into_iter().map(|(_, id)| id).collect();
            return Err(format!(
                "Ambiguous session '{}': matches multiple open sessions [{}]. Pass an exact sessionId.",
                q,
                names.join(", ")
            ));
        }

        let open = self.open_session_ids();
        if open.is_empty() {
            Err("No APK loaded. Please load an APK first using /load-apk".to_string())
        } else {
            Err(format!(
                "Session '{}' not found. Currently open sessions: [{}]",
                q,
                open.join(", ")
            ))
        }
    }

    pub fn active(&self) -> Result<Arc<ApkIndex>, String> {
        let Some(ref key) = self.active_key else {
            return Err("No APK loaded. Please load an APK first using /load-apk".to_string());
        };
        self.analyzers
            .get(key)
            .cloned()
            .ok_or_else(|| "No APK loaded. Please load an APK first using /load-apk".to_string())
    }

    pub fn resolve(&self, session: Option<&str>) -> Result<Arc<ApkIndex>, String> {
        match session {
            Some(s) if !s.trim().is_empty() => {
                let key = self.find_key(s)?;
                self.analyzers
                    .get(&key)
                    .cloned()
                    .ok_or_else(|| "Session not found".to_string())
            }
            _ => self.active(),
        }
    }

    pub fn load_apk(&mut self, raw_path: &str) -> Result<Arc<ApkIndex>, String> {
        let (entry, _) = self.load_apk_session(raw_path, None)?;
        Ok(entry.index)
    }

    pub fn load_apk_session(
        &mut self,
        raw_path: &str,
        preferred_session_id: Option<&str>,
    ) -> Result<(SessionEntry, bool), String> {
        let clean_key = Self::clean_canonical(raw_path);

        if let Some(mut existing) = self.sessions.get(&clean_key).cloned() {
            if let Some(pref) = preferred_session_id {
                let trimmed = pref.trim();
                if !trimmed.is_empty() && !existing.session_id.eq_ignore_ascii_case(trimmed) {
                    existing.session_id = self.unique_session_id(trimmed, &clean_key);
                    self.sessions.insert(clean_key.clone(), existing.clone());
                }
            }
            self.order.retain(|k| k != &clean_key);
            self.order.push(clean_key.clone());
            self.active_key = Some(clean_key);
            return Ok((existing, true));
        }

        while self.analyzers.len() >= self.max_capacity && !self.order.is_empty() {
            let oldest = self.order.remove(0);
            self.analyzers.remove(&oldest);
            self.sessions.remove(&oldest);
            if self.active_key.as_deref() == Some(oldest.as_str()) {
                self.active_key = None;
            }
            self.evictions += 1;
        }

        let loaded = Arc::new(ApkIndex::load(raw_path)?);
        let session_id = self.derive_session_id(&clean_key, &loaded, preferred_session_id);
        let now_ms = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let entry = SessionEntry {
            session_id,
            canonical_path: clean_key.clone(),
            index: loaded.clone(),
            loaded_at_ms: now_ms,
        };
        self.analyzers.insert(clean_key.clone(), loaded);
        self.sessions.insert(clean_key.clone(), entry.clone());
        self.order.push(clean_key.clone());
        self.active_key = Some(clean_key);
        Ok((entry, false))
    }

    pub fn select_session(&mut self, query: &str) -> Result<SessionEntry, String> {
        let key = self.find_key(query)?;
        self.order.retain(|k| k != &key);
        self.order.push(key.clone());
        self.active_key = Some(key.clone());
        self.sessions
            .get(&key)
            .cloned()
            .ok_or_else(|| "Session not found".to_string())
    }

    pub fn close_active(&mut self) {
        let _ = self.close_session(None);
    }

    pub fn close_session(&mut self, query: Option<&str>) -> Result<Map<String, Value>, String> {
        if let Some(q) = query {
            let trimmed = q.trim();
            if trimmed.eq_ignore_ascii_case("all") || trimmed == "*" {
                let closed = self.open_session_ids();
                self.analyzers.clear();
                self.sessions.clear();
                self.order.clear();
                self.active_key = None;
                let mut m = Map::new();
                m.insert("message".to_string(), Value::String("All sessions closed".to_string()));
                m.insert(
                    "closedSessions".to_string(),
                    Value::Array(closed.into_iter().map(Value::String).collect()),
                );
                m.insert("activeSession".to_string(), Value::Null);
                m.insert("openSessions".to_string(), Value::Array(Vec::new()));
                return Ok(m);
            }
        }

        let target_key = match query {
            Some(q) if !q.trim().is_empty() => self.find_key(q)?,
            _ => match self.active_key.clone() {
                Some(k) => k,
                None => {
                    let mut m = Map::new();
                    m.insert(
                        "message".to_string(),
                        Value::String("Analyzer closed successfully".to_string()),
                    );
                    m.insert("closedSession".to_string(), Value::Null);
                    m.insert("activeSession".to_string(), Value::Null);
                    m.insert("openSessions".to_string(), Value::Array(Vec::new()));
                    return Ok(m);
                }
            },
        };

        let closed_id = self
            .sessions
            .get(&target_key)
            .map(|s| s.session_id.clone());
        self.analyzers.remove(&target_key);
        self.sessions.remove(&target_key);
        self.order.retain(|k| k != &target_key);
        if self.active_key.as_deref() == Some(target_key.as_str()) {
            self.active_key = self.order.last().cloned();
        }

        let mut m = Map::new();
        m.insert(
            "message".to_string(),
            Value::String("Analyzer closed successfully".to_string()),
        );
        m.insert(
            "closedSession".to_string(),
            closed_id.map(Value::String).unwrap_or(Value::Null),
        );
        m.insert(
            "activeSession".to_string(),
            self.active_session_id()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        m.insert(
            "openSessions".to_string(),
            Value::Array(
                self.open_session_ids()
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        );
        Ok(m)
    }

    pub fn list_sessions_info(&self) -> Map<String, Value> {
        let mut items = Vec::new();
        for key in &self.order {
            let Some(entry) = self.sessions.get(key) else {
                continue;
            };
            let apk = &entry.index;
            let is_active = self.active_key.as_deref() == Some(key.as_str());
            let native_lib_count = apk
                .resource_entries
                .iter()
                .filter(|(name, _)| name.starts_with("lib/") && name.ends_with(".so"))
                .count();
            let ridx_built = apk.reverse_index.read().unwrap().is_some();
            let mut item = Map::new();
            item.insert(
                "sessionId".to_string(),
                Value::String(entry.session_id.clone()),
            );
            item.insert("active".to_string(), Value::Bool(is_active));
            item.insert(
                "apkPath".to_string(),
                Value::String(entry.canonical_path.clone()),
            );
            item.insert(
                "packageName".to_string(),
                Value::String(apk.package_name.clone()),
            );
            item.insert(
                "mainActivity".to_string(),
                apk.get_main_activity_class()
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            );
            item.insert("format".to_string(), Value::String(apk.format.clone()));
            item.insert("dexCount".to_string(), Value::from(apk.dex_tables.len()));
            item.insert("totalClasses".to_string(), Value::from(apk.classes.len()));
            item.insert("totalMethods".to_string(), Value::from(apk.methods.len()));
            item.insert("totalFields".to_string(), Value::from(apk.fields.len()));
            item.insert("nativeLibCount".to_string(), Value::from(native_lib_count));
            item.insert("reverseIndexBuilt".to_string(), Value::Bool(ridx_built));
            item.insert("loadedAtMs".to_string(), Value::from(entry.loaded_at_ms));
            items.push(Value::Object(item));
        }

        let mut m = Map::new();
        m.insert(
            "activeSession".to_string(),
            self.active_session_id()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        m.insert("totalOpen".to_string(), Value::from(items.len()));
        m.insert("maxCapacity".to_string(), Value::from(self.max_capacity));
        m.insert("evictions".to_string(), Value::from(self.evictions));
        m.insert("sessions".to_string(), Value::Array(items));
        m
    }

    pub fn stats(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("size".to_string(), Value::from(self.analyzers.len()));
        m.insert("maxCapacity".to_string(), Value::from(self.max_capacity));
        m.insert("evictions".to_string(), Value::from(self.evictions));
        m.insert(
            "loaded".to_string(),
            Value::Array(self.order.iter().cloned().map(Value::String).collect()),
        );
        m.insert(
            "sessions".to_string(),
            Value::Array(
                self.open_session_ids()
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        );
        m.insert(
            "activeSession".to_string(),
            self.active_session_id()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        m.insert(
            "active".to_string(),
            self.active_key
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        m
    }
}

fn build_fingerprint() -> Map<String, Value> {
    let mut b = Map::new();
    b.insert("pid".to_string(), Value::from(std::process::id()));
    b.insert("engine".to_string(), Value::String("rust".to_string()));
    if let Ok(exe) = env::current_exe() {
        let clean = exe
            .to_string_lossy()
            .strip_prefix(r"\\?\")
            .unwrap_or(&exe.to_string_lossy())
            .to_string();
        b.insert("artifact".to_string(), Value::String(clean));
        if let Ok(meta) = std::fs::metadata(&exe) {
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            b.insert("mtime".to_string(), Value::from(mtime));
            b.insert("size".to_string(), Value::from(meta.len()));
        } else {
            b.insert("mtime".to_string(), Value::Null);
            b.insert("size".to_string(), Value::Null);
        }
    } else {
        b.insert("artifact".to_string(), Value::Null);
        b.insert("mtime".to_string(), Value::Null);
        b.insert("size".to_string(), Value::Null);
    }
    b
}

fn parse_query_params(raw_url: &str) -> (String, HashMap<String, Vec<String>>) {
    let full = format!("http://localhost{}", raw_url);
    let Ok(parsed) = Url::parse(&full) else {
        return (raw_url.to_string(), HashMap::new());
    };
    let path = parsed.path().to_string();
    let mut params: HashMap<String, Vec<String>> = HashMap::new();
    for (k, v) in parsed.query_pairs() {
        params
            .entry(k.into_owned())
            .or_default()
            .push(v.into_owned());
    }
    (path, params)
}

fn first_param<'a>(params: &'a HashMap<String, Vec<String>>, key: &str) -> Option<&'a str> {
    params
        .get(key)
        .and_then(|v| v.first())
        .map(|s| s.as_str())
}

fn int_param(params: &HashMap<String, Vec<String>>, key: &str, default_val: i32) -> i32 {
    first_param(params, key)
        .and_then(|s| s.trim().parse::<i32>().ok())
        .unwrap_or(default_val)
}

fn single_key_json(key: &str, val: Value) -> Value {
    let mut m = Map::new();
    m.insert(key.to_string(), val);
    Value::Object(m)
}

fn send_json(req: Request, status: u16, body: &Value) {
    let data = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    let header =
        Header::from_bytes(&b"Content-Type"[..], &b"application/json; charset=utf-8"[..]).unwrap();
    let resp = Response::from_data(data)
        .with_status_code(StatusCode(status))
        .with_header(header);
    let _ = req.respond(resp);
}

fn send_error(req: Request, msg: &str) {
    let mut err = Map::new();
    err.insert("error".to_string(), Value::String(msg.to_string()));
    send_json(req, 400, &Value::Object(err));
}

pub fn handle_http_request(mut req: Request, state: &Arc<RwLock<RegistryState>>) {
    let method = req.method().clone();
    let (raw_path, params) = parse_query_params(req.url());
    let path = if let Some(rest) = raw_path.strip_prefix("/api/droidscope/") {
        format!("/api/jadx/{}", rest)
    } else {
        raw_path
    };

    match (&method, path.as_str()) {
        (&Method::Get, "/api/jadx/health") => {
            let guard = state.read().unwrap();
            let loaded_apk = guard.active().ok().map(|a| a.apk_path.clone());
            let ridx_stats = guard.active().ok().and_then(|a| a.reverse_index_stats());
            let mut m = Map::new();
            m.insert("status".to_string(), Value::String("ok".to_string()));
            m.insert(
                "loadedApk".to_string(),
                loaded_apk.map(Value::String).unwrap_or(Value::Null),
            );
            m.insert("build".to_string(), Value::Object(build_fingerprint()));
            m.insert("registry".to_string(), Value::Object(guard.stats()));
            m.insert(
                "reverseIndex".to_string(),
                ridx_stats.map(Value::Object).unwrap_or(Value::Null),
            );
            send_json(req, 200, &Value::Object(m));
        }

        (&Method::Post, "/api/jadx/load-apk") => {
            let mut body_str = String::new();
            if let Err(e) = req.as_reader().read_to_string(&mut body_str) {
                send_error(req, &format!("Failed reading request body: {}", e));
                return;
            }
            let Ok(json_body) = serde_json::from_str::<Value>(&body_str) else {
                send_error(req, "Invalid JSON body");
                return;
            };
            let apk_path = json_body
                .get("apkPath")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if apk_path.is_empty() {
                send_error(req, "apkPath is required");
                return;
            }
            let preferred_session = json_body
                .get("sessionId")
                .or_else(|| json_body.get("session"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty());

            let res = {
                let mut guard = state.write().unwrap();
                let loaded = guard.load_apk_session(apk_path, preferred_session);
                loaded.map(|(entry, reused)| {
                    let mut info = entry.index.get_apk_info();
                    info.insert(
                        "sessionId".to_string(),
                        Value::String(entry.session_id.clone()),
                    );
                    info.insert(
                        "activeSession".to_string(),
                        Value::String(entry.session_id.clone()),
                    );
                    info.insert("reusedSession".to_string(), Value::Bool(reused));
                    info.insert(
                        "openSessions".to_string(),
                        Value::Array(
                            guard
                                .open_session_ids()
                                .into_iter()
                                .map(Value::String)
                                .collect(),
                        ),
                    );
                    info
                })
            };
            match res {
                Ok(info) => send_json(req, 200, &Value::Object(info)),
                Err(e) => send_error(req, &e),
            }
        }

        (&Method::Get, "/api/jadx/sessions") => {
            let info = state.read().unwrap().list_sessions_info();
            send_json(req, 200, &single_key_json("sessions", Value::Object(info)));
        }

        (&Method::Post, "/api/jadx/select-session") => {
            let mut body_str = String::new();
            if let Err(e) = req.as_reader().read_to_string(&mut body_str) {
                send_error(req, &format!("Failed reading request body: {}", e));
                return;
            }
            let Ok(json_body) = serde_json::from_str::<Value>(&body_str) else {
                send_error(req, "Invalid JSON body");
                return;
            };
            let target = json_body
                .get("session")
                .or_else(|| json_body.get("sessionId"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if target.is_empty() {
                send_error(req, "session is required");
                return;
            }
            let res = {
                let mut guard = state.write().unwrap();
                guard.select_session(target).map(|entry| {
                    let mut info = entry.index.get_apk_info();
                    info.insert(
                        "sessionId".to_string(),
                        Value::String(entry.session_id.clone()),
                    );
                    info.insert(
                        "activeSession".to_string(),
                        Value::String(entry.session_id.clone()),
                    );
                    info.insert(
                        "openSessions".to_string(),
                        Value::Array(
                            guard
                                .open_session_ids()
                                .into_iter()
                                .map(Value::String)
                                .collect(),
                        ),
                    );
                    info
                })
            };
            match res {
                Ok(info) => send_json(req, 200, &single_key_json("session", Value::Object(info))),
                Err(e) => send_error(req, &e),
            }
        }

        (&Method::Post, "/api/jadx/close") => {
            let mut body_str = String::new();
            let _ = req.as_reader().read_to_string(&mut body_str);
            let target_opt = serde_json::from_str::<Value>(&body_str)
                .ok()
                .and_then(|v| {
                    v.get("session")
                        .or_else(|| v.get("sessionId"))
                        .and_then(|s| s.as_str())
                        .map(|s| s.trim().to_string())
                })
                .filter(|s| !s.is_empty());

            let res = {
                let mut guard = state.write().unwrap();
                guard.close_session(target_opt.as_deref())
            };
            match res {
                Ok(m) => send_json(req, 200, &Value::Object(m)),
                Err(e) => send_error(req, &e),
            }
        }

        (&Method::Get, "/api/jadx/classes") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let prefix = first_param(&params, "packagePrefix");
            let limit = int_param(&params, "limit", DEFAULT_RESULT_LIMIT);
            let classes = apk.get_all_classes(prefix, limit);
            send_json(
                req,
                200,
                &single_key_json(
                    "classes",
                    Value::Array(classes.into_iter().map(Value::String).collect()),
                ),
            );
        }

        (&Method::Get, "/api/jadx/class-source") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let Some(class_name) = first_param(&params, "className") else {
                return send_error(req, "className is required");
            };
            let max_bytes = int_param(&params, "maxBytes", DEFAULT_SOFT_BYTES);
            match apk.get_class_source(class_name, max_bytes) {
                Ok(src) => send_json(req, 200, &single_key_json("source", Value::String(src))),
                Err(e) => send_error(req, &e),
            }
        }

        (&Method::Get, "/api/jadx/class-methods") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let Some(class_name) = first_param(&params, "className") else {
                return send_error(req, "className is required");
            };
            let limit = int_param(&params, "limit", DEFAULT_RESULT_LIMIT);
            match apk.get_methods_of_class(class_name, limit) {
                Ok(methods) => send_json(
                    req,
                    200,
                    &single_key_json(
                        "methods",
                        Value::Array(methods.into_iter().map(Value::String).collect()),
                    ),
                ),
                Err(e) => send_error(req, &e),
            }
        }

        (&Method::Get, "/api/jadx/class-fields") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let Some(class_name) = first_param(&params, "className") else {
                return send_error(req, "className is required");
            };
            let limit = int_param(&params, "limit", DEFAULT_RESULT_LIMIT);
            match apk.get_fields_of_class(class_name, limit) {
                Ok(fields) => send_json(
                    req,
                    200,
                    &single_key_json(
                        "fields",
                        Value::Array(fields.into_iter().map(Value::String).collect()),
                    ),
                ),
                Err(e) => send_error(req, &e),
            }
        }

        (&Method::Get, "/api/jadx/method-source") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let Some(class_name) = first_param(&params, "className") else {
                return send_error(req, "className is required");
            };
            let Some(method_name) = first_param(&params, "methodName") else {
                return send_error(req, "methodName is required");
            };
            let signature = first_param(&params, "signature");
            match apk.get_method_by_name(class_name, method_name, signature) {
                Ok(src) => send_json(req, 200, &single_key_json("source", Value::String(src))),
                Err(e) => send_error(req, &e),
            }
        }

        (&Method::Get, "/api/jadx/search-classes") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let keyword = first_param(&params, "keyword");
            let limit = int_param(&params, "limit", DEFAULT_RESULT_LIMIT);
            let classes = apk.search_classes_by_keyword(keyword, limit);
            send_json(
                req,
                200,
                &single_key_json(
                    "classes",
                    Value::Array(classes.into_iter().map(Value::String).collect()),
                ),
            );
        }

        (&Method::Get, "/api/jadx/search-method") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let method_name = first_param(&params, "methodName");
            let limit = int_param(&params, "limit", DEFAULT_RESULT_LIMIT);
            let results = apk.search_method_by_name(method_name, limit);
            send_json(req, 200, &single_key_json("results", Value::Object(results)));
        }

        (&Method::Get, "/api/jadx/xrefs-to-class") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let Some(class_name) = first_param(&params, "className") else {
                return send_error(req, "className is required");
            };
            let limit = int_param(&params, "limit", DEFAULT_RESULT_LIMIT);
            match apk.get_xrefs_to_class(class_name, limit) {
                Ok(xrefs) => send_json(
                    req,
                    200,
                    &single_key_json(
                        "xrefs",
                        Value::Array(xrefs.into_iter().map(Value::Object).collect()),
                    ),
                ),
                Err(e) => send_error(req, &e),
            }
        }

        (&Method::Get, "/api/jadx/xrefs-to-method") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let Some(class_name) = first_param(&params, "className") else {
                return send_error(req, "className is required");
            };
            let Some(method_name) = first_param(&params, "methodName") else {
                return send_error(req, "methodName is required");
            };
            let signature = first_param(&params, "signature");
            let limit = int_param(&params, "limit", DEFAULT_RESULT_LIMIT);
            match apk.get_xrefs_to_method(class_name, method_name, signature, limit) {
                Ok(xrefs) => send_json(
                    req,
                    200,
                    &single_key_json(
                        "xrefs",
                        Value::Array(xrefs.into_iter().map(Value::Object).collect()),
                    ),
                ),
                Err(e) => send_error(req, &e),
            }
        }

        (&Method::Get, "/api/jadx/xrefs-to-field") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let Some(class_name) = first_param(&params, "className") else {
                return send_error(req, "className is required");
            };
            let Some(field_name) = first_param(&params, "fieldName") else {
                return send_error(req, "fieldName is required");
            };
            let limit = int_param(&params, "limit", DEFAULT_RESULT_LIMIT);
            match apk.get_xrefs_to_field(class_name, field_name, limit) {
                Ok(xrefs) => send_json(
                    req,
                    200,
                    &single_key_json(
                        "xrefs",
                        Value::Array(xrefs.into_iter().map(Value::Object).collect()),
                    ),
                ),
                Err(e) => send_error(req, &e),
            }
        }

        (&Method::Get, "/api/jadx/callees") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let Some(class_name) = first_param(&params, "className") else {
                return send_error(req, "className is required");
            };
            let Some(method_name) = first_param(&params, "methodName") else {
                return send_error(req, "methodName is required");
            };
            let signature = first_param(&params, "signature");
            let limit = int_param(&params, "limit", DEFAULT_RESULT_LIMIT);
            match apk.get_callees(class_name, method_name, signature, limit) {
                Ok(callees) => send_json(
                    req,
                    200,
                    &single_key_json("callees", Value::Object(callees)),
                ),
                Err(e) => send_error(req, &e),
            }
        }

        (&Method::Get, "/api/jadx/sink-call-sites") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let limit = int_param(&params, "limit", DEFAULT_CALL_SITE_LIMIT);
            let sink_list: Option<Vec<String>> = params.get("sinks").map(|raw_vec| {
                raw_vec
                    .iter()
                    .flat_map(|s| s.split(','))
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            });
            let sites = apk.find_sink_call_sites(sink_list.as_deref(), limit);
            send_json(
                req,
                200,
                &single_key_json("sinkCallSites", Value::Object(sites)),
            );
        }

        (&Method::Get, "/api/jadx/type-hierarchy") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let Some(class_name) = first_param(&params, "className") else {
                return send_error(req, "className is required");
            };
            match apk.get_type_hierarchy(class_name) {
                Ok(h) => send_json(req, 200, &single_key_json("hierarchy", Value::Object(h))),
                Err(e) => send_error(req, &e),
            }
        }

        (&Method::Get, "/api/jadx/overrides") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let Some(class_name) = first_param(&params, "className") else {
                return send_error(req, "className is required");
            };
            let Some(method_name) = first_param(&params, "methodName") else {
                return send_error(req, "methodName is required");
            };
            let signature = first_param(&params, "signature");
            let limit = int_param(&params, "limit", DEFAULT_RESULT_LIMIT);
            match apk.get_overrides(class_name, method_name, signature, limit) {
                Ok(ov) => send_json(req, 200, &single_key_json("overrides", Value::Object(ov))),
                Err(e) => send_error(req, &e),
            }
        }

        (&Method::Get, "/api/jadx/components") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            match apk.get_exported_components() {
                Ok(comps) => send_json(
                    req,
                    200,
                    &single_key_json(
                        "components",
                        Value::Array(comps.into_iter().map(Value::Object).collect()),
                    ),
                ),
                Err(e) => send_error(req, &e),
            }
        }

        (&Method::Get, "/api/jadx/deeplink-components") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            match apk.get_deeplink_components() {
                Ok(comps) => send_json(
                    req,
                    200,
                    &single_key_json(
                        "components",
                        Value::Array(comps.into_iter().map(Value::Object).collect()),
                    ),
                ),
                Err(e) => send_error(req, &e),
            }
        }

        (&Method::Get, "/api/jadx/manifest") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            match apk.get_android_manifest() {
                Ok(m) => send_json(req, 200, &single_key_json("manifest", Value::String(m))),
                Err(e) => send_error(req, &e),
            }
        }

        (&Method::Get, "/api/jadx/main-activity") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let main_act = apk
                .get_main_activity_class()
                .map(Value::String)
                .unwrap_or(Value::Null);
            send_json(req, 200, &single_key_json("mainActivity", main_act));
        }

        (&Method::Get, "/api/jadx/resources") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let prefix = first_param(&params, "pathPrefix");
            let limit = int_param(&params, "limit", DEFAULT_RESULT_LIMIT);
            let res = apk.get_all_resource_file_names(prefix, limit);
            send_json(
                req,
                200,
                &single_key_json(
                    "resources",
                    Value::Array(res.into_iter().map(Value::String).collect()),
                ),
            );
        }

        (&Method::Get, "/api/jadx/resource") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let Some(file_name) = first_param(&params, "fileName") else {
                return send_error(req, "fileName is required");
            };
            let max_bytes = int_param(&params, "maxBytes", DEFAULT_MAX_BYTES);
            match apk.get_resource_file(file_name, max_bytes) {
                Ok(content) => send_json(
                    req,
                    200,
                    &single_key_json("content", Value::String(content)),
                ),
                Err(e) => send_error(req, &e),
            }
        }

        (&Method::Get, "/api/jadx/class-smali") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let Some(class_name) = first_param(&params, "className") else {
                return send_error(req, "className is required");
            };
            let max_bytes = int_param(&params, "maxBytes", DEFAULT_MAX_BYTES);
            match apk.get_smali_of_class(class_name, max_bytes) {
                Ok(smali) => send_json(req, 200, &single_key_json("smali", Value::String(smali))),
                Err(e) => send_error(req, &e),
            }
        }

        (&Method::Get, "/api/jadx/method-smali") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let Some(class_name) = first_param(&params, "className") else {
                return send_error(req, "className is required");
            };
            let Some(method_name) = first_param(&params, "methodName") else {
                return send_error(req, "methodName is required");
            };
            let signature = first_param(&params, "signature");
            match apk.get_smali_of_method(class_name, method_name, signature) {
                Ok(smali) => send_json(req, 200, &single_key_json("smali", Value::String(smali))),
                Err(e) => send_error(req, &e),
            }
        }

        (&Method::Get, "/api/jadx/search-strings") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let query = first_param(&params, "query");
            let prefix = first_param(&params, "packagePrefix");
            let limit = int_param(&params, "limit", DEFAULT_RESULT_LIMIT);
            let strings = apk.search_strings_in_dex(query, prefix, limit);
            send_json(
                req,
                200,
                &single_key_json(
                    "strings",
                    Value::Array(strings.into_iter().map(Value::Object).collect()),
                ),
            );
        }

        (&Method::Get, "/api/jadx/call-paths") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let from_class = first_param(&params, "fromClass").unwrap_or("");
            let from_method = first_param(&params, "fromMethod").unwrap_or("");
            let Some(to_class) = first_param(&params, "toClass") else {
                return send_error(req, "toClass is required");
            };
            let Some(to_method) = first_param(&params, "toMethod") else {
                return send_error(req, "toMethod is required");
            };
            let max_depth = int_param(&params, "maxDepth", 6);
            let limit = int_param(&params, "limit", 20);
            match apk.find_call_paths(
                from_class,
                from_method,
                to_class,
                to_method,
                max_depth,
                limit,
            ) {
                Ok(paths) => send_json(
                    req,
                    200,
                    &single_key_json("callPaths", Value::Object(paths)),
                ),
                Err(e) => send_error(req, &e),
            }
        }

        (&Method::Get, "/api/jadx/native-methods") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let prefix = first_param(&params, "packagePrefix");
            let limit = int_param(&params, "limit", DEFAULT_RESULT_LIMIT);
            let natives = apk.get_native_methods(prefix, limit);
            send_json(
                req,
                200,
                &single_key_json(
                    "nativeMethods",
                    Value::Array(natives.into_iter().map(Value::Object).collect()),
                ),
            );
        }

        (&Method::Get, "/api/jadx/re-recon") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let prefix = first_param(&params, "packagePrefix");
            let recon = apk.get_re_recon(prefix);
            send_json(req, 200, &single_key_json("recon", Value::Object(recon)));
        }

        (&Method::Get, "/api/jadx/native-lib-info") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let Some(lib_name) = first_param(&params, "libName") else {
                return send_error(req, "libName is required");
            };
            match apk.get_native_lib_info(lib_name) {
                Ok(info) => send_json(
                    req,
                    200,
                    &single_key_json("nativeLibInfo", Value::Object(info)),
                ),
                Err(e) => send_error(req, &e),
            }
        }

        (&Method::Get, "/api/jadx/register-natives") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let lib_name = first_param(&params, "libName");
            let class_name = first_param(&params, "className");
            let limit = int_param(&params, "limit", DEFAULT_RESULT_LIMIT);
            match apk.resolve_register_natives(lib_name, class_name, limit) {
                Ok(items) => send_json(
                    req,
                    200,
                    &single_key_json(
                        "registeredNatives",
                        Value::Array(items.into_iter().map(Value::Object).collect()),
                    ),
                ),
                Err(e) => send_error(req, &e),
            }
        }

        (&Method::Get, "/api/jadx/native-strings") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let Some(lib_name) = first_param(&params, "libName") else {
                return send_error(req, "libName is required");
            };
            let query = first_param(&params, "query");
            let limit = int_param(&params, "limit", DEFAULT_RESULT_LIMIT);
            match apk.search_native_strings(lib_name, query, limit) {
                Ok(items) => send_json(
                    req,
                    200,
                    &single_key_json(
                        "nativeStrings",
                        Value::Array(items.into_iter().map(Value::Object).collect()),
                    ),
                ),
                Err(e) => send_error(req, &e),
            }
        }

        (&Method::Get, "/api/jadx/native-disasm") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let Some(lib_name) = first_param(&params, "libName") else {
                return send_error(req, "libName is required");
            };
            let Some(target) = first_param(&params, "target") else {
                return send_error(req, "target is required");
            };
            let instructions = int_param(&params, "instructions", 64);
            match apk.disassemble_native_arm64(lib_name, target, instructions) {
                Ok(dis) => send_json(
                    req,
                    200,
                    &single_key_json("disassembly", Value::Object(dis)),
                ),
                Err(e) => send_error(req, &e),
            }
        }

        (&Method::Get, "/api/jadx/native-analyze-func") => {
            let apk = match state.read().unwrap().resolve(first_param(&params, "session")) {
                Ok(a) => a,
                Err(e) => return send_error(req, &e),
            };
            let Some(lib_name) = first_param(&params, "libName") else {
                return send_error(req, "libName is required");
            };
            let Some(target) = first_param(&params, "target") else {
                return send_error(req, "target is required");
            };
            let max_instructions = int_param(&params, "maxInstructions", 256);
            match apk.analyze_native_function(lib_name, target, max_instructions) {
                Ok(analysis) => send_json(
                    req,
                    200,
                    &single_key_json("functionAnalysis", Value::Object(analysis)),
                ),
                Err(e) => send_error(req, &e),
            }
        }

        _ => {
            send_error(req, &format!("Unknown endpoint: {} {}", method, path));
        }
    }
}

fn main() {
    let max_apks = env::var("DROIDSCOPE_MAX_LOADED_APKS")
        .or_else(|_| env::var("JADX_MAX_LOADED_APKS"))
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(8);

    let state = Arc::new(RwLock::new(RegistryState::new(max_apks)));

    let args: Vec<String> = env::args().collect();
    let http_mode = args.iter().any(|a| a == "--http" || a == "--daemon");

    if !http_mode {
        mcp::run_mcp_stdio(state);
        return;
    }

    let port = env::var("DROIDSCOPE_PORT")
        .or_else(|_| env::var("JADX_PORT"))
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(8765);

    let bind_addr = format!("127.0.0.1:{}", port);
    let server = Server::http(&bind_addr).unwrap_or_else(|e| {
        eprintln!("Failed to bind DroidScope HTTP daemon on {}: {}", bind_addr, e);
        std::process::exit(1);
    });

    eprintln!(
        "droidscope-mcp HTTP server listening on http://{} (maxLoadedApks={})",
        bind_addr, max_apks
    );

    let server = Arc::new(server);
    let num_workers = thread::available_parallelism()
        .map(|n| n.get().clamp(2, 8))
        .unwrap_or(4);

    let mut handles = Vec::with_capacity(num_workers);
    for _ in 0..num_workers {
        let srv = Arc::clone(&server);
        let st = Arc::clone(&state);
        handles.push(thread::spawn(move || {
            for request in srv.incoming_requests() {
                handle_http_request(request, &st);
            }
        }));
    }

    for h in handles {
        let _ = h.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_apk_path() -> String {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let root_cand = PathBuf::from(manifest_dir).join("misc").join("sample-app.apk");
        if root_cand.exists() {
            return root_cand.to_string_lossy().into_owned();
        }
        PathBuf::from(manifest_dir)
            .join("..")
            .join("misc")
            .join("sample-app.apk")
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn loads_sample_apk_and_verifies_all_tools() {
        let path = sample_apk_path();
        assert!(
            std::path::Path::new(&path).exists(),
            "Fixture missing at {}",
            path
        );
        let apk = ApkIndex::load(&path).expect("Failed to load sample-app.apk");

        // 1. APK info, manifest & main activity
        let info = apk.get_apk_info();
        assert_eq!(
            info.get("packageName").and_then(|v| v.as_str()),
            Some("com.droidscope.sample")
        );
        assert_eq!(info.get("totalClasses").and_then(|v| v.as_u64()), Some(4));
        assert_eq!(
            apk.get_main_activity_class().as_deref(),
            Some("com.droidscope.sample.MainActivity")
        );
        let manifest = apk.get_android_manifest().expect("manifest");
        assert!(manifest.contains("com.droidscope.sample"));

        // 2. Classes, search-classes, methods, fields
        let all_classes = apk.get_all_classes(Some("com.droidscope.sample"), 100);
        assert!(all_classes.contains(&"com.droidscope.sample.MainActivity".to_string()));
        assert!(all_classes.contains(&"com.droidscope.sample.CryptoBridge".to_string()));

        let searched = apk.search_classes_by_keyword(Some("Crypto"), 100);
        assert!(searched.contains(&"com.droidscope.sample.CryptoBridge".to_string()));

        let methods = apk
            .get_methods_of_class("com.droidscope.sample.MainActivity", 100)
            .expect("methods");
        assert!(methods.contains(&"com.droidscope.sample.MainActivity.onCreate".to_string()));

        let fields = apk
            .get_fields_of_class("com.droidscope.sample.MainActivity", 100)
            .expect("fields");
        assert!(fields.iter().any(|f| f.contains("TAG")));

        // 3. Class source, method source & smali
        let cls_src = apk
            .get_class_source("com.droidscope.sample.MainActivity", 8192)
            .expect("class source");
        assert!(cls_src.contains("class MainActivity"));
        assert!(cls_src.contains("onCreate"));

        let mth_src = apk
            .get_method_by_name("com.droidscope.sample.MainActivity", "onCreate", None)
            .expect("method source");
        assert!(mth_src.contains("onCreate"));

        let cls_smali = apk
            .get_smali_of_class("com.droidscope.sample.MainActivity", 1048576)
            .expect("class smali");
        assert!(cls_smali.contains("###### Class com.droidscope.sample.MainActivity"));

        let mth_smali = apk
            .get_smali_of_method("com.droidscope.sample.MainActivity", "onCreate", None)
            .expect("method smali");
        assert!(mth_smali.contains(".method protected onCreate(Landroid/os/Bundle;)V"));

        // 4. Cross-references, callees & security sinks
        let xrefs_cls = apk
            .get_xrefs_to_class("com.droidscope.sample.CryptoBridge", 100)
            .expect("xrefs to class");
        assert!(!xrefs_cls.is_empty());

        let callees = apk
            .get_callees("com.droidscope.sample.MainActivity", "onCreate", None, 100)
            .expect("callees");
        assert!(callees.get("callees").and_then(|v| v.as_array()).is_some());

        let sinks = apk.find_sink_call_sites(None, 100);
        let loadurl_sites = sinks
            .get("webview_loadurl")
            .and_then(|v| v.as_array())
            .expect("webview_loadurl");
        assert!(!loadurl_sites.is_empty());

        // 5. Type hierarchy, overrides & manifest components (with ARSC scheme resolution!)
        let hier = apk
            .get_type_hierarchy("com.droidscope.sample.MainActivity")
            .expect("hierarchy");
        assert_eq!(hier.get("inApk").and_then(|v| v.as_bool()), Some(true));

        let ov = apk
            .get_overrides("com.droidscope.sample.BaseActivity", "handleIntent", None, 100)
            .expect("overrides");
        assert_eq!(ov.get("inApk").and_then(|v| v.as_bool()), Some(true));

        let comps = apk.get_exported_components().expect("exported components");
        assert_eq!(comps.len(), 2);
        let deeplinks = apk.get_deeplink_components().expect("deeplink components");
        assert!(deeplinks.iter().any(|c| {
            c.get("name").and_then(|v| v.as_str())
                == Some("com.droidscope.sample.DeepLinkActivity")
        }));

        // 6. DEX Reconnaissance, strings, native methods & call paths
        let strings = apk.search_strings_in_dex(
            Some("ds_secret_key"),
            Some("com.droidscope.sample"),
            50,
        );
        assert!(!strings.is_empty());

        let natives = apk.get_native_methods(Some("com.droidscope.sample"), 50);
        assert!(natives.iter().any(|n| {
            n.get("jniSymbol").and_then(|v| v.as_str())
                == Some("Java_com_droidscope_sample_CryptoBridge_nativeSign")
                && n.get("libraries")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().any(|x| x.as_str() == Some("droidscope")))
                    .unwrap_or(false)
        }));

        let call_paths = apk
            .find_call_paths(
                "",
                "",
                "com.droidscope.sample.CryptoBridge",
                "nativeSign",
                6,
                10,
            )
            .expect("call paths");
        assert!(
            call_paths
                .get("pathsFound")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                > 0
        );

        let recon = apk.get_re_recon(Some("com.droidscope.sample"));
        assert_eq!(recon.get("format").and_then(|v| v.as_str()), Some("APK"));

        // 7. Native ELF64 (.so) & AArch64 RE tools on libdroidscope.so
        let lib_info = apk
            .get_native_lib_info("droidscope")
            .expect("native lib info");
        assert!(lib_info
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .ends_with("libdroidscope.so"));

        let reg_natives = apk
            .resolve_register_natives(Some("droidscope"), None, 50)
            .expect("register natives");
        assert!(reg_natives.iter().any(|r| {
            r.get("matchedJavaClasses")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .any(|c| c.as_str() == Some("com.droidscope.sample.CryptoBridge"))
                })
                .unwrap_or(false)
        }));

        let nat_strings = apk
            .search_native_strings("droidscope", Some("droidscope_hmac"), 50)
            .expect("native strings");
        assert!(!nat_strings.is_empty());

        let dis = apk
            .disassemble_native_arm64(
                "droidscope",
                "Java_com_droidscope_sample_CryptoBridge_nativeSign",
                16,
            )
            .expect("native disasm");
        assert!(dis
            .get("disassembly")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .contains("0x"));

        let func_analysis = apk
            .analyze_native_function(
                "droidscope",
                "Java_com_droidscope_sample_CryptoBridge_nativeSign",
                64,
            )
            .expect("native func analysis");
        assert!(func_analysis
            .get("basicBlocks")
            .and_then(|v| v.as_array())
            .map(|arr| !arr.is_empty())
            .unwrap_or(false));
    }

    #[test]
    fn test_multi_session_registry() {
        let mut reg = RegistryState::new(4);
        let (entry1, reused1) = reg
            .load_apk_session(&sample_apk_path(), Some("sample-main"))
            .expect("load sample-main");
        assert!(!reused1);
        assert_eq!(entry1.session_id, "sample-main");
        assert_eq!(reg.active_session_id().as_deref(), Some("sample-main"));

        let (entry1b, reused1b) = reg
            .load_apk_session(&sample_apk_path(), None)
            .expect("reuse sample-main");
        assert!(reused1b);
        assert_eq!(entry1b.session_id, "sample-main");

        assert!(reg.resolve(Some("sample-main")).is_ok());
        assert!(reg.resolve(Some("com.droidscope.sample")).is_ok());
        assert!(reg.resolve(Some("sample-app")).is_ok());
        assert!(reg.resolve(Some("nonexistent-session")).is_err());

        let info = reg.list_sessions_info();
        assert_eq!(info.get("totalOpen").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(
            info.get("activeSession").and_then(|v| v.as_str()),
            Some("sample-main")
        );

        let closed = reg
            .close_session(Some("sample-main"))
            .expect("close session");
        assert_eq!(
            closed.get("closedSession").and_then(|v| v.as_str()),
            Some("sample-main")
        );
        assert!(reg.active().is_err());
    }

    #[test]
    fn test_mcp_jsonrpc_protocol_and_35_tools() {
        let state = Arc::new(RwLock::new(RegistryState::new(4)));

        // 1. initialize
        let init_resp = mcp::handle_rpc_message(
            &state,
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": { "protocolVersion": "2024-11-05" }
            }),
        )
        .expect("initialize response");
        assert_eq!(
            init_resp["result"]["serverInfo"]["name"].as_str(),
            Some("droidscope-mcp")
        );

        // 2. tools/list -> 35 tools
        let list_resp = mcp::handle_rpc_message(
            &state,
            &json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list"
            }),
        )
        .expect("tools/list response");
        let tools = list_resp["result"]["tools"].as_array().expect("tools array");
        assert_eq!(tools.len(), 35);

        // 3. tools/call -> load_apk
        let load_resp = mcp::handle_rpc_message(
            &state,
            &json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "load_apk",
                    "arguments": {
                        "apkPath": sample_apk_path(),
                        "sessionId": "sample-mcp"
                    }
                }
            }),
        )
        .expect("load_apk response");
        assert_eq!(load_resp["result"]["isError"].as_bool(), Some(false));
        let load_txt = load_resp["result"]["content"][0]["text"]
            .as_str()
            .expect("text");
        let load_json: Value = serde_json::from_str(load_txt).expect("valid json");
        assert_eq!(load_json["sessionId"].as_str(), Some("sample-mcp"));
        assert_eq!(
            load_json["packageName"].as_str(),
            Some("com.droidscope.sample")
        );

        // 4. tools/call -> analyze_native_function via session="sample-mcp"
        let cfg_resp = mcp::handle_rpc_message(
            &state,
            &json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "analyze_native_function",
                    "arguments": {
                        "libName": "droidscope",
                        "target": "Java_com_droidscope_sample_CryptoBridge_nativeSign",
                        "session": "sample-mcp"
                    }
                }
            }),
        )
        .expect("analyze_native_function response");
        assert_eq!(cfg_resp["result"]["isError"].as_bool(), Some(false));
        let cfg_txt = cfg_resp["result"]["content"][0]["text"]
            .as_str()
            .expect("text");
        let cfg_json: Value = serde_json::from_str(cfg_txt).expect("valid json");
        assert!(!cfg_json["basicBlocks"]
            .as_array()
            .expect("basicBlocks")
            .is_empty());
    }
}
