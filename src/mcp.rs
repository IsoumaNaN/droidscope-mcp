use std::io::{self, BufRead, BufReader, Write};
use std::sync::{Arc, RwLock};

use serde_json::{json, Map, Value};

use crate::guards::{
    DEFAULT_CALL_SITE_LIMIT, DEFAULT_MAX_BYTES, DEFAULT_RESULT_LIMIT, DEFAULT_SOFT_BYTES,
};
use crate::RegistryState;

fn str_arg<'a>(args: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
}

fn req_str_arg<'a>(args: &'a Map<String, Value>, key: &str) -> Result<&'a str, String> {
    str_arg(args, key).ok_or_else(|| format!("{} is required", key))
}

fn int_arg(args: &Map<String, Value>, key: &str, default_val: i32) -> i32 {
    match args.get(key) {
        Some(Value::Number(n)) => n.as_i64().map(|v| v as i32).unwrap_or(default_val),
        Some(Value::String(s)) => s.trim().parse::<i32>().unwrap_or(default_val),
        _ => default_val,
    }
}

pub fn execute_tool(
    state: &Arc<RwLock<RegistryState>>,
    name: &str,
    args: &Map<String, Value>,
) -> Result<Value, String> {
    match name {
        "load_apk" => {
            let apk_path = req_str_arg(args, "apkPath")?;
            let preferred_session = str_arg(args, "sessionId").or_else(|| str_arg(args, "session"));
            let mut guard = state.write().unwrap();
            let (entry, reused) = guard.load_apk_session(apk_path, preferred_session)?;
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
            Ok(Value::Object(info))
        }

        "list_apk_sessions" => {
            let info = state.read().unwrap().list_sessions_info();
            Ok(Value::Object(info))
        }

        "select_apk_session" => {
            let target = str_arg(args, "session")
                .or_else(|| str_arg(args, "sessionId"))
                .ok_or_else(|| "session is required".to_string())?;
            let mut guard = state.write().unwrap();
            let entry = guard.select_session(target)?;
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
            Ok(Value::Object(info))
        }

        "close_apk_session" => {
            let target = str_arg(args, "session").or_else(|| str_arg(args, "sessionId"));
            let mut guard = state.write().unwrap();
            let res = guard.close_session(target)?;
            Ok(Value::Object(res))
        }

        _ => {
            let session = str_arg(args, "session");
            let apk = state.read().unwrap().resolve(session)?;

            match name {
                "get_all_classes" => {
                    let prefix = str_arg(args, "packagePrefix");
                    let limit = int_arg(args, "limit", DEFAULT_RESULT_LIMIT);
                    let classes = apk.get_all_classes(prefix, limit);
                    Ok(Value::Array(
                        classes.into_iter().map(Value::String).collect(),
                    ))
                }

                "get_class_source" => {
                    let class_name = req_str_arg(args, "className")?;
                    let max_bytes = int_arg(args, "maxBytes", DEFAULT_SOFT_BYTES);
                    let src = apk.get_class_source(class_name, max_bytes)?;
                    Ok(Value::String(src))
                }

                "get_methods_of_class" => {
                    let class_name = req_str_arg(args, "className")?;
                    let limit = int_arg(args, "limit", DEFAULT_RESULT_LIMIT);
                    let methods = apk.get_methods_of_class(class_name, limit)?;
                    Ok(Value::Array(
                        methods.into_iter().map(Value::String).collect(),
                    ))
                }

                "get_fields_of_class" => {
                    let class_name = req_str_arg(args, "className")?;
                    let limit = int_arg(args, "limit", DEFAULT_RESULT_LIMIT);
                    let fields = apk.get_fields_of_class(class_name, limit)?;
                    Ok(Value::Array(
                        fields.into_iter().map(Value::String).collect(),
                    ))
                }

                "get_method_by_name" => {
                    let class_name = req_str_arg(args, "className")?;
                    let method_name = req_str_arg(args, "methodName")?;
                    let signature = str_arg(args, "signature");
                    let src = apk.get_method_by_name(class_name, method_name, signature)?;
                    Ok(Value::String(src))
                }

                "search_method_by_name" => {
                    let method_name = args
                        .get("methodName")
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim());
                    let limit = int_arg(args, "limit", DEFAULT_RESULT_LIMIT);
                    let results = apk.search_method_by_name(method_name, limit);
                    Ok(Value::Object(results))
                }

                "search_classes_by_keyword" => {
                    let keyword = args
                        .get("keyword")
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim());
                    let limit = int_arg(args, "limit", DEFAULT_RESULT_LIMIT);
                    let classes = apk.search_classes_by_keyword(keyword, limit);
                    Ok(Value::Array(
                        classes.into_iter().map(Value::String).collect(),
                    ))
                }

                "get_xrefs_to_class" => {
                    let class_name = req_str_arg(args, "className")?;
                    let limit = int_arg(args, "limit", DEFAULT_RESULT_LIMIT);
                    let xrefs = apk.get_xrefs_to_class(class_name, limit)?;
                    Ok(Value::Array(xrefs.into_iter().map(Value::Object).collect()))
                }

                "get_xrefs_to_method" => {
                    let class_name = req_str_arg(args, "className")?;
                    let method_name = req_str_arg(args, "methodName")?;
                    let signature = str_arg(args, "signature");
                    let limit = int_arg(args, "limit", DEFAULT_RESULT_LIMIT);
                    let xrefs =
                        apk.get_xrefs_to_method(class_name, method_name, signature, limit)?;
                    Ok(Value::Array(xrefs.into_iter().map(Value::Object).collect()))
                }

                "get_xrefs_to_field" => {
                    let class_name = req_str_arg(args, "className")?;
                    let field_name = req_str_arg(args, "fieldName")?;
                    let limit = int_arg(args, "limit", DEFAULT_RESULT_LIMIT);
                    let xrefs = apk.get_xrefs_to_field(class_name, field_name, limit)?;
                    Ok(Value::Array(xrefs.into_iter().map(Value::Object).collect()))
                }

                "get_callees" => {
                    let class_name = req_str_arg(args, "className")?;
                    let method_name = req_str_arg(args, "methodName")?;
                    let signature = str_arg(args, "signature");
                    let limit = int_arg(args, "limit", DEFAULT_RESULT_LIMIT);
                    let callees = apk.get_callees(class_name, method_name, signature, limit)?;
                    Ok(Value::Object(callees))
                }

                "find_sink_call_sites" => {
                    let limit = int_arg(args, "limit", DEFAULT_CALL_SITE_LIMIT);
                    let sink_list: Option<Vec<String>> = match args.get("sinks") {
                        Some(Value::Array(arr)) => {
                            let v: Vec<String> = arr
                                .iter()
                                .filter_map(|x| x.as_str())
                                .flat_map(|s| s.split(','))
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .collect();
                            if v.is_empty() {
                                None
                            } else {
                                Some(v)
                            }
                        }
                        Some(Value::String(s)) => {
                            let v: Vec<String> = s
                                .split(',')
                                .map(|x| x.trim().to_string())
                                .filter(|x| !x.is_empty())
                                .collect();
                            if v.is_empty() {
                                None
                            } else {
                                Some(v)
                            }
                        }
                        _ => None,
                    };
                    let sites = apk.find_sink_call_sites(sink_list.as_deref(), limit);
                    Ok(Value::Object(sites))
                }

                "get_type_hierarchy" => {
                    let class_name = req_str_arg(args, "className")?;
                    let h = apk.get_type_hierarchy(class_name)?;
                    Ok(Value::Object(h))
                }

                "get_overrides" => {
                    let class_name = req_str_arg(args, "className")?;
                    let method_name = req_str_arg(args, "methodName")?;
                    let signature = str_arg(args, "signature");
                    let limit = int_arg(args, "limit", DEFAULT_RESULT_LIMIT);
                    let ov = apk.get_overrides(class_name, method_name, signature, limit)?;
                    Ok(Value::Object(ov))
                }

                "get_exported_components" => {
                    let comps = apk.get_exported_components()?;
                    Ok(Value::Array(comps.into_iter().map(Value::Object).collect()))
                }

                "get_deeplink_components" => {
                    let comps = apk.get_deeplink_components()?;
                    Ok(Value::Array(comps.into_iter().map(Value::Object).collect()))
                }

                "get_android_manifest" => {
                    let m = apk.get_android_manifest()?;
                    Ok(Value::String(m))
                }

                "get_main_activity_class" => Ok(apk
                    .get_main_activity_class()
                    .map(Value::String)
                    .unwrap_or(Value::Null)),

                "get_all_resource_file_names" => {
                    let prefix = str_arg(args, "pathPrefix");
                    let limit = int_arg(args, "limit", DEFAULT_RESULT_LIMIT);
                    let res = apk.get_all_resource_file_names(prefix, limit);
                    Ok(Value::Array(res.into_iter().map(Value::String).collect()))
                }

                "get_resource_file" => {
                    let file_name = req_str_arg(args, "fileName")?;
                    let max_bytes = int_arg(args, "maxBytes", DEFAULT_MAX_BYTES);
                    let content = apk.get_resource_file(file_name, max_bytes)?;
                    Ok(Value::String(content))
                }

                "get_smali_of_class" => {
                    let class_name = req_str_arg(args, "className")?;
                    let max_bytes = int_arg(args, "maxBytes", DEFAULT_MAX_BYTES);
                    let smali = apk.get_smali_of_class(class_name, max_bytes)?;
                    Ok(Value::String(smali))
                }

                "get_smali_of_method" => {
                    let class_name = req_str_arg(args, "className")?;
                    let method_name = req_str_arg(args, "methodName")?;
                    let signature = str_arg(args, "signature");
                    let smali = apk.get_smali_of_method(class_name, method_name, signature)?;
                    Ok(Value::String(smali))
                }

                "search_strings_in_dex" => {
                    let query = args.get("query").and_then(|v| v.as_str());
                    let prefix = str_arg(args, "packagePrefix");
                    let limit = int_arg(args, "limit", DEFAULT_RESULT_LIMIT);
                    let strings = apk.search_strings_in_dex(query, prefix, limit);
                    Ok(Value::Array(
                        strings.into_iter().map(Value::Object).collect(),
                    ))
                }

                "find_call_paths" => {
                    let to_class = req_str_arg(args, "toClass")?;
                    let to_method = req_str_arg(args, "toMethod")?;
                    let from_class = str_arg(args, "fromClass").unwrap_or("");
                    let from_method = str_arg(args, "fromMethod").unwrap_or("");
                    let max_depth = int_arg(args, "maxDepth", 6);
                    let limit = int_arg(args, "limit", 20);
                    let paths = apk.find_call_paths(
                        from_class,
                        from_method,
                        to_class,
                        to_method,
                        max_depth,
                        limit,
                    )?;
                    Ok(Value::Object(paths))
                }

                "get_native_methods" => {
                    let prefix = str_arg(args, "packagePrefix");
                    let limit = int_arg(args, "limit", DEFAULT_RESULT_LIMIT);
                    let natives = apk.get_native_methods(prefix, limit);
                    Ok(Value::Array(
                        natives.into_iter().map(Value::Object).collect(),
                    ))
                }

                "get_re_recon" => {
                    let prefix = str_arg(args, "packagePrefix");
                    let recon = apk.get_re_recon(prefix);
                    Ok(Value::Object(recon))
                }

                "get_native_lib_info" => {
                    let lib_name = req_str_arg(args, "libName")?;
                    let info = apk.get_native_lib_info(lib_name)?;
                    Ok(Value::Object(info))
                }

                "resolve_register_natives" => {
                    let lib_name = str_arg(args, "libName");
                    let class_name = str_arg(args, "className");
                    let limit = int_arg(args, "limit", DEFAULT_RESULT_LIMIT);
                    let items = apk.resolve_register_natives(lib_name, class_name, limit)?;
                    Ok(Value::Array(items.into_iter().map(Value::Object).collect()))
                }

                "search_native_strings" => {
                    let lib_name = req_str_arg(args, "libName")?;
                    let query = str_arg(args, "query");
                    let limit = int_arg(args, "limit", DEFAULT_RESULT_LIMIT);
                    let items = apk.search_native_strings(lib_name, query, limit)?;
                    Ok(Value::Array(items.into_iter().map(Value::Object).collect()))
                }

                "disassemble_native_arm64" => {
                    let lib_name = req_str_arg(args, "libName")?;
                    let target = req_str_arg(args, "target")?;
                    let instructions = int_arg(args, "instructions", 64);
                    let dis = apk.disassemble_native_arm64(lib_name, target, instructions)?;
                    Ok(Value::Object(dis))
                }

                "analyze_native_function" => {
                    let lib_name = req_str_arg(args, "libName")?;
                    let target = req_str_arg(args, "target")?;
                    let max_instructions = int_arg(args, "maxInstructions", 256);
                    let analysis =
                        apk.analyze_native_function(lib_name, target, max_instructions)?;
                    Ok(Value::Object(analysis))
                }

                _ => Err(format!("Unknown tool: {}", name)),
            }
        }
    }
}

fn tool_def(name: &str, description: &str, properties: Value, required: &[&str]) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": required,
        }
    })
}

pub fn list_mcp_tools() -> Vec<Value> {
    let session_prop = json!({
        "type": "string",
        "description": "Optional session ID, package name, filename, or unique substring targeting a specific loaded APK session. Omit to query the active session."
    });

    vec![
        tool_def(
            "load_apk",
            "Load and index an APK, DEX, JAR, or AAB file into a named multi-session slot. Re-opening an already loaded path reuses the warm index in 0ms.",
            json!({
                "apkPath": { "type": "string", "description": "Absolute or relative path to the APK, DEX, JAR, or AAB file" },
                "sessionId": { "type": "string", "description": "Optional custom session alias (e.g. 'app-v1', 'app-v2')" }
            }),
            &["apkPath"],
        ),
        tool_def(
            "list_apk_sessions",
            "List all APK/DEX/JAR/AAB sessions currently loaded in memory, including sessionId, active status, packageName, apkPath, class/method counts, and native library counts.",
            json!({}),
            &[],
        ),
        tool_def(
            "select_apk_session",
            "Switch the default active APK session by sessionId, package name, file name, or unique substring.",
            json!({
                "session": { "type": "string", "description": "Target sessionId, package name, or file name" }
            }),
            &["session"],
        ),
        tool_def(
            "close_apk_session",
            "Close an open APK session and free its memory-mapped DEX and CSR index. Omit session to close the active session, or pass 'all' to close all sessions.",
            json!({
                "session": { "type": "string", "description": "Optional sessionId to close (or 'all' for all sessions)" }
            }),
            &[],
        ),
        tool_def(
            "get_all_classes",
            "List class names in the loaded APK, inner classes included. Pass packagePrefix to filter by package subtree (case-insensitive) and limit to cap results (default 1000; 0 for uncapped).",
            json!({
                "packagePrefix": { "type": "string", "description": "Optional package or class prefix filter" },
                "limit": { "type": "integer", "description": "Maximum number of class names (default 1000; 0 for uncapped)" },
                "session": session_prop
            }),
            &[],
        ),
        tool_def(
            "get_class_source",
            "Get the decompiled Java source of a class, or its field/method outline (@outline:) if the source exceeds maxBytes (default 8192; 0 for uncapped).",
            json!({
                "className": { "type": "string", "description": "Fully-qualified class name" },
                "maxBytes": { "type": "integer", "description": "Byte budget before returning class outline (default 8192; 0 for uncapped)" },
                "session": session_prop
            }),
            &["className"],
        ),
        tool_def(
            "get_methods_of_class",
            "List a class's declared methods as fully-qualified names (capped at 1000 by default; 0 for uncapped).",
            json!({
                "className": { "type": "string", "description": "Fully-qualified class name" },
                "limit": { "type": "integer", "description": "Maximum number of methods (default 1000; 0 for uncapped)" },
                "session": session_prop
            }),
            &["className"],
        ),
        tool_def(
            "get_fields_of_class",
            "List a class's declared fields as 'type name' entries sorted by name (capped at 1000 by default; 0 for uncapped).",
            json!({
                "className": { "type": "string", "description": "Fully-qualified class name" },
                "limit": { "type": "integer", "description": "Maximum number of fields (default 1000; 0 for uncapped)" },
                "session": session_prop
            }),
            &["className"],
        ),
        tool_def(
            "get_method_by_name",
            "Get the decompiled Java source of a specific method. Pass signature (e.g. '(Ljava/lang/String;)V') to disambiguate overloaded methods.",
            json!({
                "className": { "type": "string", "description": "Fully-qualified class name" },
                "methodName": { "type": "string", "description": "Method name ('<init>' for constructors, '<clinit>' for static initializer)" },
                "signature": { "type": "string", "description": "Optional JNI/Dalvik method descriptor to disambiguate overloads" },
                "session": session_prop
            }),
            &["className", "methodName"],
        ),
        tool_def(
            "search_method_by_name",
            "Search for methods across all classes by case-insensitive substring (minimum 2 characters). Returns a map of className -> matching method names.",
            json!({
                "methodName": { "type": "string", "description": "Method name substring (min 2 chars)" },
                "limit": { "type": "integer", "description": "Max matching classes (default 1000; 0 for uncapped)" },
                "session": session_prop
            }),
            &["methodName"],
        ),
        tool_def(
            "search_classes_by_keyword",
            "Search for classes whose fully-qualified name contains keyword (case-insensitive, minimum 2 characters).",
            json!({
                "keyword": { "type": "string", "description": "Keyword to match anywhere in the class name (min 2 chars)" },
                "limit": { "type": "integer", "description": "Max matching classes (default 1000; 0 for uncapped)" },
                "session": session_prop
            }),
            &["keyword"],
        ),
        tool_def(
            "get_xrefs_to_class",
            "Find all references to a class across the DEX CSR reverse index. Returns entries of {'className', 'methodName', 'signature'}.",
            json!({
                "className": { "type": "string", "description": "Target class name" },
                "limit": { "type": "integer", "description": "Max references (default 1000; 0 for uncapped)" },
                "session": session_prop
            }),
            &["className"],
        ),
        tool_def(
            "get_xrefs_to_method",
            "Find all callers of a method across the DEX CSR reverse index.",
            json!({
                "className": { "type": "string", "description": "Declaring class name" },
                "methodName": { "type": "string", "description": "Target method name" },
                "signature": { "type": "string", "description": "Optional method signature to disambiguate overloads" },
                "limit": { "type": "integer", "description": "Max callers (default 1000; 0 for uncapped)" },
                "session": session_prop
            }),
            &["className", "methodName"],
        ),
        tool_def(
            "get_xrefs_to_field",
            "Find all methods reading or writing a field across the DEX CSR reverse index.",
            json!({
                "className": { "type": "string", "description": "Declaring class name" },
                "fieldName": { "type": "string", "description": "Target field name (or 'type name')" },
                "limit": { "type": "integer", "description": "Max references (default 1000; 0 for uncapped)" },
                "session": session_prop
            }),
            &["className", "fieldName"],
        ),
        tool_def(
            "get_callees",
            "Find all internal APK methods (callees) and external framework/SDK methods (external) invoked by a method, plus self-recursion (callsSelf).",
            json!({
                "className": { "type": "string", "description": "Declaring class name" },
                "methodName": { "type": "string", "description": "Method name" },
                "signature": { "type": "string", "description": "Optional method signature" },
                "limit": { "type": "integer", "description": "Max entries per list (default 1000; 0 for uncapped)" },
                "session": session_prop
            }),
            &["className", "methodName"],
        ),
        tool_def(
            "find_sink_call_sites",
            "Sweep the entire APK for security sink call sites across 20 built-in categories (webview_loadurl, js_bridge_call, intent_launch, intent_parse, file_read, file_write, exec, native_load, class_load, network_request, crypto_misuse, etc.) or custom 'package.Class.method' targets.",
            json!({
                "sinks": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Optional list of sink category tags or 'package.Class.method' targets. Omit to sweep all 20 categories."
                },
                "limit": { "type": "integer", "description": "Max call sites per sink (default 100; 0 for uncapped)" },
                "session": session_prop
            }),
            &[],
        ),
        tool_def(
            "get_type_hierarchy",
            "Get supertypes, implemented interfaces, direct subclasses, and outer/inner classes for a class.",
            json!({
                "className": { "type": "string", "description": "Target class name" },
                "session": session_prop
            }),
            &["className"],
        ),
        tool_def(
            "get_overrides",
            "Get concrete methods overriding a method (overriddenBy) and base methods it overrides (baseMethods), resolving class and interface dispatch.",
            json!({
                "className": { "type": "string", "description": "Declaring class or interface name" },
                "methodName": { "type": "string", "description": "Method name" },
                "signature": { "type": "string", "description": "Optional method signature" },
                "limit": { "type": "integer", "description": "Max entries (default 1000; 0 for uncapped)" },
                "session": session_prop
            }),
            &["className", "methodName"],
        ),
        tool_def(
            "get_exported_components",
            "Get all manifest components whose android:exported resolves to true, including the launcher activity and intent filters.",
            json!({
                "session": session_prop
            }),
            &[],
        ),
        tool_def(
            "get_deeplink_components",
            "Get all browsable/deeplink and exported components with @string/... scheme, host, and path references resolved against resources.arsc.",
            json!({
                "session": session_prop
            }),
            &[],
        ),
        tool_def(
            "get_android_manifest",
            "Get the decoded AndroidManifest.xml content.",
            json!({
                "session": session_prop
            }),
            &[],
        ),
        tool_def(
            "get_main_activity_class",
            "Get the main launcher activity class name from AndroidManifest.xml.",
            json!({
                "session": session_prop
            }),
            &[],
        ),
        tool_def(
            "get_all_resource_file_names",
            "List resource, asset, and native library entry names in the archive. Pass pathPrefix (e.g. 'res/xml', 'assets/', 'lib/arm64-v8a/') to filter.",
            json!({
                "pathPrefix": { "type": "string", "description": "Optional archive path prefix filter" },
                "limit": { "type": "integer", "description": "Max entries (default 1000; 0 for uncapped)" },
                "session": session_prop
            }),
            &[],
        ),
        tool_def(
            "get_resource_file",
            "Get the content of a resource or asset file (automatically decodes binary XML files under res/).",
            json!({
                "fileName": { "type": "string", "description": "Archive path of the resource file" },
                "maxBytes": { "type": "integer", "description": "Max bytes to return (default 1048576; 0 for uncapped)" },
                "session": session_prop
            }),
            &["fileName"],
        ),
        tool_def(
            "get_smali_of_class",
            "Get the disassembled Smali code of a class.",
            json!({
                "className": { "type": "string", "description": "Fully-qualified class name" },
                "maxBytes": { "type": "integer", "description": "Max bytes to return (default 1048576; 0 for uncapped)" },
                "session": session_prop
            }),
            &["className"],
        ),
        tool_def(
            "get_smali_of_method",
            "Get the disassembled Smali code of a specific method.",
            json!({
                "className": { "type": "string", "description": "Fully-qualified class name" },
                "methodName": { "type": "string", "description": "Method name" },
                "signature": { "type": "string", "description": "Optional method signature" },
                "session": session_prop
            }),
            &["className", "methodName"],
        ),
        tool_def(
            "search_strings_in_dex",
            "Search string literals in Dalvik bytecode (const-string instructions) and static String field initializers without decompiling classes.",
            json!({
                "query": { "type": "string", "description": "Case-insensitive substring to search (min 2 chars)" },
                "packagePrefix": { "type": "string", "description": "Optional package prefix scope" },
                "limit": { "type": "integer", "description": "Max matches (default 1000; 0 for uncapped)" },
                "session": session_prop
            }),
            &["query"],
        ),
        tool_def(
            "find_call_paths",
            "Find shortest call chains from an entrypoint or class/method to a target method or framework sink using in-memory BFS over the DEX CSR reverse index.",
            json!({
                "toClass": { "type": "string", "description": "Destination class name" },
                "toMethod": { "type": "string", "description": "Destination method name" },
                "fromClass": { "type": "string", "description": "Optional source class name (omit to search from all exported entrypoints)" },
                "fromMethod": { "type": "string", "description": "Optional source method name" },
                "maxDepth": { "type": "integer", "description": "Maximum BFS call depth (default 6, max 15)" },
                "limit": { "type": "integer", "description": "Max paths returned (default 20)" },
                "session": session_prop
            }),
            &["toClass", "toMethod"],
        ),
        tool_def(
            "get_native_methods",
            "List native (JNI) methods declared in DEX along with their standard mangled Java_... symbol names and inferred .so library names.",
            json!({
                "packagePrefix": { "type": "string", "description": "Optional package prefix filter" },
                "limit": { "type": "integer", "description": "Max entries (default 1000; 0 for uncapped)" },
                "session": session_prop
            }),
            &[],
        ),
        tool_def(
            "get_re_recon",
            "Get a one-shot reverse-engineering reconnaissance summary: package metadata, counts, bundled .so libraries, detected frameworks and packer/anti-tamper signatures, plus high-value targets (network/TLS interceptors, crypto classes, JNI bridges, reflection, and XOR-heavy string decryptor candidates).",
            json!({
                "packagePrefix": { "type": "string", "description": "Optional package prefix filter" },
                "session": session_prop
            }),
            &[],
        ),
        tool_def(
            "get_native_lib_info",
            "Inspect a bundled native ELF (.so) library directly from the APK: architecture, sections, .init_array constructors, JNI_OnLoad address, static Java_* exports, categorized security imports, cryptographic constant signatures (AES S-Box, SHA-256, ChaCha20, MD5, Base64), and packer/Frida/anti-tamper indicators.",
            json!({
                "libName": { "type": "string", "description": "Library name ('foo', 'libfoo.so', or 'lib/arm64-v8a/libfoo.so')" },
                "session": session_prop
            }),
            &["libName"],
        ),
        tool_def(
            "resolve_register_natives",
            "Resolve JNI native method bindings across .so libraries in the APK, covering static Java_* exports and dynamic JNI_OnLoad -> RegisterNatives bindings (relocated .data.rel.ro/.data tables, AArch64 ADR/ADRP+ADD/ADRP+LDR code triplets, and stack-constructed stp/str [sp, #imm] structs).",
            json!({
                "libName": { "type": "string", "description": "Optional .so library name filter" },
                "className": { "type": "string", "description": "Optional Java class name filter" },
                "limit": { "type": "integer", "description": "Max entries (default 1000; 0 for uncapped)" },
                "session": session_prop
            }),
            &[],
        ),
        tool_def(
            "search_native_strings",
            "Search printable ASCII strings inside a native .so library and automatically resolve AArch64 ADRP+ADD code cross-references (codeXrefs) pointing to each matched string.",
            json!({
                "libName": { "type": "string", "description": "Library name ('foo', 'libfoo.so', or full path)" },
                "query": { "type": "string", "description": "Optional case-insensitive substring filter" },
                "limit": { "type": "integer", "description": "Max strings (default 1000; 0 for uncapped)" },
                "session": session_prop
            }),
            &["libName"],
        ),
        tool_def(
            "disassemble_native_arm64",
            "Disassemble AArch64 (ARM64) machine code inside a native .so library at a hex virtual address ('0x59fa0') or exported symbol name ('JNI_OnLoad', 'Java_...'), annotating .plt calls, ADRP+ADD string references, JNIEnv* vtable calls, and LR-based anti-disassembly trampolines.",
            json!({
                "libName": { "type": "string", "description": "Library name ('foo', 'libfoo.so', or full path)" },
                "target": { "type": "string", "description": "Hex virtual address ('0x120d90') or exported symbol name" },
                "instructions": { "type": "integer", "description": "Number of 32-bit AArch64 instructions to decode (default 64, max 2000)" },
                "session": session_prop
            }),
            &["libName", "target"],
        ),
        tool_def(
            "analyze_native_function",
            "Perform AArch64 control-flow graph (basicBlocks), cross-reference (incomingXrefs), JNIEnv* vtable (jniApiCalls), string/global data reference, and anti-obfuscation (protectionSummary) analysis on a native function inside a .so library.",
            json!({
                "libName": { "type": "string", "description": "Library name ('foo', 'libfoo.so', or full path)" },
                "target": { "type": "string", "description": "Hex virtual address ('0x120d90') or exported symbol name" },
                "maxInstructions": { "type": "integer", "description": "Maximum instructions to traverse across CFG basic blocks (default 256, max 2000)" },
                "session": session_prop
            }),
            &["libName", "target"],
        ),
    ]
}

pub fn handle_rpc_message(state: &Arc<RwLock<RegistryState>>, msg: &Value) -> Option<Value> {
    let method = msg.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let id = msg.get("id").cloned();

    // Notifications have no "id" and expect no response
    let id_val = id?;

    match method {
        "initialize" => {
            let client_version = msg
                .get("params")
                .and_then(|p| p.get("protocolVersion"))
                .and_then(|v| v.as_str())
                .unwrap_or("2024-11-05");
            Some(json!({
                "jsonrpc": "2.0",
                "id": id_val,
                "result": {
                    "protocolVersion": client_version,
                    "capabilities": {
                        "tools": {
                            "listChanged": false
                        }
                    },
                    "serverInfo": {
                        "name": "droidscope-mcp",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                }
            }))
        }

        "ping" => Some(json!({
            "jsonrpc": "2.0",
            "id": id_val,
            "result": {}
        })),

        "tools/list" => Some(json!({
            "jsonrpc": "2.0",
            "id": id_val,
            "result": {
                "tools": list_mcp_tools()
            }
        })),

        "resources/list" => Some(json!({
            "jsonrpc": "2.0",
            "id": id_val,
            "result": {
                "resources": []
            }
        })),

        "prompts/list" => Some(json!({
            "jsonrpc": "2.0",
            "id": id_val,
            "result": {
                "prompts": []
            }
        })),

        "tools/call" => {
            let params = msg.get("params");
            let tool_name = params
                .and_then(|p| p.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let empty_map = Map::new();
            let args = params
                .and_then(|p| p.get("arguments"))
                .and_then(|v| v.as_object())
                .unwrap_or(&empty_map);

            match execute_tool(state, tool_name, args) {
                Ok(val) => {
                    let serialized =
                        serde_json::to_string(&val).unwrap_or_else(|_| "null".to_string());
                    Some(json!({
                        "jsonrpc": "2.0",
                        "id": id_val,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": serialized
                                }
                            ],
                            "isError": false
                        }
                    }))
                }
                Err(err_msg) => Some(json!({
                    "jsonrpc": "2.0",
                    "id": id_val,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": err_msg
                            }
                        ],
                        "isError": true
                    }
                })),
            }
        }

        _ => Some(json!({
            "jsonrpc": "2.0",
            "id": id_val,
            "error": {
                "code": -32601,
                "message": format!("Method not found: {}", method)
            }
        })),
    }
}

pub fn run_mcp_stdio(state: Arc<RwLock<RegistryState>>) {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();

    loop {
        let mut line = String::new();
        let Ok(n) = reader.read_line(&mut line) else {
            break;
        };
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Support both Content-Length framed messages and standard MCP line-delimited JSON
        let payload_str = if let Some(rest) = trimmed.strip_prefix("Content-Length:") {
            let len = rest.trim().parse::<usize>().unwrap_or(0);
            // Skip remaining header lines until empty line
            loop {
                let mut hdr = String::new();
                if reader.read_line(&mut hdr).unwrap_or(0) == 0 || hdr.trim().is_empty() {
                    break;
                }
            }
            if len == 0 {
                continue;
            }
            let mut buf = vec![0u8; len];
            if io::Read::read_exact(&mut reader, &mut buf).is_err() {
                break;
            }
            String::from_utf8_lossy(&buf).into_owned()
        } else {
            trimmed.to_string()
        };

        let Ok(parsed) = serde_json::from_str::<Value>(&payload_str) else {
            continue;
        };

        if let Some(arr) = parsed.as_array() {
            let mut responses = Vec::new();
            for item in arr {
                if let Some(resp) = handle_rpc_message(&state, item) {
                    responses.push(resp);
                }
            }
            if !responses.is_empty() {
                if let Ok(out) = serde_json::to_string(&Value::Array(responses)) {
                    let _ = writeln!(writer, "{}", out);
                    let _ = writer.flush();
                }
            }
        } else if let Some(resp) = handle_rpc_message(&state, &parsed) {
            if let Ok(out) = serde_json::to_string(&resp) {
                let _ = writeln!(writer, "{}", out);
                let _ = writer.flush();
            }
        }
    }
}
