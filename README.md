# droidscope-mcp

An Android reverse-engineering MCP server written in Rust. It reads multi-DEX bytecode, binary `AndroidManifest.xml` / `resources.arsc`, and bundled ARM64 `.so` libraries directly from an APK/AAB/DEX/JAR without spawning a JVM or unpacking the archive to disk.

Most existing Android MCP wrappers sit in front of JADX or an external Java process. On modern 300–500 MB apps (50+ `.dex` files, 400k+ classes), that means 15–24 GB of JVM heap, minute-long cold starts, and zero visibility once execution crosses `native` methods into `lib/arm64-v8a/*.so`. `droidscope-mcp` replaces that stack with a single native binary that speaks MCP JSON-RPC 2.0 over `stdio`.

## What it does

- **Zero-copy multi-DEX indexing**: Streams `classes*.dex` into a page-cached backing file (`mmap`) and builds a Compressed Sparse Row (CSR) reverse index (`4 bytes` per call/field/type edge) across millions of Dalvik instructions in ~1–2 seconds.
- **On-demand Dalvik decompiler & Smali disassembler**: Reconstructs Java source (`if`/`else`, loops, `switch`, `try`/`catch`) or Smali per class/method in `< 1 ms`. Large classes return a field/method `@outline` by default so you don't blow up your context window on a 5 MB `R$id` class.
- **Binary AXML & ARSC**: Decodes `AndroidManifest.xml`, exported components, and browsable deep links with `@string/...` references resolved against `resources.arsc`.
- **Native ELF & AArch64 engine**: Parses `.so` libraries in-memory, resolves both static `Java_*` symbols and obfuscated `JNI_OnLoad -> RegisterNatives` tables (including `.data.rel.ro`, `ADRP+ADD` triplets, and stack-constructed `JNINativeMethod` structs), disassembles ARM64, and builds function CFGs while stepping over LR-based anti-disassembly trampolines.
- **Multi-session**: Keeps up to 8 APKs warm in memory at once (`DROIDSCOPE_MAX_LOADED_APKS`). Every tool takes an optional `session` parameter so you can diff two APK versions or query multiple apps in parallel.

## Benchmarks

Measured on a single local workstation (Windows x64, NVMe):

| Target | Size / Classes | Cold Load + Index | Working Set (RAM) | Xref / Decompile Query |
|---|---|---|---|---|
| `sample-app.apk` | 2.3 KB / 4 classes | `< 2 ms` | ~15 MB | `< 0.5 ms` |
| Production E-Commerce APK | 206.5 MB / 13 DEX / 151,916 classes | `1.51 s` | ~1.06 GB | `< 1 ms` |
| Production Social/Video APK | 443.1 MB / 57 DEX / 481,091 classes / 2.06M methods | `6.42 s` | ~3.47 GB | `< 1 ms` |

Whole-APK sweeps (`find_sink_call_sites`, `get_re_recon`) finish in ~165–175 ms on the 481k-class APK.

## Build

Requires Rust 1.75+:

```bash
cargo build --release
```

The binary is placed at `target/release/droidscope-mcp` (`target\release\droidscope-mcp.exe` on Windows).

## MCP Configuration

Point your client (Claude Code, Claude Desktop, Cursor, Windsurf, Antigravity) directly at the compiled binary:

```json
{
  "mcpServers": {
    "droidscope-mcp": {
      "command": "/absolute/path/to/droidscope-mcp/target/release/droidscope-mcp",
      "args": []
    }
  }
}
```

If you want to run it as a standalone HTTP REST server instead of `stdio` MCP:

```bash
./target/release/droidscope-mcp --http
# listens on http://127.0.0.1:8765/api/droidscope/* (override port with DROIDSCOPE_PORT)
```

## Tools (35)

All analysis tools accept an optional `session` argument (matching a `sessionId`, package name, filename, or substring). Omit `session` to query the active APK.

### Session Management

| Tool | Arguments | Purpose |
|---|---|---|
| `load_apk` | `apkPath`, `sessionId?` | Load an APK/DEX/JAR/AAB into a session (0ms cache hit if already open) |
| `list_apk_sessions` | — | List open sessions, class/method/lib counts, and active state |
| `select_apk_session` | `session` | Switch the default active session |
| `close_apk_session` | `session?` | Close a session (`"all"` to close everything) and free its `mmap` |

### DEX Decompilation & Search

| Tool | Arguments | Purpose |
|---|---|---|
| `get_all_classes` | `packagePrefix?`, `limit?`, `session?` | List classes (default cap 1000; `limit=0` for uncapped) |
| `get_class_source` | `className`, `maxBytes?`, `session?` | Decompile class to Java (returns `@outline` if over 8 KB; `maxBytes=0` for full source) |
| `get_method_by_name` | `className`, `methodName`, `signature?`, `session?` | Decompile a specific method (or all overloads if `signature` omitted) |
| `get_methods_of_class` | `className`, `limit?`, `session?` | List method names declared by a class |
| `get_fields_of_class` | `className`, `limit?`, `session?` | List fields (`type name`) declared by a class |
| `get_smali_of_class` | `className`, `maxBytes?`, `session?` | Disassemble class to Smali |
| `get_smali_of_method` | `className`, `methodName`, `signature?`, `session?` | Disassemble method to Smali |
| `search_classes_by_keyword` | `keyword`, `limit?`, `session?` | Case-insensitive substring search over class names |
| `search_method_by_name` | `methodName`, `limit?`, `session?` | Case-insensitive substring search over method names |
| `search_strings_in_dex` | `query`, `packagePrefix?`, `limit?`, `session?` | Scan `const-string` instructions and static `String` initializers |

### Cross-References, Call Graph & Sinks

| Tool | Arguments | Purpose |
|---|---|---|
| `get_xrefs_to_class` | `className`, `limit?`, `session?` | All code and declaration references to a class |
| `get_xrefs_to_method` | `className`, `methodName`, `signature?`, `limit?`, `session?` | All callers of a method |
| `get_xrefs_to_field` | `className`, `fieldName`, `limit?`, `session?` | All methods reading or writing a field |
| `get_callees` | `className`, `methodName`, `signature?`, `limit?`, `session?` | Internal APK callees, external framework calls, and recursion flag |
| `get_type_hierarchy` | `className`, `session?` | Supertypes, interfaces, direct subclasses, outer/inner classes |
| `get_overrides` | `className`, `methodName`, `signature?`, `limit?`, `session?` | Base definitions and concrete overriding implementations |
| `find_call_paths` | `toClass`, `toMethod`, `fromClass?`, `fromMethod?`, `maxDepth?`, `limit?`, `session?` | Shortest-path BFS over the CSR call graph |
| `find_sink_call_sites` | `sinks?`, `limit?`, `session?` | Sweep 20 built-in sink categories (`webview_loadurl`, `intent_parse`, `exec`, `crypto_misuse`, etc.) or custom targets |
| `get_re_recon` | `packagePrefix?`, `session?` | One-shot overview: packers, SDKs, `.so` libs, TLS/OkHttp interceptors, crypto, JNI bridges, XOR-heavy methods |
| `get_native_methods` | `packagePrefix?`, `limit?`, `session?` | All `native` methods in DEX with mangled `Java_...` symbols and inferred `.so` names |

### Manifest & Resources

| Tool | Arguments | Purpose |
|---|---|---|
| `get_android_manifest` | `session?` | Decoded `AndroidManifest.xml` |
| `get_main_activity_class` | `session?` | Launcher activity class name |
| `get_exported_components` | `session?` | All components with `android:exported="true"` |
| `get_deeplink_components` | `session?` | Browsable/deeplink components with `@string/...` schemes resolved from `resources.arsc` |
| `get_all_resource_file_names` | `pathPrefix?`, `limit?`, `session?` | List archive entries (`res/`, `assets/`, `lib/`) |
| `get_resource_file` | `fileName`, `maxBytes?`, `session?` | Read text or binary-XML resource files |

### Native ELF (`.so`) & ARM64 Analysis

| Tool | Arguments | Purpose |
|---|---|---|
| `get_native_lib_info` | `libName`, `session?` | ELF headers, sections, `.init_array` ctors, `JNI_OnLoad`, imports, crypto S-boxes/constants, packer/Frida checks |
| `resolve_register_natives` | `libName?`, `className?`, `limit?`, `session?` | Recover static `Java_*` exports and dynamic `RegisterNatives` bindings (`.data.rel.ro`, `ADRP+ADD`, stack structs) |
| `search_native_strings` | `libName`, `query?`, `limit?`, `session?` | Extract printable strings from `.so` and resolve ARM64 `ADRP+ADD` code xrefs |
| `disassemble_native_arm64` | `libName`, `target`, `instructions?`, `session?` | Decode ARM64 instructions at a hex vaddr or symbol with `.plt`, string, `JNIEnv*` vtable, and trampoline annotations |
| `analyze_native_function` | `libName`, `target`, `maxInstructions?`, `session?` | Build ARM64 basic-block CFG (stepping over anti-disasm trampolines), callers, `JNIEnv*` calls, string/data refs, and obfuscation flags |

## Testing

```bash
cargo test --release
```

Runs the test suite against [`misc/sample-app.apk`](misc/sample-app.apk) (a 2.3 KB synthetic fixture containing AXML, ARSC, DEX, and an ARM64 `libdroidscope.so`).

## License

[MIT](LICENSE)
