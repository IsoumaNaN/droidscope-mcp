use serde_json::{Map, Value};

pub const DEFAULT_RESULT_LIMIT: i32 = 1000;
pub const DEFAULT_CALL_SITE_LIMIT: i32 = 100;
pub const DEFAULT_MAX_BYTES: i32 = 1_048_576;
pub const DEFAULT_SOFT_BYTES: i32 = 8_192;
pub const OVERSIZED_RESPONSE_BYTES: i64 = 1_048_576;
pub const MIN_QUERY_LENGTH: usize = 2;

pub const TRUNCATION_MARKER_PREFIX: &str = "@truncated";
pub const OVERSIZED_MARKER_PREFIX: &str = "@oversized";
pub const AMBIGUOUS_MARKER_PREFIX: &str = "@ambiguous";
pub const REJECTED_MARKER_PREFIX: &str = "@rejected";
pub const OUTLINE_MARKER_PREFIX: &str = "@outline";
pub const RESOLVED_IN_APK_KEY: &str = "@resolved_in_apk";

pub const RAISE_LIMIT: &str = "Raise limit, or pass limit 0 for the rest.";

pub const XREF_ADVICE: &str = "A target this widely referenced is usually a utility rather than the thing being traced -- ask about the caller you actually came from instead.";
pub const CALLEE_ADVICE: &str = "A method this wide is usually a generated table-filler or router -- use get_method_by_name to read the dispatch directly.";
pub const MEMBER_ADVICE: &str = "A class this wide is usually generated -- an R table or a Kotlin stdlib facade -- so the name you want is better found with search_method_by_name.";
pub const OVERRIDE_ADVICE: &str = "A method this widely implemented is a framework callback rather than a dispatch target -- narrow by asking about the interface the caller actually holds, or use search_classes_by_keyword.";
pub const RESOURCE_TOO_BIG: &str = "A file this size is a binary asset or a bundled library, not something to read in a context window -- unzip it if you need the whole thing.";

pub const CLASS_SEARCH_COST: &str = "most of the APK: on a 141,461-class target one character matched 134,834 names and 7.5 MB, as wide as get_all_classes itself. Nothing is lost by refusing it -- the shortest class name measured there is 5 characters, so one can never be a name. To enumerate a subtree, use get_all_classes with a packagePrefix.";
pub const EMPTY_METHOD_SEARCH_COST: &str = "every method in the APK -- very many of them and 58.9 MB on a 141,461-class target, because every name contains the empty string.";
pub const ONE_CHAR_METHOD_SEARCH_COST: &str = "a large fraction of the APK: one character measured 26.5 MB on a 141,461-class target.";
pub const METHOD_SEARCH_FLOOR_REASON: &str = " Nothing is lost by refusing it: loadApk deobfuscates with a minimum name length of 2, so no method alias is 1 character.";

pub fn marker(prefix: &str, text: &str) -> String {
    format!("{}: {}", prefix, text)
}

pub fn truncation_text(shown: usize, total: usize, unit: &str, advice: &str) -> String {
    format!("showing {} of {} {}. {}", shown, total, unit, advice)
}

pub fn json_char_cost(c: char) -> i64 {
    let u = c as u32;
    if u < 0x20 {
        if c == '\x08' || c == '\t' || c == '\n' || c == '\x0c' || c == '\r' {
            2
        } else {
            6
        }
    } else if c == '"' || c == '\\' {
        2
    } else if u < 0x80 {
        1
    } else if u < 0x800 {
        2
    } else if u >= 0x10000 {
        4
    } else {
        3
    }
}

pub fn json_cost(text: &str) -> i64 {
    text.chars().map(json_char_cost).sum()
}

pub fn json_bytes_strings(names: &[String]) -> i64 {
    names.iter().map(|s| json_cost(s) + 3).sum()
}

pub fn json_cost_of_value(val: &Value) -> i64 {
    match val {
        Value::Null => 5,
        Value::Bool(b) => {
            if *b {
                5
            } else {
                6
            }
        }
        Value::Number(n) => n.to_string().len() as i64 + 1,
        Value::String(s) => json_cost(s) + 3,
        Value::Array(arr) => {
            if arr.is_empty() {
                3
            } else {
                2 + arr.iter().map(json_cost_of_value).sum::<i64>()
            }
        }
        Value::Object(map) => {
            if map.is_empty() {
                3
            } else {
                let mut bytes = 2i64;
                for (k, v) in map {
                    bytes += json_cost(k) + 3;
                    bytes += json_cost_of_value(v);
                }
                bytes
            }
        }
    }
}

pub fn ref_bytes(entries: &[Map<String, Value>]) -> i64 {
    entries
        .iter()
        .map(|m| json_cost_of_value(&Value::Object(m.clone())))
        .sum()
}

pub fn oversized_notice(
    tool: &str,
    count: i64,
    unit: &str,
    bytes: i64,
    scope: &str,
    advice: &str,
) -> Option<String> {
    if bytes < OVERSIZED_RESPONSE_BYTES {
        return None;
    }
    let text = format!(
        "{} returned {} {} ({} MB of JSON, {}). That is a file dump, not a lookup: {}",
        tool,
        count,
        unit,
        bytes / (1024 * 1024),
        scope,
        advice
    );
    Some(marker(OVERSIZED_MARKER_PREFIX, &text))
}

pub fn guarded_names(
    all: Vec<String>,
    limit: i32,
    tool: &str,
    unit: &str,
    scope: &str,
    advice: &str,
) -> Vec<String> {
    let lim = if limit > 0 { limit as usize } else { 0 };
    if lim > 0 && all.len() > lim {
        let total = all.len();
        let mut capped: Vec<String> = all.into_iter().take(lim).collect();
        let full_advice = format!("{} {}", RAISE_LIMIT, advice);
        capped.push(marker(
            TRUNCATION_MARKER_PREFIX,
            &truncation_text(lim, total, unit, &full_advice),
        ));
        if let Some(cut_notice) = oversized_notice(
            tool,
            lim as i64,
            unit,
            json_bytes_strings(&capped),
            scope,
            advice,
        ) {
            capped.push(cut_notice);
        }
        return capped;
    }
    let bytes = json_bytes_strings(&all);
    if let Some(notice) = oversized_notice(tool, all.len() as i64, unit, bytes, scope, advice) {
        let mut annotated = all;
        annotated.push(notice);
        return annotated;
    }
    all
}

pub fn capped_names(all: Vec<String>, limit: i32, unit: &str, advice: &str) -> Vec<String> {
    if limit <= 0 || all.len() <= limit as usize {
        return all;
    }
    let lim = limit as usize;
    let total = all.len();
    let mut capped: Vec<String> = all.into_iter().take(lim).collect();
    capped.push(marker(
        TRUNCATION_MARKER_PREFIX,
        &truncation_text(lim, total, unit, advice),
    ));
    capped
}

pub fn guarded_refs(
    all: Vec<Map<String, Value>>,
    limit: i32,
    tool: &str,
    unit: &str,
    scope: &str,
    advice: &str,
) -> Vec<Map<String, Value>> {
    let lim = if limit > 0 { limit as usize } else { 0 };
    if lim > 0 && all.len() > lim {
        let total = all.len();
        let mut capped: Vec<Map<String, Value>> = all.into_iter().take(lim).collect();
        let full_advice = format!("{} {}", RAISE_LIMIT, advice);
        let mut trunc_entry = Map::new();
        trunc_entry.insert(
            TRUNCATION_MARKER_PREFIX.to_string(),
            Value::String(marker(
                TRUNCATION_MARKER_PREFIX,
                &truncation_text(lim, total, unit, &full_advice),
            )),
        );
        capped.push(trunc_entry);
        if let Some(cut_notice) =
            oversized_notice(tool, lim as i64, unit, ref_bytes(&capped), scope, advice)
        {
            let mut over_entry = Map::new();
            over_entry.insert(OVERSIZED_MARKER_PREFIX.to_string(), Value::String(cut_notice));
            capped.push(over_entry);
        }
        return capped;
    }
    let bytes = ref_bytes(&all);
    if let Some(notice) = oversized_notice(tool, all.len() as i64, unit, bytes, scope, advice) {
        let mut annotated = all;
        let mut over_entry = Map::new();
        over_entry.insert(OVERSIZED_MARKER_PREFIX.to_string(), Value::String(notice));
        annotated.push(over_entry);
        return annotated;
    }
    all
}

pub fn whole_response_notice(
    result: &mut Map<String, Value>,
    tool: &str,
    count: i64,
    unit: &str,
    scope: &str,
    advice: &str,
) {
    if result.contains_key(OVERSIZED_MARKER_PREFIX) {
        return;
    }
    let bytes = json_cost_of_value(&Value::Object(result.clone()));
    if let Some(notice) = oversized_notice(tool, count, unit, bytes, scope, advice) {
        result.insert(
            OVERSIZED_MARKER_PREFIX.to_string(),
            Value::Array(vec![Value::String(notice)]),
        );
    }
}

pub fn text_truncation_marker(
    tool: &str,
    budget: i32,
    total: &str,
    scope: &str,
    advice: &str,
) -> String {
    format!(
        "{}\n\n",
        marker(
            TRUNCATION_MARKER_PREFIX,
            &format!(
                "{} cut {} to maxBytes={} (full size: {}). {} Pass maxBytes 0 for the whole thing.",
                tool, scope, budget, total, advice
            )
        )
    )
}

pub fn budget_left_after(notice: &str, max_bytes: i32) -> i64 {
    (max_bytes as i64 - json_cost(notice)).max(0)
}

pub fn cut_to_json_budget(text: &str, budget: i64) -> String {
    let mut cost = 0i64;
    let mut end_byte = text.len();
    for (idx, ch) in text.char_indices() {
        cost += json_char_cost(ch);
        if cost > budget {
            end_byte = idx;
            break;
        }
    }
    text[..end_byte].to_string()
}

pub fn with_oversized_notice(
    text: String,
    cost: i64,
    tool: &str,
    count: i64,
    unit: &str,
    scope: &str,
    advice: &str,
) -> String {
    if let Some(notice) = oversized_notice(tool, count, unit, cost, scope, advice) {
        format!("{}\n\n{}", notice, text)
    } else {
        text
    }
}

pub fn guarded_text(
    text: String,
    max_bytes: i32,
    tool: &str,
    scope: &str,
    advice: &str,
) -> String {
    let cost = json_cost(&text);
    let char_count = text.chars().count();
    if max_bytes > 0 && cost > max_bytes as i64 {
        let notice = text_truncation_marker(
            tool,
            max_bytes,
            &format!("{} characters", char_count),
            scope,
            advice,
        );
        let left = budget_left_after(&notice, max_bytes);
        return format!("{}{}", notice, cut_to_json_budget(&text, left));
    }
    with_oversized_notice(
        text,
        cost,
        tool,
        char_count as i64,
        "characters",
        scope,
        advice,
    )
}

pub fn short_query_rejection(param: &str, query: Option<&str>, cost: &str) -> Option<String> {
    let q = query.unwrap_or("");
    if q.trim().chars().count() >= MIN_QUERY_LENGTH {
        return None;
    }
    Some(marker(
        REJECTED_MARKER_PREFIX,
        &format!(
            "{} \"{}\" is shorter than {} characters, and this search matches on substring rather than on the whole name -- so it asks for {} Pass at least {} characters.",
            param, q, MIN_QUERY_LENGTH, cost, MIN_QUERY_LENGTH
        ),
    ))
}
