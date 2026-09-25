use crate::core::{b64, jsnum, sha};
use crate::pipeline::{flow, Timing, StackFacts};

pub struct Facts {
    pub stack: StackFacts,
    pub timing: Timing,
    pub origin: &'static str,
    pub bundle_url: String,
    // Факты верификации из AST бандла: jsa-чеки сверяют литералы челленджа
    // с ними (точное сравнение, ноль угадывания).
    pub verify_attrs: Vec<(Box<str>, Box<str>)>,
    pub verify_globals: Vec<Box<str>>,
}

impl Facts {
    pub fn fixture() -> Facts {
        Facts {
            stack: StackFacts { fname: "l".into(), line: 1, col_error: 5, col_race: 17 },
            timing: Timing { timeout_ms: 500, duration_delta: 0, macrotask_zero: true },
            origin: "https://duck.ai",
            bundle_url: "https://duck.ai/dist/duckai-dist/entry.duckai.c51e9bb9ebdb169571b0.js".into(),
            verify_attrs: Vec::new(),
            verify_globals: Vec::new(),
        }
    }
}

fn esc(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
}

fn xor_debug(sigs: &[(&str, &str)], key: &str, out: &mut String) {
    let ku: Vec<u16> = key.encode_utf16().collect();
    let mut json = String::from("{");
    for (i, (n, v)) in sigs.iter().enumerate() {
        if i > 0 { json.push(','); }
        json.push('"'); esc(n, &mut json); json.push_str("\":\""); esc(v, &mut json); json.push('"');
    }
    json.push('}');
    for (i, u) in json.encode_utf16().enumerate() {
        let x = u ^ ku[i % ku.len()];
        if x == 0x22 || x == 0x5c || x < 0x20 {
            out.push_str(&format!("\\u{:04x}", x));
        } else {
            out.push(char::from_u32(u32::from(x)).unwrap_or(char::REPLACEMENT_CHARACTER));
        }
    }
}

pub fn token(js: &str, ua: &str, facts: &Facts, duration: u64) -> Result<String, flow::FlowErr> {
    let m = flow::run(js, &facts.verify_attrs, &facts.verify_globals)?;
    let mut p = String::with_capacity(768);
    p.push_str("{\"server_hashes\":[");
    for (i, h) in m.server_hashes.iter().enumerate() {
        if i > 0 { p.push(','); }
        p.push('"'); esc(h, &mut p); p.push('"');
    }
    p.push_str("],\"client_hashes\":[\"");
    p.push_str(&sha::sha256_b64(ua.as_bytes()));
    p.push('"');
    for probe in &m.probes {
        let v = probe
            .value
            .ok_or_else(|| flow::FlowErr::Read("проба не решается структурно".into()))?;
        p.push_str(",\"");
        let num = jsnum::format_js_num(v);
        p.push_str(&sha::sha256_b64(num.as_bytes()));
        p.push('"');
    }
    p.push_str("],\"signals\":{},\"meta\":{\"v\":\"");
    p.push_str(&m.v);
    p.push_str("\",\"challenge_id\":\"");
    p.push_str(&m.challenge_id);
    p.push_str("\",\"timestamp\":\"");
    p.push_str(&m.timestamp);
    p.push_str("\",\"debug\":\"");
    xor_debug(&[], &m.key, &mut p);
    p.push_str("\",\"origin\":\"");
    p.push_str(facts.origin);
    p.push_str("\",\"stack\":\"Error\\n    at ");
    p.push_str(&facts.stack.fname);
    p.push_str(" (");
    p.push_str(&facts.bundle_url);
    p.push(':');
    p.push_str(&facts.stack.line.to_string());
    p.push(':');
    p.push_str(&facts.stack.col_error.to_string());
    p.push_str(")\\n    at async ");
    p.push_str(&facts.bundle_url);
    p.push(':');
    p.push_str(&facts.stack.line.to_string());
    p.push(':');
    p.push_str(&facts.stack.col_race.to_string());
    p.push_str("\",\"duration\":\"");
    p.push_str(&duration.to_string());
    p.push_str("\"}}");
    Ok(b64::encode_string(p.as_bytes()))
}

pub fn seed_rng() -> u64 {
    crate::core::rng::seed()
}

pub fn sample_u64(rng: &mut u64, span: u64) -> u64 {
    if span == 0 {
        return 0;
    }
    let mut x = *rng;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *rng = x;
    x % span
}
