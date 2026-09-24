#[inline(always)]
pub fn to_int32(x: f64) -> i32 {
    let m = x.trunc();
    if !m.is_finite() || m == 0.0 {
        return 0;
    }
    let m32 = m.rem_euclid(4_294_967_296.0);
    if m32 >= 2_147_483_648.0 {
        (m32 - 4_294_967_296.0) as i32
    } else {
        m32 as i32
    }
}

#[inline(always)]
pub fn to_uint32(x: f64) -> u32 {
    let m = x.trunc();
    if !m.is_finite() || m == 0.0 {
        return 0;
    }
    m.rem_euclid(4_294_967_296.0) as u32
}

#[inline]
fn is_js_ws(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\x0b' | '\x0c' | '\r' | ' ' | '\u{85}' | '\u{a0}' | '\u{1680}'
        | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}'
        | '\u{feff}')
}

pub fn js_parse_int(s: &str) -> f64 {
    js_parse_int_radix(s, 0)
}

pub fn js_parse_int_radix(s: &str, radix: u32) -> f64 {
    let t = s.trim_matches(is_js_ws);
    let b = t.as_bytes();
    let mut i = 0usize;
    let mut neg = false;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        neg = b[i] == b'-';
        i += 1;
    }
    let mut r = if radix == 0 { 10 } else { radix };
    if (r == 16 || radix == 0)
        && i + 1 < b.len()
        && b[i] == b'0'
        && (b[i + 1] | 0x20) == b'x'
        && i + 2 < b.len()
        && b[i + 2].is_ascii_hexdigit()
    {
        i += 2;
        r = 16;
    }
    let start = i;
    let mut acc = 0f64;
    while i < b.len() {
        let d = match b[i] {
            b'0'..=b'9' => (b[i] - b'0') as u32,
            b'a'..=b'f' if r == 16 => (b[i] - b'a' + 10) as u32,
            b'A'..=b'F' if r == 16 => (b[i] - b'A' + 10) as u32,
            _ => break,
        };
        if d >= r {
            break;
        }
        acc = acc * f64::from(r) + f64::from(d);
        i += 1;
    }
    if i == start {
        return f64::NAN;
    }
    if neg {
        -acc
    } else {
        acc
    }
}

pub fn format_js_num(v: f64) -> String {
    if v.is_nan() {
        "NaN".into()
    } else if v.is_infinite() {
        if v > 0.0 { "Infinity".into() } else { "-Infinity".into() }
    } else if v.fract() == 0.0 && v.abs() < 1e21 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

pub fn json_escape_into(raw: &[u8], out: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in raw {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            0x00..=0x1f => {
                out.extend_from_slice(b"\\u00");
                out.push(HEX[(b >> 4) as usize]);
                out.push(HEX[(b & 0x0f) as usize]);
            }
            _ => out.push(b),
        }
    }
}
