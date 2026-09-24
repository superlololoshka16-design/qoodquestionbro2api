use std::io::Write as _;

pub struct WireMsg {
    pub role: String,
    pub text: String,
}

fn json_escape_into(raw: &[u8], out: &mut Vec<u8>) {
    for &c in raw {
        match c {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            c if c < 0x20 => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.extend_from_slice(b"\\u00");
                out.push(HEX[(c >> 4) as usize]);
                out.push(HEX[(c & 0xf) as usize]);
            }
            c => out.push(c),
        }
    }
}

pub struct BodySpec<'a> {
    pub model: &'a str,
    pub reasoning: &'a str,
    pub msgs: &'a [WireMsg],
    pub window_id: [u8; 36],
}

fn messages_json(msgs: &[WireMsg], window_id: &[u8; 36], j: &mut Vec<u8>) {
    j.push(b'[');
    let mut first = true;
    for m in msgs {
        if !first {
            j.push(b',');
        }
        first = false;
        if m.role == "user" {
            j.extend_from_slice(b"{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"");
            json_escape_into(m.text.as_bytes(), j);
            j.extend_from_slice(b"\"}],\"windowID\":\"");
        } else {
            j.extend_from_slice(b"{\"role\":\"");
            j.extend_from_slice(m.role.as_bytes());
            j.extend_from_slice(b"\",\"content\":\"\",\"parts\":[{\"type\":\"text\",\"text\":\"");
            json_escape_into(m.text.as_bytes(), j);
            j.extend_from_slice(b"\"}],\"windowID\":\"");
        }
        j.extend_from_slice(window_id);
        j.push(b'"');
        j.push(b'}');
    }
    j.push(b']');
}

pub fn duck_body(spec: &BodySpec) -> Vec<u8> {
    let mut j: Vec<u8> = Vec::with_capacity(2048);
    j.extend_from_slice(b"{\"model\":\"");
    j.extend_from_slice(spec.model.as_bytes());
    j.extend_from_slice(b"\",\"metadata\":{\"toolChoice\":{\"NewsSearch\":false,\"VideosSearch\":false,\"LocalSearch\":false,\"WeatherForecast\":false}},\"messages\":");
    messages_json(spec.msgs, &spec.window_id, &mut j);
    j.extend_from_slice(b",\"canUseTools\":true,\"reasoningEffort\":\"");
    j.extend_from_slice(spec.reasoning.as_bytes());
    j.extend_from_slice(b"\",\"canUseApproxLocation\":null,\"canDelegateImageGeneration\":false,\"canUseWebSearch\":false,\"canUploadFiles\":false,\"canShowGreeting\":false}");
    j
}

#[derive(Debug, PartialEq)]
pub enum Ev<'a> {
    Part(&'a str),
    Reasoning(&'a str),
    Done,
}

pub fn parse_ddg_frame<'s>(line: &'s [u8], scratch: &'s mut Vec<u8>) -> Option<Ev<'s>> {
    if line == b"[DONE]" || line.is_empty() {
        return Some(Ev::Done);
    }
    if line.first() == Some(&b'[') {
        return None;
    }
    if let Some((s, e)) = json_str_field(line, b"message") {
        scratch.clear();
        json_unescape_into(&line[s..e], scratch);
        if scratch.is_empty() {
            return None;
        }
        let text = std::str::from_utf8(scratch).ok()?;
        return Some(Ev::Part(text));
    }
    if json_str_field(line, b"role").map(|(s, e)| &line[s..e]) == Some(b"reasoning") {
        let (s, e) = json_str_field(line, b"text")?;
        scratch.clear();
        json_unescape_into(&line[s..e], scratch);
        if scratch.is_empty() {
            return None;
        }
        let text = std::str::from_utf8(scratch).ok()?;
        return Some(Ev::Reasoning(text));
    }
    None
}

fn json_str_field(line: &[u8], key: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0usize;
    let mut in_str = false;
    while i < line.len() {
        let c = line[i];
        if in_str {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c == b'"' {
            let after = i + 1;
            if line.len() > after + key.len()
                && &line[after..after + key.len()] == key
                && line[after + key.len()] == b'"'
            {
                let mut j = after + key.len() + 1;
                while j < line.len() && matches!(line[j], b' ' | b'\t') {
                    j += 1;
                }
                if j < line.len() && line[j] == b':' {
                    j += 1;
                    while j < line.len() && matches!(line[j], b' ' | b'\t') {
                        j += 1;
                    }
                    if j < line.len() && line[j] == b'"' {
                        let start = j + 1;
                        let mut k = start;
                        while k < line.len() {
                            if line[k] == b'\\' {
                                k += 2;
                                continue;
                            }
                            if line[k] == b'"' {
                                return Some((start, k));
                            }
                            k += 1;
                        }
                    }
                }
            }
            in_str = true;
            i = after;
            continue;
        }
        i += 1;
    }
    None
}

fn json_unescape_into(raw: &[u8], out: &mut Vec<u8>) {
    let mut i = 0usize;
    let mut buf4 = [0u8; 4];
    while i < raw.len() {
        let c = raw[i];
        if c != b'\\' {
            out.push(c);
            i += 1;
            continue;
        }
        i += 1;
        match raw.get(i) {
            Some(b'"') => out.push(b'"'),
            Some(b'\\') => out.push(b'\\'),
            Some(b'/') => out.push(b'/'),
            Some(b'b') => out.push(0x08),
            Some(b'f') => out.push(0x0c),
            Some(b'n') => out.push(b'\n'),
            Some(b'r') => out.push(b'\r'),
            Some(b't') => out.push(b'\t'),
            Some(b'u') => {
                let hex4 = |p: usize| -> u16 {
                    let mut v: u16 = 0;
                    for q in 0..4 {
                        let d = raw.get(p + q).map(|&b| match b {
                            b'0'..=b'9' => b - b'0',
                            b'a'..=b'f' => b - b'a' + 10,
                            b'A'..=b'F' => b - b'A' + 10,
                            _ => 0xff,
                        });
                        v = (v << 4) | u16::from(d.unwrap_or(0xff));
                    }
                    v
                };
                let cp = hex4(i + 1);
                let ch = match cp {
                    0xd800..=0xdbff => {
                        if raw.get(i + 5) == Some(&b'\\') && raw.get(i + 6) == Some(&b'u') {
                            let lo = hex4(i + 7);
                            if (0xdc00..=0xdfff).contains(&lo) {
                                let c = 0x10000 + ((u32::from(cp) - 0xd800) << 10) + (u32::from(lo) - 0xdc00);
                                i += 10;
                                char::from_u32(c).unwrap_or(char::REPLACEMENT_CHARACTER)
                            } else {
                                char::REPLACEMENT_CHARACTER
                            }
                        } else {
                            char::REPLACEMENT_CHARACTER
                        }
                    }
                    0xdc00..=0xdfff => char::REPLACEMENT_CHARACTER,
                    _ => char::from_u32(u32::from(cp)).unwrap_or(char::REPLACEMENT_CHARACTER),
                };
                out.extend_from_slice(ch.encode_utf8(&mut buf4).as_bytes());
                i += 5;
                continue;
            }
            _ => out.push(b'\\'),
        }
        i += 1;
    }
}

pub fn strip_inline_markers(s: &str, out: &mut String) {
    let mut rest = s;
    out.clear();
    while let Some(start) = rest.find('[') {
        out.push_str(&rest[..start]);
        let after = &rest[start..];
        match after.find(']') {
            Some(end) => {
                let tag = &after[1..end];
                let known = tag == "ADS"
                    || tag.starts_with("LIMIT_")
                    || tag.starts_with("STOP_REASON")
                    || tag.starts_with("CHAT_TITLE");
                if !known {
                    out.push('[');
                    out.push_str(tag);
                    out.push(']');
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(after);
                return;
            }
        }
    }
    out.push_str(rest);
}

pub fn write_flushed(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(text.as_bytes());
    let _ = out.flush();
}
