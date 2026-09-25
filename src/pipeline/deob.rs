use crate::pipeline::flow;

pub fn run(js: &[u8]) -> Result<String, flow::FlowErr> {
    let src = std::str::from_utf8(js).map_err(|_| flow::FlowErr::Parse("не UTF-8".into()))?;
    let m = flow::run(src, &[], &[])?;
    let mut out = String::with_capacity(8192);
    out.push_str("// duckkit 13 — деобфускация (oxc → const-prop → slice → egg)\n");
    out.push_str(&format!(
        "// family={} template={:016x} ops={}/{} rotation={} ({}) target={}\n",
        m.egg.family,
        m.egg.template_hash,
        m.egg.canonical_ops,
        m.egg.raw_ops,
        m.rotation,
        if m.rotate_left { "left" } else { "right" },
        m.target
    ));
    out.push_str(&format!("// canonical: {}\n\n", m.egg.canonical_sexpr));

    out.push_str(&format!("const STRINGS = {:?};\n", m.strings));
    out.push_str(&format!("const key = {:?};\n", m.key));
    out.push_str(&format!("const challenge_id = {:?};\n", m.challenge_id));
    out.push_str(&format!("const timestamp = {:?};\n", m.timestamp));
    out.push_str(&format!("const server_hashes = {:?};\n\n", m.server_hashes));

    out.push_str("// чтения проб (что именно дёргает каждая проба Promise.all):\n");
    for (i, p) in m.probes.iter().enumerate() {
        out.push_str(&format!("// probe[{i}] base={:?} value={:?}\n", p.base, p.value));
        for r in &p.reads {
            match r {
                flow::Read::NavUa => out.push_str("//   navigator.userAgent -> <символ UA>\n"),
                flow::Read::Env { desc } => {
                    out.push_str(&format!("//   {desc}\n"));
                }
            }
        }
    }
    out.push('\n');

    out.push_str("// полное деобфусцированное тело (строки подставлены, константы свёрнуты):\n");
    for s in &m.body {
        flow::render_stmt(s, &mut out, 0);
    }
    Ok(out)
}
