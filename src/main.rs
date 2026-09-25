use std::io::Read as _;

use duckkit::session;
use duckkit::solver::{self, Facts};
use duckkit::{net, wire};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("deob") => cmd_deob(&args[1..]),
        Some("solve") => cmd_solve(&args[1..]),
        Some("batch") => cmd_batch(&args[1..]),
        Some("facts") => cmd_facts(&args[1..]),
        Some("live") => cmd_live(&args[1..]),
        Some("chat") => cmd_chat(&args[1..]),
        Some("help") | None => usage(),
        other => {
            eprintln!("неизвестная команда {other:?}");
            usage()
        }
    };
    std::process::exit(code);
}

fn usage() -> i32 {
    eprintln!(
        "duckkit 13 — деобфускация+снапшот (oxc→dataflow→egg), wreq-транспорт\n\
         deob <file.js>               полная деобфускация: строки+ротация+константы, читаемый JS\n\
         solve <file.js> [--ua UA]   решить челлендж из файла (пайплайн синхронно)\n\
         batch [dir]                 все фикстуры, таблица значений\n\
         live [--proxy P] \"текст\"    живой E2E: boot→челлендж→compile→chat через сеть\n\
         chat [--out F] [--proxy P]  живая сессия: сообщения подряд, куки в клиенте,\n\
                                     история копится, ответы пишутся в JSONL (chat.jsonl)"
    );
    0
}


fn cmd_deob(rest: &[String]) -> i32 {
    let Some(path) = rest.iter().find(|a| !a.starts_with("--")) else {
        eprintln!("deob: нужен путь к файлу");
        return 2;
    };
    let Some(js) = read_file(path) else {
        eprintln!("deob: не читается {path}");
        return 1;
    };
    match duckkit::pipeline::deob::run(&js) {
        Ok(out) => {
            println!("{out}");
            0
        }
        Err(e) => {
            eprintln!("deob: {e}");
            1
        }
    }
}
fn flag(rest: &[String], name: &str) -> Option<String> {
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        if a == name {
            return it.next().cloned();
        }
    }
    None
}

const DEFAULT_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

fn read_file(path: &str) -> Option<Vec<u8>> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).ok()?;
    Some(buf)
}

fn solve_file(path: &str, ua: &str) -> Result<String, String> {
    let js = read_file(path).ok_or_else(|| format!("не читается {path}"))?;
    let src = std::str::from_utf8(&js).map_err(|_| "не UTF-8".to_string())?;
    let facts = Facts::fixture();
    solver::token(src, ua, &facts, 23).map_err(|e| e.to_string())
}

fn cmd_solve(rest: &[String]) -> i32 {
    let Some(path) = rest.iter().find(|a| !a.starts_with("--")) else {
        eprintln!("solve: нужен путь к файлу");
        return 2;
    };
    let ua = flag(rest, "--ua").unwrap_or_else(|| DEFAULT_UA.into());
    match solve_file(path, &ua) {
        Ok(token) => {
            println!("== {path}");
            println!("  token={token}");
            0
        }
        Err(e) => {
            eprintln!("solve: {e}");
            1
        }
    }
}

fn cmd_batch(rest: &[String]) -> i32 {
    let dir = flag(rest, "--dir").unwrap_or_else(|| "fixtures".into());
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .ok()
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "js"))
                .collect()
        })
        .unwrap_or_default();
    entries.sort();
    if entries.is_empty() {
        eprintln!("batch: нет .js в {dir}");
        return 1;
    }
    let mut fails = 0;
    for p in &entries {
        let path = p.to_string_lossy();
        match solve_file(&path, DEFAULT_UA) {
            Ok(token) => {
                let head = &token[..token.len().min(48)];
                println!("{path}: {head}…");
            }
            Err(e) => {
                eprintln!("!! {path}: {e}");
                fails += 1;
            }
        }
    }
    if fails > 0 {
        eprintln!("batch: {fails} ошибок");
        return 1;
    }
    0
}

fn cmd_facts(rest: &[String]) -> i32 {
    let Some(path) = rest.iter().find(|a| !a.starts_with("--")) else {
        eprintln!("facts: нужен путь к бандлу entry.duckai.*.js");
        return 2;
    };
    let Some(js) = read_file(path) else {
        eprintln!("facts: не читается {path}");
        return 1;
    };
    let src = match std::str::from_utf8(&js) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("facts: не UTF-8");
            return 1;
        }
    };
    let Some(benv) = duckkit::pipeline::analyze_bundle(src) else {
        eprintln!("facts: бандл не парсится oxc");
        return 1;
    };
    println!("timing.timeout_ms        = {}", benv.timing.timeout_ms);
    println!("timing.duration_delta    = {}", benv.timing.duration_delta);
    println!("timing.macrotask_zero    = {}", benv.timing.macrotask_zero);
    println!("fe_version_ok            = {}", benv.fe_version_ok);
    println!("dc_* events              = {}", benv.signal_events.len());
    for (attr, val) in &benv.verify_attrs {
        println!("verify.attr              = {attr}={val:?}");
    }
    for g in &benv.verify_globals {
        println!("verify.global            = {g}");
    }
    if let Some(st) = &benv.stack {
        println!("stack.fname              = {}", st.fname);
        println!("stack.line               = {}", st.line);
        println!("stack.col_error          = {}", st.col_error);
        println!("stack.col_race           = {}", st.col_race);
    } else {
        println!("stack                    = <не найден>");
        return 1;
    }
    0
}

fn cmd_live(rest: &[String]) -> i32 {
    let prompt: String = rest
        .iter()
        .filter(|a| !a.starts_with("--"))
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    if prompt.is_empty() {
        eprintln!("live: нужен текст сообщения");
        return 2;
    }
    let proxy = flag(rest, "--proxy");
    let mut sess = match session::Session::boot(proxy) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("live boot: {e}");
            return 1;
        }
    };
    eprintln!(
        "[duckkit] timing: timeout={}ms duration_delta={} macrotask={}",
        sess.timing_facts().timeout_ms,
        sess.timing_facts().duration_delta,
        sess.timing_facts().macrotask_zero
    );
    let model = flag(rest, "--model").unwrap_or_else(|| sess.default_model.clone());
    let mut window_id = [0u8; 36];
    if net::uuid_v4(&mut window_id).is_err() {
        eprintln!("live: urandom недоступен");
        return 1;
    }
    let msgs = vec![wire::WireMsg { role: "user".into(), text: prompt }];
    let body = wire::duck_body(&wire::BodySpec { model: &model, reasoning: "none", msgs: &msgs, window_id });

    eprintln!("[duckkit] model={model}");
    let mut answer = String::new();
    let mut res = run_chat(&mut sess, &body, &mut answer);
    if matches!(res, session::ChatOutcome::Challenge) {
        answer.clear();
        res = run_chat(&mut sess, &body, &mut answer);
    }
    match res {
        session::ChatOutcome::Ok => {
            let mut clean = String::with_capacity(answer.len());
            wire::strip_inline_markers(&answer, &mut clean);
            eprintln!();
            println!("{clean}");
            eprintln!();
            0
        }
        session::ChatOutcome::Challenge => {
            eprintln!("\nlive: челлендж обновлён — повторите запрос");
            1
        }
        session::ChatOutcome::Err(e) => {
            eprintln!("\nlive: {e}");
            1
        }
    }
}

fn run_chat(sess: &mut session::Session, body: &[u8], answer: &mut String) -> session::ChatOutcome {
    sess.chat(body, &mut |ev| match ev {
        wire::Ev::Part(p) => {
            answer.push_str(p);
            wire::write_flushed(p);
        }
        wire::Ev::Reasoning(r) => {
            eprint!("\x1b[2m{r}\x1b[0m");
        }
        wire::Ev::Done => {}
    })
}

fn json_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

fn log_line(path: &str, role: &str, text: &str) {
    use std::io::Write as _;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let _ = writeln!(f, "{{\"ts\":{ts},\"role\":\"{role}\",\"text\":\"{}\"}}", json_escape(text));
    }
}

// Живая сессия: куки в wreq-клиенте, история копится, ответы в JSONL,
// сообщения подряд без boot на каждое. Ответ модели < 1с после решённого jsa.
fn cmd_chat(rest: &[String]) -> i32 {
    let out = flag(rest, "--out").unwrap_or_else(|| "chat.jsonl".into());
    let proxy = flag(rest, "--proxy");
    let mut sess = match session::Session::boot(proxy) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("chat boot: {e}");
            return 1;
        }
    };
    let model = flag(rest, "--model").unwrap_or_else(|| sess.default_model.clone());
    eprintln!("[duckkit] chat: model={model} log={out} — пиши сообщения, пустая строка = выход");

    let mut history: Vec<wire::WireMsg> = Vec::new();
    let mut window_id = [0u8; 36];
    let _ = net::uuid_v4(&mut window_id);
    let stdin = std::io::stdin();
    let mut line = String::new();
    loop {
        line.clear();
        eprint!("> ");
        let _ = std::io::Write::flush(&mut std::io::stderr());
        match stdin.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                eprintln!("stdin: {e}");
                break;
            }
        }
        let text = line.trim();
        if text.is_empty() {
            break;
        }
        log_line(&out, "user", text);
        history.push(wire::WireMsg { role: "user".into(), text: text.into() });
        let body = wire::duck_body(&wire::BodySpec { model: &model, reasoning: "none", msgs: &history, window_id });
        let mut answer = String::new();
        let mut res = run_chat(&mut sess, &body, &mut answer);
        if matches!(res, session::ChatOutcome::Challenge) {
            answer.clear();
            res = run_chat(&mut sess, &body, &mut answer);
        }
        eprintln!();
        match res {
            session::ChatOutcome::Ok => {
                let mut clean = String::with_capacity(answer.len());
                wire::strip_inline_markers(&answer, &mut clean);
                println!("{clean}");
                log_line(&out, "assistant", &clean);
                history.push(wire::WireMsg { role: "assistant".into(), text: clean });
            }
            session::ChatOutcome::Challenge => eprintln!("chat: челлендж обновлён — повтори сообщение"),
            session::ChatOutcome::Err(e) => {
                log_line(&out, "error", &e);
                eprintln!("chat: {e}");
            }
        }
    }
    0
}
