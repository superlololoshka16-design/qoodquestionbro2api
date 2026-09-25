use std::io::Write as _;
use std::sync::Arc;

use crate::pipeline::{analyze_bundle_cached, StackFacts, Timing};
use crate::solver::{self, Facts};

use crate::err::{Err, Net};
use crate::net::{self, Http};
use crate::wire::{self, Ev};

pub struct Session {
    pub http: Http,
    pub ua: String,
    pub fe_version: String,
    pub bundle_url: String,
    pub facts: Arc<Facts>,
    pub signal_events: Vec<Box<str>>,
    pub default_model: String,
    jsa: Option<String>,
    pending: Option<Vec<u8>>,
    signals_start: u64,
    pending_events: Vec<(Box<str>, u64)>,
    scratch: Vec<u8>,
    rng: u64,
    journey: String,
    facts_reboots: u32,
}

pub enum ChatOutcome {
    Ok,
    Challenge,
    Err(String),
}

fn find_default_model(models_json: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(models_json).ok()?;
    let mut best: Option<String> = None;
    let mut rest = s;
    while let Some(p) = rest.find('{') {
        rest = &rest[p..];
        let Some(end) = rest.find('}') else { break };
        let obj = &rest[..end];
        rest = &rest[end..];
        let id = obj
            .find("\"id\":\"")
            .map(|i| &obj[i + 6..])
            .and_then(|r| r.split('"').next())
            .unwrap_or("");
        if id.is_empty() {
            continue;
        }
        let free = obj.contains("\"free\"");
        let has_efforts = obj.contains("supportedReasoningEffort");
        if free && has_efforts {
            return Some(id.to_string());
        }
        if best.is_none() && has_efforts {
            best = Some(id.to_string());
        }
    }
    best
}

fn bundle_facts(page: &net::Page, bundle_js: &[u8]) -> Result<(StackFacts, Timing, Vec<Box<str>>, String, Vec<(Box<str>, Box<str>)>, Vec<Box<str>>), Err> {
    let bsrc = std::str::from_utf8(bundle_js).map_err(|_| Err::Metric("бандл не UTF-8".into()))?;
    let benv = analyze_bundle_cached(bsrc).ok_or(Err::Metric("бандл не парсится oxc".into()))?;
    let stack = benv.stack.ok_or(Err::Metric("стек не извлечён из бандла".into()))?;
    if benv.timing.timeout_ms == 0 {
        return Err(Err::Metric("таймаут гонки jsa не найден в бандле".into()));
    }
    let bundle_url = format!("https://duck.ai/dist/duckai-dist/entry.duckai.{}.js", page.entry_bundle);
    Ok((stack, benv.timing, benv.signal_events, bundle_url, benv.verify_attrs, benv.verify_globals))
}

impl Session {
    pub fn boot(proxy: Option<String>) -> Result<Session, Err> {
        let http = Http::new(proxy)?;
        let page = http.page()?;
        let bundle_js = http.bundle(&page.entry_bundle)?;
        let (stack, timing, signal_events, bundle_url, verify_attrs, verify_globals) = bundle_facts(&page, &bundle_js)?;
        let facts = Arc::new(Facts { stack, timing, origin: "https://duck.ai", bundle_url: bundle_url.clone(), verify_attrs, verify_globals });
        let mut journey_buf = [0u8; 32];
        net::journey_hex(&mut journey_buf)?;
        let journey = String::from_utf8_lossy(&journey_buf).into_owned();
        let models_raw = http.models(&journey)?;
        let default_model = find_default_model(&models_raw)
            .ok_or(Err::Session("каталог моделей пуст или не распознан".into()))?;
        let fe_version = page.fe_version();
        let ua = http.ua().to_string();
        let rng = solver::seed_rng();
        let mut s = Session {
            http,
            ua,
            fe_version,
            bundle_url,
            facts,
            signal_events,
            default_model,
            jsa: None,
            pending: None,
            signals_start: net::now_ms(),
            pending_events: Vec::new(),
            scratch: Vec::with_capacity(512),
            rng,
            journey,
            facts_reboots: 0,
        };
        s.seed_page_events();
        s.refresh_jsa()?;
        Ok(s)
    }

    pub fn timing_facts(&self) -> &Timing {
        &self.facts.timing
    }

    pub fn jsa_token(&self) -> Option<&str> {
        self.jsa.as_deref()
    }

    fn seed_page_events(&mut self) {
        if !self.signal_events.iter().any(|e| e.as_ref() == "impression") {
            return;
        }
        let delta = 60 + solver::sample_u64(&mut self.rng, 360);
        self.pending_events.push(("impression".into(), delta));
    }

    fn signals_b64(&mut self) -> String {
        let now = net::now_ms();
        let start = self.signals_start;
        let end = now.saturating_sub(start);
        let mut j = std::mem::take(&mut self.scratch);
        j.clear();
        let _ = write!(j, "{{\"start\":{start},\"events\":[");
        for (i, (name, delta)) in self.pending_events.iter().enumerate() {
            if i > 0 {
                j.push(b',');
            }
            let d = (*delta).min(end);
            let _ = write!(j, "{{\"name\":\"{name}\",\"delta\":{d}}}");
        }
        let _ = write!(j, "],\"end\":{end}}}");
        self.pending_events.clear();
        self.signals_start = now;
        self.scratch = j;
        crate::core::b64::encode_string(&self.scratch)
    }

    fn fetch_challenge(&mut self) -> Result<Vec<u8>, Net> {
        let signals = self.signals_b64();
        let jsa = self.jsa.clone().unwrap_or_else(|| "initial".into());
        let r = self.http.status(&self.journey, &self.fe_version, &signals, &jsa)?;
        if r.status != 200 {
            return Err(Net::Status { ctx: "status", status: r.status });
        }
        net::header_ci(&r.headers, "x-vqd-hash-1")
            .map(|v| v.as_bytes().to_vec())
            .ok_or(Net::RespHeader("x-vqd-hash-1"))
    }

    pub fn refresh_jsa(&mut self) -> Result<(), Err> {
        let b64: Vec<u8> = match self.pending.take() {
            Some(p) => p,
            None => self.fetch_challenge()?,
        };
        let Some(js) = crate::core::b64::decode(&b64) else {
            return Err(Err::Metric("челлендж не декодируется из base64".into()));
        };
        let src = std::str::from_utf8(&js).map_err(|_| Err::Metric("челлендж не UTF-8".into()))?;
        let timeout = self.facts.timing.timeout_ms;
        let dur = 8u64 + solver::sample_u64(&mut self.rng, timeout / 2);
        let t = solver::token(src, &self.ua, &self.facts, dur).map_err(|e| Err::Session(e.to_string()))?;
        self.jsa = Some(t);
        Ok(())
    }

    pub fn reboot_facts(&mut self) -> Result<(), Err> {
        if self.facts_reboots >= 2 {
            return Err(Err::Session("факты бандла пересобраны дважды — дальше бессмысленно".into()));
        }
        self.facts_reboots += 1;
        let page = self.http.page()?;
        let bundle_js = self.http.bundle(&page.entry_bundle)?;
        let (stack, timing, signal_events, bundle_url, verify_attrs, verify_globals) = bundle_facts(&page, &bundle_js)?;
        self.bundle_url = bundle_url.clone();
        self.fe_version = page.fe_version();
        self.facts = Arc::new(Facts { stack, timing, origin: "https://duck.ai", bundle_url, verify_attrs, verify_globals });
        self.signal_events = signal_events;
        eprintln!("[duckkit] факты бандла пересобраны ({})", self.bundle_url);
        Ok(())
    }

    pub fn chat(&mut self, body: &[u8], on_event: &mut dyn FnMut(Ev<'_>)) -> ChatOutcome {
        let mut new_challenge: Option<Vec<u8>> = None;
        let mut attempt = 0u32;
        let mut frame_scratch = Vec::with_capacity(512);
        let (status, resp_headers) = loop {
            attempt += 1;
            let signals = self.signals_b64();
            let jsa = self.jsa.clone().unwrap_or_else(|| "initial".into());
            let headers: Vec<(&'static str, String)> = vec![
                ("Content-Type", "application/json".into()),
                ("accept", "text/event-stream".into()),
                ("x-fe-version", self.fe_version.clone()),
                ("x-fe-signals", signals),
                ("X-Vqd-Hash-1", jsa),
                ("x-ddg-journey-id", self.journey.clone()),
                ("origin", "https://duck.ai".into()),
                ("referer", "https://duck.ai/".into()),
            ];
            match self.http.stream(
                "https://duck.ai/duckchat/v1/chat",
                &headers,
                body,
                12,
                &mut |line: &[u8]| {
                    if let Some(ev) = wire::parse_ddg_frame(line, &mut frame_scratch) {
                        match ev {
                            Ev::Done => {}
                            other => on_event(other),
                        }
                    }
                },
            ) {
                Ok(v) => break v,
                Err(Net::FirstByte(_)) if attempt < 3 => {
                    eprintln!("[duckkit] L7 hang ({attempt}/3) — ретрай");
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                Err(e) => return ChatOutcome::Err(e.to_string()),
            }
        };
        let next_challenge = net::header_ci(&resp_headers, "x-vqd-hash-1");
        eprintln!("[duckkit] chat status={status} next_challenge={}", if next_challenge.is_some() { "yes" } else { "NO" });
        if let Some(nc) = next_challenge {
            new_challenge = Some(nc.as_bytes().to_vec());
        }
        // 410 = факты бандла устарели: пересобрать и решить новый челлендж.
        if status == 410 {
            if let Err(e) = self.reboot_facts() {
                return ChatOutcome::Err(format!("410 reboot: {e}"));
            }
            self.pending = new_challenge;
            if let Err(e) = self.refresh_jsa() {
                return ChatOutcome::Err(format!("410 jsa: {e}"));
            }
            return ChatOutcome::Challenge;
        }
        // 418 = токен истёк, сервер выдал новый челлендж — решаем его. Это протокол.
        if status == 418 {
            self.pending = new_challenge;
            if let Err(e) = self.refresh_jsa() {
                return ChatOutcome::Err(format!("418 jsa: {e}"));
            }
            return ChatOutcome::Challenge;
        }
        if status == 429 {
            return ChatOutcome::Err("429: rate limit — следи за частотой запросов".into());
        }
        if status != 200 {
            return ChatOutcome::Err(format!("duck статус {status}"));
        }
        // 200: сервер выдал челлендж на следующий запрос — решаем сразу, не «потом».
        if let Some(nc) = new_challenge {
            self.pending = Some(nc);
            if let Err(e) = self.refresh_jsa() {
                return ChatOutcome::Err(format!("next jsa: {e}"));
            }
        }
        ChatOutcome::Ok
    }
}
