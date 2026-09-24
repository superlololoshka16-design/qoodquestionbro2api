use std::time::Duration;

use futures_util::StreamExt;
use wreq::header::{HeaderMap, OrigHeaderMap, USER_AGENT};
use wreq_util::{Emulation, Platform, Profile};

use crate::err::Net;

pub const API: &str = "https://duck.ai/duckchat/v1";

/// Точный User-Agent, который шлёт профиль Chrome131/Windows из wreq-util.
/// Эта строка хешируется в client_hashes токена — любое расхождение с
/// фактическим заголовком убивает сессию.
pub const PROFILE_UA: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

pub type HeaderList = Vec<(&'static str, String)>;
pub type RespHeaders = Vec<(Box<str>, Box<str>)>;

/// Порядок дефолтных заголовков профиля Chrome131
/// (header_initializer_with_zstd_priority в wreq-util). Wire-порядок
/// формируется через OrigHeaderMap: эти имена идут первыми в этом порядке,
/// кастомные заголовки запроса — хвостом.
const CHROME_HEADERS: &[&str] = &[
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "upgrade-insecure-requests",
    "user-agent",
    "accept",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-user",
    "sec-fetch-dest",
    "accept-language",
    "priority",
];

pub struct Http {
    client: wreq::Client,
    rt: tokio::runtime::Runtime,
    pub proxy: Option<String>,
    pub ua: String,
    ua_override: Option<String>,
}

pub struct Resp {
    pub status: u16,
    pub headers: RespHeaders,
    pub body: Vec<u8>,
}

pub struct Page {
    pub be_version: String,
    pub fe_chat_hash: String,
    pub entry_bundle: String,
}

impl Page {
    pub fn fe_version(&self) -> String {
        let tag = if self.be_version.is_empty() { "dev" } else { &self.be_version };
        let sha = if self.fe_chat_hash.is_empty() { "hash" } else { &self.fe_chat_hash };
        format!("{tag}-{sha}")
    }
}

impl Http {
    pub fn new(proxy: Option<String>) -> Result<Self, Net> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| Net::Wreq(format!("tokio runtime: {e}")))?;
        let ua_override = std::env::var("DUCKKIT_UA").ok().filter(|s| !s.is_empty());
        let ua = ua_override.clone().unwrap_or_else(|| PROFILE_UA.to_string());
        let mut cb = wreq::Client::builder()
            .emulation(
                Emulation::builder()
                    .profile(Profile::Chrome131)
                    .platform(Platform::Windows)
                    .build(),
            )
            .redirect(wreq::redirect::Policy::none())
            .cookie_store(true)
            .timeout(Duration::from_secs(90))
            .connect_timeout(Duration::from_secs(12));
        if let Some(p) = &proxy {
            cb = cb.proxy(wreq::Proxy::all(p).map_err(|e| Net::Wreq(e.to_string()))?);
        }
        let client = cb.build().map_err(|e| Net::Wreq(e.to_string()))?;
        Ok(Self { client, rt, proxy, ua, ua_override })
    }

    pub fn ua(&self) -> &str {
        &self.ua
    }

    fn orig_map(&self, extra: &[(&'static str, String)]) -> OrigHeaderMap {
        let mut m = OrigHeaderMap::new();
        for name in CHROME_HEADERS {
            if let Some((k, _)) = extra.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)) {
                m.insert(*k);
            } else if *name == "user-agent" && self.ua_override.is_some() {
                m.insert("User-Agent");
            } else {
                m.insert(*name);
            }
        }
        for (k, _) in extra {
            if !CHROME_HEADERS.iter().any(|n| n.eq_ignore_ascii_case(k)) {
                m.insert(*k);
            }
        }
        m
    }

    fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(&'static str, String)],
    ) -> Result<wreq::RequestBuilder, Net> {
        let m = wreq::Method::from_bytes(method.as_bytes()).map_err(|e| Net::Wreq(e.to_string()))?;
        let mut rb = self.client.request(m, url).orig_headers(self.orig_map(headers));
        for (k, v) in headers {
            rb = rb.header(*k, v.as_str());
        }
        if let Some(ua) = &self.ua_override {
            rb = rb.header(USER_AGENT, ua.as_str());
        }
        Ok(rb)
    }

    fn once(
        &self,
        url: &str,
        method: &str,
        headers: &[(&'static str, String)],
        body: Option<&[u8]>,
    ) -> Result<Resp, Net> {
        let mut rb = self.request(method, url, headers)?;
        if let Some(b) = body {
            rb = rb.body(b.to_vec());
        }
        self.rt.block_on(async {
            let resp = rb.send().await.map_err(|e| Net::Wreq(e.to_string()))?;
            let status = resp.status().as_u16();
            let headers = collect_headers(resp.headers());
            let body = resp.bytes().await.map_err(|e| Net::Wreq(e.to_string()))?.to_vec();
            Ok(Resp { status, headers, body })
        })
    }

    pub fn send_retry(
        &self,
        url: &str,
        method: &str,
        headers: &[(&'static str, String)],
        body: Option<&[u8]>,
        attempts: u32,
        ctx: &'static str,
    ) -> Result<Resp, Net> {
        for i in 0..attempts {
            match self.once(url, method, headers, body) {
                Ok(r) => return Ok(r),
                Err(Net::Wreq(_)) | Err(Net::Empty(_)) => {}
                Err(e) => return Err(e),
            }
            std::thread::sleep(Duration::from_millis(400 + 300 * u64::from(i)));
        }
        Err(Net::Empty(format!("hang {ctx} после {attempts} попыток")))
    }

    pub fn page(&self) -> Result<Page, Net> {
        let hdrs = vec![
            ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".into()),
            ("accept-language", "en-US,en;q=0.9".into()),
        ];
        let r = self.send_retry("https://duck.ai/", "GET", &hdrs, None, 3, "duck.ai HTML")?;
        if r.status != 200 {
            return Err(Net::Status { ctx: "duck.ai HTML", status: r.status });
        }
        let be = attr(&r.body, b"data-version-tag=\"");
        let sha = attr(&r.body, b"data-version-sha=\"");
        let bundle = entry_bundle(&r.body)
            .ok_or(Net::Empty("entry.duckai.<hash>.js не найден в HTML".into()))?;
        if be.is_empty() || sha.is_empty() {
            return Err(Net::Empty("data-version-tag/sha не найдены".into()));
        }
        Ok(Page { be_version: be, fe_chat_hash: sha, entry_bundle: bundle })
    }

    pub fn status(&self, journey: &str, fe_version: &str, fe_signals: &str, _jsa: &str) -> Result<Resp, Net> {
        let hdrs = vec![
            ("Cache-Control", "no-store".into()),
            ("x-vqd-accept", "1".into()),
            ("x-fe-version", fe_version.to_string()),
            ("x-fe-signals", fe_signals.to_string()),
            ("x-ddg-journey-id", journey.to_string()),
            ("accept", "*/*".into()),
            ("origin", "https://duck.ai".into()),
            ("referer", "https://duck.ai/".into()),
        ];
        self.send_retry(&format!("{API}/status"), "GET", &hdrs, None, 4, "status")
    }

    pub fn bundle(&self, hash: &str) -> Result<Vec<u8>, Net> {
        let hdrs = vec![("accept", "*/*".into()), ("referer", "https://duck.ai/".into())];
        let r = self.send_retry(
            &format!("https://duck.ai/dist/duckai-dist/entry.duckai.{hash}.js"),
            "GET",
            &hdrs,
            None,
            3,
            "бандл",
        )?;
        if r.status != 200 {
            return Err(Net::Status { ctx: "бандл", status: r.status });
        }
        Ok(r.body)
    }

    pub fn models(&self, journey: &str) -> Result<Vec<u8>, Net> {
        let hdrs = vec![
            ("accept", "application/json".into()),
            ("x-ddg-journey-id", journey.to_string()),
            ("origin", "https://duck.ai".into()),
            ("referer", "https://duck.ai/".into()),
        ];
        let r = self.send_retry(&format!("{API}/models"), "GET", &hdrs, None, 4, "models")?;
        if r.status != 200 {
            return Err(Net::Status { ctx: "models", status: r.status });
        }
        Ok(r.body)
    }

    pub fn stream(
        &self,
        url: &str,
        headers: &[(&'static str, String)],
        body: &[u8],
        first_byte_timeout: u64,
        on_data: &mut dyn FnMut(&[u8]),
    ) -> Result<(u16, RespHeaders), Net> {
        let rb = self.request("POST", url, headers)?.body(body.to_vec());
        self.rt.block_on(async {
            let resp = rb.send().await.map_err(|e| Net::Wreq(e.to_string()))?;
            let status = resp.status().as_u16();
            let rh = collect_headers(resp.headers());
            let mut stream = resp.bytes_stream();
            let first = match tokio::time::timeout(Duration::from_secs(first_byte_timeout), stream.next()).await {
                Ok(Some(Ok(b))) => b,
                Ok(Some(Err(e))) => return Err(Net::Wreq(e.to_string())),
                Ok(None) => return Ok((status, rh)),
                Err(_) => return Err(Net::FirstByte(first_byte_timeout)),
            };
            let mut sse = Sse { tail: Vec::with_capacity(512) };
            sse.chunk(&first, on_data);
            while let Some(item) = stream.next().await {
                match item {
                    Ok(b) => sse.chunk(&b, on_data),
                    Err(e) => return Err(Net::Wreq(e.to_string())),
                }
            }
            if !sse.tail.is_empty() {
                let tail = std::mem::take(&mut sse.tail);
                feed(&tail, on_data);
            }
            Ok((status, rh))
        })
    }
}

struct Sse {
    tail: Vec<u8>,
}

impl Sse {
    fn chunk(&mut self, chunk: &[u8], on_data: &mut dyn FnMut(&[u8])) {
        let mut data = std::mem::take(&mut self.tail);
        data.extend_from_slice(chunk);
        match data.iter().rposition(|&b| b == b'\n') {
            Some(p) => {
                feed(&data[..=p], on_data);
                self.tail.extend_from_slice(&data[p + 1..]);
            }
            None => self.tail = data,
        }
    }
}

fn feed(mut buf: &[u8], on_data: &mut dyn FnMut(&[u8])) {
    while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
        let line = trim_eol(&buf[..pos]);
        if line.starts_with(b"data:") {
            let mut d = &line[5..];
            while d.first() == Some(&b' ') {
                d = &d[1..];
            }
            on_data(d);
        }
        buf = &buf[pos + 1..];
    }
}

fn collect_headers(headers: &HeaderMap) -> RespHeaders {
    headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().into(),
                String::from_utf8_lossy(v.as_bytes()).into_owned().into_boxed_str(),
            )
        })
        .collect()
}

fn trim_eol(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && matches!(line[end - 1], b'\r' | b'\n') {
        end -= 1;
    }
    &line[..end]
}

pub fn header_ci<'a>(headers: &'a [(Box<str>, Box<str>)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_ref())
}

fn attr(html: &[u8], needle: &[u8]) -> String {
    html.windows(needle.len())
        .position(|w| w == needle)
        .map(|pos| {
            let start = pos + needle.len();
            let end = html[start..]
                .iter()
                .position(|&b| b == b'"')
                .map(|p| start + p)
                .unwrap_or(html.len());
            String::from_utf8_lossy(&html[start..end]).into_owned()
        })
        .unwrap_or_default()
}

fn entry_bundle(html: &[u8]) -> Option<String> {
    let needle = b"entry.duckai.";
    let mut from = 0usize;
    while let Some(rel) = html[from..].windows(needle.len()).position(|w| w == needle) {
        let start = from + rel + needle.len();
        let hash_len = html[start..].iter().take_while(|&&b| b.is_ascii_alphanumeric()).count();
        if hash_len >= 16 && html[start + hash_len..].starts_with(b".js") {
            return Some(String::from_utf8_lossy(&html[start..start + hash_len]).into_owned());
        }
        from = start;
    }
    None
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn random_bytes(buf: &mut [u8]) -> Result<(), Net> {
    if crate::core::rng::fill(buf) {
        Ok(())
    } else {
        Err(Net::Urandom("os entropy".into()))
    }
}

pub fn journey_hex(out: &mut [u8; 32]) -> Result<(), Net> {
    let mut b = [0u8; 16];
    random_bytes(&mut b)?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, &x) in b.iter().enumerate() {
        out[i * 2] = HEX[(x >> 4) as usize];
        out[i * 2 + 1] = HEX[(x & 0x0f) as usize];
    }
    Ok(())
}

pub fn uuid_v4(out: &mut [u8; 36]) -> Result<(), Net> {
    let mut b = [0u8; 16];
    random_bytes(&mut b)?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut w = 0usize;
    for (i, &x) in b.iter().enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            out[w] = b'-';
            w += 1;
        }
        out[w] = HEX[(x >> 4) as usize];
        out[w + 1] = HEX[(x & 0x0f) as usize];
        w += 2;
    }
    Ok(())
}
