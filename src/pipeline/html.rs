// WHATWG HTML fragment metrics — zero-alloc, один проход по байтам.
// Не браузер, не DOM, ноль аллокаций: стек имён = &[str]-срезы самого входа,
// два счётчика. Длина сериализации innerHTML от глубины не зависит (элемент
// даёт `<name>` при открытии, `</name>` при закрытии), дерево не нужно.
// Возвращает (innerHTML.length, querySelectorAll("*").length). Вход — литерал
// из AST; вызывается ОДИН раз в AST-проходе (metric_probe), результат
// сворачивается в готовое число Probe.value — в рантайме токена не исполняется.

const VOID: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];
const FMT: &[&str] = &[
    "a", "b", "big", "code", "em", "font", "i", "nobr", "s", "small", "strike", "strong", "tt", "u",
    "span", "label", "abbr", "cite", "q", "kbd", "samp", "var", "mark", "sub", "sup", "time", "dfn",
];
const IMPLIES_P: &[&str] = &[
    "address", "article", "aside", "blockquote", "details", "div", "dd", "dl", "dt", "fieldset",
    "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header",
    "hgroup", "hr", "li", "main", "menu", "nav", "ol", "p", "section", "table", "ul",
];
const SCOPE_STOP: &[&str] = &[
    "applet", "caption", "html", "td", "th", "marquee", "object", "template", "button",
];
const LI_SPECIAL: &[&str] = &["address", "div", "p"];

#[inline]
fn any(list: &[&str], n: &str) -> bool {
    list.iter().any(|v| v.eq_ignore_ascii_case(n))
}

#[inline]
fn alpha_prefix(s: &str) -> &str {
    let end = s
        .char_indices()
        .find(|(_, c)| !c.is_ascii_alphabetic())
        .map(|(i, _)| i)
        .unwrap_or(s.len());
    &s[..end]
}

struct P<'a> {
    len: usize,
    cnt: usize,
    stack: [&'a str; 64],
    depth: usize,
}

impl<'a> P<'a> {
    #[inline]
    fn open(&mut self, nm: &'a str) {
        self.len += nm.len() + 2;
        self.cnt += 1;
        if !any(VOID, nm) && self.depth < 64 {
            self.stack[self.depth] = nm;
            self.depth += 1;
        }
    }
    #[inline]
    fn close(&mut self, nm: &str) {
        self.len += nm.len() + 3;
    }
    fn in_scope(&self, nm: &str) -> bool {
        for i in (0..self.depth).rev() {
            if self.stack[i].eq_ignore_ascii_case(nm) {
                return true;
            }
            if any(SCOPE_STOP, self.stack[i]) {
                return false;
            }
        }
        false
    }
    fn pop_until(&mut self, nm: &str) {
        while self.depth > 0 {
            self.depth -= 1;
            let top = self.stack[self.depth];
            let hit = top.eq_ignore_ascii_case(nm);
            self.close(top);
            if hit {
                break;
            }
        }
    }
    fn close_p(&mut self) {
        while self.depth > 0 {
            self.depth -= 1;
            let top = self.stack[self.depth];
            let is_p = top.eq_ignore_ascii_case("p");
            self.close(top);
            if is_p {
                break;
            }
        }
    }
}

pub fn metrics(frag: &str) -> (usize, usize) {
    let b = frag.as_bytes();
    let n = b.len();
    let mut p = P { len: 0, cnt: 0, stack: [""; 64], depth: 0 };
    let mut i = 0usize;
    while i < n {
        if b[i] == b'<' {
            let mut j = i + 1;
            while j < n && b[j] != b'>' {
                j += 1;
            }
            if j >= n {
                break; // тег оборван на EOF — дропается (parse error)
            }
            let tag = &frag[i + 1..j];
            i = j + 1;
            if let Some(rest) = tag.strip_prefix('/') {
                let nm = alpha_prefix(rest);
                if nm.is_empty() {
                    continue;
                }
                if nm.eq_ignore_ascii_case("br") {
                    p.open(nm); // </br> = parse error, но вставляет <br>
                } else if nm.eq_ignore_ascii_case("p") {
                    if p.in_scope("p") {
                        p.close_p();
                    } else {
                        p.open(nm);
                        p.pop_until("p");
                    }
                } else if p.in_scope(nm) {
                    p.pop_until(nm);
                }
            } else if tag.starts_with('!') || tag.starts_with('?') || tag.is_empty() {
                // doctype / комментарий / PI — во фрагменте игнорируются
            } else {
                let nm = alpha_prefix(tag);
                if nm.is_empty() {
                    continue;
                }
                if !any(FMT, nm) && !any(VOID, nm) && any(IMPLIES_P, nm) && p.in_scope("p") {
                    p.close_p();
                }
                if nm.eq_ignore_ascii_case("li") {
                    let mut k = p.depth;
                    while k > 0 {
                        k -= 1;
                        if p.stack[k].eq_ignore_ascii_case("li") {
                            p.pop_until("li");
                            break;
                        }
                        if !any(LI_SPECIAL, p.stack[k]) {
                            break;
                        }
                    }
                }
                p.open(nm);
            }
        } else {
            let start = i;
            while i < n && b[i] != b'<' {
                i += 1;
            }
            p.len += i - start; // текстовый узел: сырая длина
        }
    }
    while p.depth > 0 {
        p.depth -= 1;
        let top = p.stack[p.depth];
        p.close(top);
    }
    (p.len, p.cnt)
}
