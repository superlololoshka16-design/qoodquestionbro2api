// WHATWG HTML fragment parsing — детерминированная чистая функция, один проход.
// Не браузер, не DOM, ноль памяти под узлы: только стек открытых имён + два
// счётчика. Длина сериализации innerHTML от глубины не зависит (каждый элемент
// даёт `<name>` при открытии и `</name>` при закрытии), поэтому дерево не нужно.
// Возвращает (innerHTML.length, querySelectorAll("*").length). Вход — строковый
// литерал из AST; любая новая строка считается на месте, таблица не нужна.

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
    "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hgroup",
    "hr", "li", "main", "menu", "nav", "ol", "p", "section", "table", "ul",
];
const SCOPE_STOP: &[&str] = &[
    "applet", "caption", "html", "td", "th", "marquee", "object", "template", "button",
];

fn is_void(n: &str) -> bool {
    VOID.contains(&n)
}

pub fn metrics(frag: &str) -> (usize, usize) {
    let b = frag.as_bytes();
    let n = b.len();
    let mut len = 0usize; // длина сериализации innerHTML
    let mut cnt = 0usize; // число элементов = querySelectorAll("*").length
    let mut stack: Vec<String> = Vec::new(); // открытые элементы (глубина вложенности)

    // открыть элемент: emit `<name>`, счётчик++; не-void кладём в стек
    let open = |nm: &str, len: &mut usize, cnt: &mut usize, stack: &mut Vec<String>| {
        *len += nm.len() + 2;
        *cnt += 1;
        if !is_void(nm) {
            stack.push(nm.to_string());
        }
    };
    // закрыть один элемент: emit `</name>`
    let close = |nm: &str, len: &mut usize| {
        *len += nm.len() + 3;
    };
    let in_scope = |nm: &str, stack: &[String]| -> bool {
        for s in stack.iter().rev() {
            if s == nm {
                return true;
            }
            if SCOPE_STOP.contains(&s.as_str()) {
                return false;
            }
        }
        false
    };
    // pop до элемента nm включительно, emit их `</name>`
    let pop_until = |nm: &str, len: &mut usize, stack: &mut Vec<String>| {
        while let Some(top) = stack.pop() {
            let hit = top == nm;
            close(&top, len);
            if hit {
                break;
            }
        }
    };
    let close_p = |len: &mut usize, stack: &mut Vec<String>| {
        while let Some(top) = stack.pop() {
            let is_p = top == "p";
            close(&top, len);
            if is_p {
                break;
            }
        }
    };

    let mut i = 0usize;
    while i < n {
        if b[i] == b'<' {
            let mut j = i + 1;
            while j < n && b[j] != b'>' {
                j += 1;
            }
            if j >= n {
                break; // тег обрывается на EOF — дропается (parse error)
            }
            let tag = &frag[i + 1..j];
            i = j + 1;
            if tag.starts_with('/') {
                let nm: String = tag[1..].chars().take_while(|c| c.is_ascii_alphabetic()).collect::<String>().to_ascii_lowercase();
                if nm.is_empty() {
                    continue;
                }
                if nm == "br" {
                    open("br", &mut len, &mut cnt, &mut stack); // </br> = parse error, вставляет <br>
                } else if nm == "p" {
                    if in_scope("p", &stack) {
                        close_p(&mut len, &mut stack);
                    } else {
                        open("p", &mut len, &mut cnt, &mut stack);
                        pop_until("p", &mut len, &mut stack);
                    }
                } else if in_scope(&nm, &stack) {
                    pop_until(&nm, &mut len, &mut stack);
                }
            } else if tag.starts_with('!') || tag.starts_with('?') || tag.is_empty() {
                // doctype / комментарий / PI — во фрагменте игнорируются
            } else {
                let nm: String = tag.chars().take_while(|c| c.is_ascii_alphabetic()).collect::<String>().to_ascii_lowercase();
                if nm.is_empty() {
                    continue;
                }
                if !FMT.contains(&nm.as_str()) && !is_void(&nm) && IMPLIES_P.contains(&nm.as_str()) && in_scope("p", &stack) {
                    close_p(&mut len, &mut stack);
                }
                if nm == "li" {
                    let mut k = stack.len();
                    while k > 0 {
                        k -= 1;
                        if stack[k] == "li" {
                            pop_until("li", &mut len, &mut stack);
                            break;
                        }
                        if !matches!(stack[k].as_str(), "address" | "div" | "p") {
                            break;
                        }
                    }
                }
                open(&nm, &mut len, &mut cnt, &mut stack);
            }
        } else {
            let start = i;
            while i < n && b[i] != b'<' {
                i += 1;
            }
            len += i - start; // текстовый узел: сырая длина (в литералах челленджа текста нет)
        }
    }
    // EOF: все открытые элементы закрываются
    while let Some(top) = stack.pop() {
        close(&top, &mut len);
    }
    (len, cnt)
}
