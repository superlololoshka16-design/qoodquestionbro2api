use oxc_allocator::Allocator;
use oxc_ast::ast::{self, Expression, Statement};
use oxc_span::GetSpan;
use oxc_parser::Parser;
use oxc_span::{SourceType, Span};

#[derive(Debug, Clone, Default)]
pub struct StackFacts {
    pub fname: Box<str>,
    pub line: u64,
    pub col_error: u64,
    pub col_race: u64,
}

#[derive(Debug, Clone, Default)]
pub struct Timing {
    pub timeout_ms: u64,
    pub duration_delta: i64,
    pub macrotask_zero: bool,
}

#[derive(Debug, Clone, Default)]
pub struct BundleEnv {
    pub stack: Option<StackFacts>,
    pub timing: Timing,
    pub fe_version_ok: bool,
    pub signal_events: Vec<Box<str>>,
}

const CACHE_MAGIC: u32 = 0x44_4B_42_45; // "DKBE"
const CACHE_VERSION: u8 = 1;

impl BundleEnv {
    // Ручная бинарная сериализация фактов бандла. Ноль serde, ноль лишних аллокаций.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(128);
        b.extend_from_slice(&CACHE_MAGIC.to_le_bytes());
        b.push(CACHE_VERSION);
        match &self.stack {
            Some(s) => {
                b.push(1);
                let n = s.fname.as_bytes();
                b.extend_from_slice(&(n.len() as u32).to_le_bytes());
                b.extend_from_slice(n);
                b.extend_from_slice(&s.line.to_le_bytes());
                b.extend_from_slice(&s.col_error.to_le_bytes());
                b.extend_from_slice(&s.col_race.to_le_bytes());
            }
            None => b.push(0),
        }
        b.extend_from_slice(&self.timing.timeout_ms.to_le_bytes());
        b.extend_from_slice(&self.timing.duration_delta.to_le_bytes());
        b.push(u8::from(self.timing.macrotask_zero));
        b.push(u8::from(self.fe_version_ok));
        b.extend_from_slice(&(self.signal_events.len() as u32).to_le_bytes());
        for e in &self.signal_events {
            let n = e.as_bytes();
            b.extend_from_slice(&(n.len() as u32).to_le_bytes());
            b.extend_from_slice(n);
        }
        b
    }

    pub fn from_bytes(b: &[u8]) -> Option<BundleEnv> {
        let mut r = Reader { b, i: 0 };
        if r.u32()? != CACHE_MAGIC || r.u8()? != CACHE_VERSION {
            return None;
        }
        let stack = match r.u8()? {
            1 => Some(StackFacts {
                fname: r.str()?.into(),
                line: r.u64()?,
                col_error: r.u64()?,
                col_race: r.u64()?,
            }),
            0 => None,
            _ => return None,
        };
        let timing = Timing { timeout_ms: r.u64()?, duration_delta: r.i64()?, macrotask_zero: r.u8()? != 0 };
        let fe_version_ok = r.u8()? != 0;
        let n = r.u32()? as usize;
        if n > 4096 {
            return None;
        }
        let mut signal_events = Vec::with_capacity(n);
        for _ in 0..n {
            signal_events.push(r.str()?.into());
        }
        Some(BundleEnv { stack, timing, fe_version_ok, signal_events })
    }
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let e = self.i.checked_add(n)?;
        if e > self.b.len() {
            return None;
        }
        let s = &self.b[self.i..e];
        self.i = e;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|x| x[0])
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8).map(|x| {
            let mut a = [0u8; 8];
            a.copy_from_slice(x);
            u64::from_le_bytes(a)
        })
    }
    fn i64(&mut self) -> Option<i64> {
        self.u64().map(|v| v as i64)
    }
    fn str(&mut self) -> Option<&'a str> {
        let n = self.u32()? as usize;
        if n > 1 << 20 {
            return None;
        }
        std::str::from_utf8(self.take(n)?).ok()
    }
}

fn cache_dir() -> Option<std::path::PathBuf> {
    if let Ok(d) = std::env::var("DUCKKIT_CACHE") {
        return Some(std::path::PathBuf::from(d));
    }
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("LOCALAPPDATA").map(std::path::PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".cache")))?;
    Some(base.join("duckkit"))
}

// Факты бандла стабильны на бандл (48ms oxc-парс 2.2MB) — кэш по xxh3(бандл).
// Совпал хэш → грузим готовый BundleEnv за микросекунды, oxc не запускается.
pub fn analyze_bundle_cached(src: &str) -> Option<BundleEnv> {
    let key = crate::core::xxh3_64(src.as_bytes());
    let path = cache_dir().map(|d| d.join(format!("bundle-{key:016x}.bin")))?;
    if let Ok(bytes) = std::fs::read(&path)
        && let Some(env) = BundleEnv::from_bytes(&bytes)
    {
        return Some(env);
    }
    let env = analyze_bundle(src)?;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
        // новый бандл → старый кэш сбрасывается: активен один бандл, прочие stale
        if let Ok(rd) = std::fs::read_dir(parent) {
            for e in rd.flatten() {
                let p = e.path();
                if p != path
                    && p.file_name().map(|f| f.to_string_lossy().starts_with("bundle-")).unwrap_or(false)
                {
                    let _ = std::fs::remove_file(p);
                }
            }
        }
    }
    let _ = std::fs::write(&path, env.to_bytes());
    Some(env)
}

struct FnFrame {
    span: Span,
    name: Option<Box<str>>,
}

struct Walk {
    fn_stack: Vec<FnFrame>,
    timeout_hits: Vec<(u32, Vec<FnFrame>)>,
    timeout_calls: Vec<(u64, u32)>,
    stack_hits: Vec<(u32, Vec<FnFrame>)>,
    race_hits: Vec<(u32, Vec<FnFrame>)>,
    signals: Option<Vec<Box<str>>>,
    fever_ids: u8,
    fever_attrs: u8,
    duration_delta: Option<i64>,
    macrotask_zero: bool,
    macrotask_zeros: Vec<u32>,
    aliases: std::collections::HashMap<String, &'static str>,
}

fn common_prefix(names: &[Box<str>]) -> Option<String> {
    let first = names.first()?;
    let mut end = first.len();
    while end > 0 {
        let cand = &first[..end];
        if names.iter().all(|n| n.starts_with(cand)) {
            return Some(cand.to_string());
        }
        end = first[..end].char_indices().rev().next().map(|(i, _)| i).unwrap_or(0);
    }
    None
}

impl Walk {
    fn enter_fn(&mut self, span: Span, name: Option<Box<str>>) {
        self.fn_stack.push(FnFrame { span, name });
    }
    fn exit_fn(&mut self) {
        self.fn_stack.pop();
    }

    fn bind_alias(&mut self, decl: &ast::VariableDeclarator, init: &Expression) {
        let name = match &decl.id { ast::BindingPattern::BindingIdentifier(b) => b.name.to_string(), _ => return };
        let builtin = match init {
            Expression::StaticMemberExpression(m) => {
                let prop = m.property.name.as_str();
                let obj_is = |want: &str| matches!(&m.object, Expression::Identifier(i) if i.name == want);
                if obj_is("Promise") && prop == "race" {
                    "Promise.race"
                } else if obj_is("window") && prop == "setTimeout" {
                    "window.setTimeout"
                } else {
                    match prop {
                        "getAttribute" => "getAttribute",
                        "setTimeout" => "setTimeout",
                        _ => return,
                    }
                }
            }
            Expression::Identifier(i) if i.name == "setTimeout" => "setTimeout",
            _ => return,
        };
        self.aliases.insert(name, builtin);
    }

    fn callee_builtin(&self, callee: &Expression) -> Option<&'static str> {
        match callee {
            Expression::StaticMemberExpression(m) => {
                let prop = m.property.name.as_str();
                if matches!(&m.object, Expression::Identifier(i) if i.name == "Promise") && prop == "race" {
                    Some("Promise.race")
                } else if prop == "setTimeout" {
                    Some("setTimeout")
                } else if prop == "getAttribute" {
                    Some("getAttribute")
                } else {
                    None
                }
            }
            Expression::Identifier(i) => {
                if i.name == "setTimeout" {
                    Some("setTimeout")
                } else {
                    self.aliases.get(i.name.as_ref()).copied()
                }
            }
            _ => None,
        }
    }

    fn ancestors(&self) -> Vec<FnFrame> {
        self.fn_stack
            .iter()
            .map(|f| FnFrame { span: f.span, name: f.name.clone() })
            .collect()
    }

    fn expr(&mut self, e: &Expression) {
        match e {
            Expression::ObjectExpression(o) => {
                for p in &o.properties {
                    let ast::ObjectPropertyKind::ObjectProperty(p) = p else { continue };
                    let k = match &p.key {
                        ast::PropertyKey::StaticIdentifier(i) => i.name.as_str(),
                        ast::PropertyKey::StringLiteral(s) => s.value.as_str(),
                        _ => continue,
                    };
                    match k {
                        "stack" => {
                            if let Expression::CallExpression(c) = &p.value
                                && let Some(arg) = c.arguments.first().and_then(|a| a.as_expression())
                                    && let Expression::NewExpression(n) = arg
                                        && matches!(&n.callee, Expression::Identifier(i) if i.name == "Error") {
                                            self.stack_hits.push((n.span().start, self.ancestors()));
                                        }
                        }
                        "duration" => {
                            self.duration_delta = self.duration_delta.or(duration_delta_of(&p.value));
                        }
                        _ => {}
                    }
                }
            }
            Expression::StringLiteral(s) => {
                if s.value == "jsa_evaluation_timeout" {
                    self.timeout_hits.push((s.span.start, self.ancestors()));
                }
            }
            Expression::AwaitExpression(a) => {
                if let Expression::CallExpression(c) = &a.argument
                    && self.callee_builtin(&c.callee) == Some("Promise.race") {
                    self.race_hits.push((a.span().start, self.ancestors()));
                }
            }
            Expression::NewExpression(n) => {
                if matches!(&n.callee, Expression::Identifier(i) if i.name == "Set")
                    && let Some(arg) = n.arguments.first().and_then(|a| a.as_expression())
                        && let Expression::ArrayExpression(arr) = arg
                            && arr.elements.len() >= 2
                            && self.signals.is_none() {
                                let mut names: Vec<Box<str>> = Vec::with_capacity(arr.elements.len());
                                let mut all = true;
                                for el in &arr.elements {
                                    match el.as_expression() {
                                        Some(Expression::StringLiteral(s)) => names.push(s.value.as_str().into()),
                                        _ => {
                                            all = false;
                                            break;
                                        }
                                    }
                                }
                                if all
                                    && let Some(prefix) = common_prefix(&names)
                                    && prefix.len() >= 2 {
                                        let cut = prefix.len();
                                        self.signals = Some(names.iter().map(|n| n[cut..].into()).collect());
                                    }
                            }
            }
            Expression::StaticMemberExpression(m) => {
                let prop = m.property.name.as_str();
                match prop {
                    "__DDG_BE_VERSION__" => self.fever_ids |= 1,
                    "__DDG_FE_CHAT_HASH__" => self.fever_ids |= 2,
                    _ => {}
                }
            }
            Expression::CallExpression(c) => {
                match self.callee_builtin(&c.callee) {
                    Some("getAttribute") => {
                        for a in &c.arguments {
                            if let Some(Expression::StringLiteral(s)) = a.as_expression() {
                                if s.value == "data-version-tag" {
                                    self.fever_attrs |= 1;
                                } else if s.value == "data-version-sha" {
                                    self.fever_attrs |= 2;
                                }
                            }
                        }
                    }
                    Some("setTimeout") | Some("window.setTimeout") => {
                        for a in &c.arguments {
                            if let Some(Expression::NumericLiteral(z)) = a.as_expression()
                                && z.value >= 10.0 {
                                    self.timeout_calls.push((z.value as u64, z.span.start));
                                }
                        }
                        if c.arguments.len() == 2
                            && matches!(c.arguments[1].as_expression(), Some(Expression::NumericLiteral(z)) if z.value == 0.0)
                        {
                            self.macrotask_zeros.push(c.span().start);
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    fn stmt(&mut self, s: &Statement) {
        match s {
            Statement::ExpressionStatement(es) => walk_expr(&es.expression, self),
            Statement::VariableDeclaration(d) => {
                for x in &d.declarations {
                    if let Some(i) = &x.init {
                        self.bind_alias(x, i);
                        walk_expr(i, self);
                    }
                }
            }
            Statement::FunctionDeclaration(f) => {
                let name = f.id.as_ref().map(|i| i.name.as_str().into());
                self.enter_fn(f.span, name);
                if let Some(b) = &f.body {
                    for s in &b.statements {
                        walk_stmt(s, self);
                    }
                }
                self.exit_fn();
            }
            Statement::ReturnStatement(r) => {
                if let Some(a) = &r.argument {
                    walk_expr(a, self);
                }
            }
            Statement::IfStatement(i) => {
                walk_expr(&i.test, self);
                walk_stmt(&i.consequent, self);
                if let Some(a) = &i.alternate {
                    walk_stmt(a, self);
                }
            }
            Statement::WhileStatement(w) => {
                walk_expr(&w.test, self);
                walk_stmt(&w.body, self);
            }
            Statement::DoWhileStatement(w) => {
                walk_stmt(&w.body, self);
                walk_expr(&w.test, self);
            }
            Statement::ForStatement(fs) => {
                if let Some(ast::ForStatementInit::VariableDeclaration(d)) = &fs.init {
                    for x in &d.declarations {
                        if let Some(i) = &x.init {
                            walk_expr(i, self);
                        }
                    }
                }
                if let Some(t) = &fs.test {
                    walk_expr(t, self);
                }
                if let Some(u) = &fs.update {
                    walk_expr(u, self);
                }
                walk_stmt(&fs.body, self);
            }
            Statement::ForOfStatement(fs) => {
                walk_expr(&fs.right, self);
                walk_stmt(&fs.body, self);
            }
            Statement::ForInStatement(fs) => {
                walk_expr(&fs.right, self);
                walk_stmt(&fs.body, self);
            }
            Statement::BlockStatement(b) => {
                for s in &b.body {
                    walk_stmt(s, self);
                }
            }
            Statement::TryStatement(t) => {
                for s in &t.block.body {
                    walk_stmt(s, self);
                }
                if let Some(h) = &t.handler {
                    for s in &h.body.body {
                        walk_stmt(s, self);
                    }
                }
                if let Some(fi) = &t.finalizer {
                    for s in &fi.body {
                        walk_stmt(s, self);
                    }
                }
            }
            Statement::SwitchStatement(sw) => {
                walk_expr(&sw.discriminant, self);
                for c in &sw.cases {
                    if let Some(t) = &c.test {
                        walk_expr(t, self);
                    }
                    for s in &c.consequent {
                        walk_stmt(s, self);
                    }
                }
            }
            Statement::LabeledStatement(l) => walk_stmt(&l.body, self),
            Statement::ThrowStatement(t) => walk_expr(&t.argument, self),
            _ => {}
        }
    }
}

fn duration_delta_of(e: &Expression) -> Option<i64> {
    let Expression::CallExpression(c) = e else { return None };
    let ident = match &c.callee {
        Expression::Identifier(i) => i.name.as_ref(),
        _ => return None,
    };
    if ident != "String" {
        return None;
    }
    let arg = c.arguments.first()?.as_expression()?;
    let Expression::BinaryExpression(b) = arg else { return None };
    if b.operator != ast::BinaryOperator::Subtraction {
        return None;
    }
    let right = &b.right;
    match right {
        Expression::Identifier(_) => Some(0),
        Expression::BinaryExpression(rb)
            if rb.operator == ast::BinaryOperator::Addition
                && matches!(rb.left, Expression::Identifier(_)) =>
        {
            match &rb.right {
                Expression::NumericLiteral(n) => Some(n.value as i64),
                Expression::UnaryExpression(u)
                    if u.operator == ast::UnaryOperator::UnaryNegation
                        && matches!(&u.argument, Expression::NumericLiteral(_)) =>
                {
                    Some(-(num_of(&u.argument)? as i64))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn num_of(e: &Expression) -> Option<f64> {
    match e {
        Expression::NumericLiteral(n) => Some(n.value),
        _ => None,
    }
}

fn walk_expr(e: &Expression, w: &mut Walk) {
    w.expr(e);
    match e {
        Expression::ArrayExpression(a) => {
            for el in &a.elements {
                if let Some(x) = el.as_expression() {
                    walk_expr(x, w);
                }
            }
        }
        Expression::ObjectExpression(o) => {
            for p in &o.properties {
                if let ast::ObjectPropertyKind::ObjectProperty(p) = p {
                    if let Some(k) = p.key.as_expression() {
                        walk_expr(k, w);
                    }
                    walk_expr(&p.value, w);
                }
            }
        }
        Expression::CallExpression(c) => {
            walk_expr(&c.callee, w);
            for a in &c.arguments {
                if let Some(x) = a.as_expression() {
                    walk_expr(x, w);
                }
            }
        }
        Expression::NewExpression(c) => {
            walk_expr(&c.callee, w);
            for a in &c.arguments {
                if let Some(x) = a.as_expression() {
                    walk_expr(x, w);
                }
            }
        }
        Expression::BinaryExpression(b) => {
            walk_expr(&b.left, w);
            walk_expr(&b.right, w);
        }
        Expression::LogicalExpression(b) => {
            walk_expr(&b.left, w);
            walk_expr(&b.right, w);
        }
        Expression::UnaryExpression(u) => walk_expr(&u.argument, w),
        Expression::AwaitExpression(u) => walk_expr(&u.argument, w),
        Expression::AssignmentExpression(a) => {
            walk_expr(&a.right, w);
            if let ast::AssignmentTarget::ComputedMemberExpression(m) = &a.left {
                walk_expr(&m.object, w);
                walk_expr(&m.expression, w);
            }
        }
        Expression::SequenceExpression(s) => {
            for e in &s.expressions {
                walk_expr(e, w);
            }
        }
        Expression::ParenthesizedExpression(p) => walk_expr(&p.expression, w),
        Expression::ConditionalExpression(c) => {
            walk_expr(&c.test, w);
            walk_expr(&c.consequent, w);
            walk_expr(&c.alternate, w);
        }
        Expression::TemplateLiteral(t) => {
            for e in &t.expressions {
                walk_expr(e, w);
            }
        }
        Expression::ArrowFunctionExpression(a) => {
            w.enter_fn(a.span, None);
            match &a.body {
                ast::ArrowFunctionBody::FunctionBody(b) => {
                    for s in &b.statements {
                        walk_stmt(s, w);
                    }
                }
                other => {
                    if let Some(x) = other.as_expression() {
                        walk_expr(x, w);
                    }
                }
            }
            w.exit_fn();
        }
        Expression::FunctionExpression(fun) => {
            let name = fun.id.as_ref().map(|i| i.name.as_str().into());
            w.enter_fn(fun.span, name);
            if let Some(b) = &fun.body {
                for s in &b.statements {
                    walk_stmt(s, w);
                }
            }
            w.exit_fn();
        }
        Expression::ComputedMemberExpression(m) => {
            walk_expr(&m.object, w);
            walk_expr(&m.expression, w);
        }
        Expression::StaticMemberExpression(m) => walk_expr(&m.object, w),
        _ => {}
    }
}

fn walk_stmt(s: &Statement, w: &mut Walk) {
    w.stmt(s);
}

fn utf16_line_col(src: &str, offset: usize) -> (u64, u64) {
    let b = src.as_bytes();
    let mut line = 1u64;
    let mut line_start = 0usize;
    for (i, &c) in b[..offset.min(b.len())].iter().enumerate() {
        if c == b'\n' {
            line += 1;
            line_start = i + 1;
        }
    }
    let seg = &src[line_start..offset.min(src.len())];
    let col: usize = seg.chars().map(char::len_utf16).sum();
    (line, col as u64 + 1)
}

fn find_stack(w: &Walk) -> Option<(u32, u32, &[FnFrame])> {
    for (_, anc) in &w.timeout_hits {
        for frame in anc.iter().rev() {
            let span = frame.span;
            let in_span = |p: u32| span.start <= p && p < span.end;
            if let Some((sepos, sanc)) = w.stack_hits.iter().find(|(p, _)| in_span(*p))
                && let Some((rpos, _)) = w.race_hits.iter().find(|(p, _)| in_span(*p)) {
                    return Some((*sepos, *rpos, sanc));
                }
        }
    }
    None
}


pub fn analyze_bundle(src: &str) -> Option<BundleEnv> {
    let allocator = Allocator::default();
    let ret = Parser::new(&allocator, src, SourceType::default()).parse();
    if ret.fatal_error {
        return None;
    }
    let mut w = Walk {
        fn_stack: Vec::new(),
        timeout_hits: Vec::new(),
        timeout_calls: Vec::new(),
        stack_hits: Vec::new(),
        race_hits: Vec::new(),
        signals: None,
        fever_ids: 0,
        fever_attrs: 0,
        duration_delta: None,
        macrotask_zero: false,
        macrotask_zeros: Vec::new(),
        aliases: std::collections::HashMap::new(),
    };
    for s in &ret.program.body {
        walk_stmt(s, &mut w);
    }
    let mut env = BundleEnv {
        stack: None,
        timing: Timing {
            timeout_ms: 0,
            duration_delta: w.duration_delta.unwrap_or(0),
            macrotask_zero: w.macrotask_zero,
        },
        fe_version_ok: w.fever_ids == 3 && w.fever_attrs == 3,
        signal_events: w.signals.clone().unwrap_or_default(),
    };
    if let Some((sepos, rapos, sanc)) = find_stack(&w) {
        let (line, col_error) = utf16_line_col(src, sepos as usize);
        let (_, col_race) = utf16_line_col(src, rapos as usize);
        if let Some(fname) = sanc.iter().rev().find_map(|f| f.name.clone()) {
            let fn_span = sanc.last().map(|f| f.span);
            if let Some(sp) = fn_span
                && w.macrotask_zeros.iter().any(|&p| sp.start <= p && p < sp.end)
            {
                env.timing.macrotask_zero = true;
            }
            env.timing.timeout_ms = w
                .timeout_calls
                .iter()
                .filter(|&(_, p)| w.race_hits.iter().any(|&(r, _)| r <= *p && *p - r < 5000) || w.timeout_hits.iter().any(|&(t, _)| t <= *p && *p - t < 5000))
                .map(|&(v, _)| v)
                .max()
                .unwrap_or(0);
            env.stack = Some(StackFacts { fname, line, col_error, col_race });
        }
    }
    Some(env)
}
