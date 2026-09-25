use std::collections::HashMap;

use oxc_allocator::Allocator;
use oxc_ast::ast::{self, Expression, Statement};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};
use thiserror::Error;

use crate::pipeline::mba;
use crate::pipeline::ops::Program;
use crate::pipeline::roles::{num_lit, unwrap_parens, Translator};

#[derive(Debug, Error)]
pub enum FlowErr {
    #[error("не JS (oxc): {0}")]
    Parse(String),
    #[error("массив строк не найден")]
    NoStrings,
    #[error("декодер не найден: {0}")]
    NoDecoder(String),
    #[error("ротатор не найден: {0}")]
    NoRotator(String),
    #[error("ротация: {0}")]
    Rotation(String),
    #[error("payload: {0}")]
    Payload(String),
    #[error("вне модели: {0}")]
    Read(String),
}

#[derive(Debug, Clone)]
pub enum Sx {
    Num(f64),
    Str(String),
    Bool(bool),
    Null,
    Undef,
    Ref(String),
    Member { obj: Box<Sx>, prop: String },
    Index { obj: Box<Sx>, idx: Box<Sx> },
    Call { callee: Box<Sx>, args: Vec<Sx> },
    New { callee: Box<Sx>, args: Vec<Sx> },
    Bin { op: &'static str, l: Box<Sx>, r: Box<Sx> },
    Un { op: &'static str, a: Box<Sx> },
    Log { op: &'static str, l: Box<Sx>, r: Box<Sx> },
    Cond { t: Box<Sx>, c: Box<Sx>, a: Box<Sx> },
    Arr(Vec<Sx>),
    Obj(Vec<(String, Sx)>),
    Fn { params: Vec<String>, body: Vec<Sx>, arrow: bool },
    Class { name: String, super_: Option<Box<Sx>> },
    Seq(Vec<Sx>),
    Block(Vec<Sx>),
    Var { name: String, value: Box<Sx> },
    Assign { target: Box<Sx>, op: &'static str, value: Box<Sx> },
    If { t: Box<Sx>, c: Vec<Sx>, a: Vec<Sx> },
    For { init: Option<Box<Sx>>, t: Option<Box<Sx>>, u: Option<Box<Sx>>, body: Vec<Sx> },
    While { t: Box<Sx>, body: Vec<Sx> },
    Try { body: Vec<Sx>, handler: Option<(String, Vec<Sx>)>, fin: Vec<Sx> },
    Ret(Option<Box<Sx>>),
    Throw(Box<Sx>),
    Break,
    Continue,
    Empty,
}

#[derive(Debug, Clone)]
pub enum Read {
    NavUa,
    Env { desc: String },
}

#[derive(Debug, Clone)]
pub struct Probe {
    pub reads: Vec<Read>,
    pub base: Option<f64>,
    pub value: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CheckVal {
    True,
    False,
    Unknown,
}

// Факты верификации из AST бандла (oxc): пары (атрибут, значение) которые бандл
// сам ставит на #jsa (sandbox, content=CSP из srcDoc) и имена глобалов (__DDG_*).
// Значение jsa-чека = ТОЧНОЕ сравнение литерала челленджа с фактом бандла.
// Ноль угадывания: смена значений в бандле меняет факты — сравнение адаптируется.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProbeCtx<'a> {
    pub attached_styled: bool,
    pub verify_attrs: &'a [(Box<str>, Box<str>)],
    pub verify_globals: &'a [Box<str>],
}

fn has_prop(sx: &Sx, prop: &str) -> bool {
    let mut hit = false;
    walk_sx(sx, &mut |s| {
        if let Sx::Member { prop: p, .. } = s
            && p == prop
        {
            hit = true;
        }
    });
    hit
}

fn has_member(sx: &Sx, root: &str, prop: &str) -> bool {
    let mut hit = false;
    walk_sx(sx, &mut |s| {
        if let Sx::Member { obj, prop: p } = s
            && p == prop
                && let Sx::Ref(r) = obj.as_ref()
                    && r == root
        {
            hit = true;
        }
    });
    hit
}

fn has_call(sx: &Sx, prop: &str) -> bool {
    let mut hit = false;
    walk_sx(sx, &mut |s| {
        if let Sx::Call { callee, .. } = s {
            match callee.as_ref() {
                Sx::Member { prop: p, .. } if p == prop => hit = true,
                Sx::Ref(r) if r == prop => hit = true,
                _ => {}
            }
        }
    });
    hit
}

fn has_str(sx: &Sx, needle: &str) -> bool {
    let mut hit = false;
    walk_sx(sx, &mut |s| {
        if let Sx::Str(t) = s
            && t == needle
        {
            hit = true;
        }
    });
    hit
}

fn is_self_plus_k(sx: &Sx) -> bool {
    let Sx::Bin { op: "===", l, r } = sx else { return false };
    let Sx::Bin { op: "+", l: a, r: b } = r.as_ref() else { return false };
    matches!(b.as_ref(), Sx::Num(n) if *n != 0.0) && render_sx(a) == render_sx(l)
}

// Значение чека выводится из ФОРМЫ AST-узла (web-платформа детерминирована).
// Неизвестная форма → Unknown → честный отказ, никакого угадывания.
pub fn check_value(c: &Sx, ctx: ProbeCtx<'_>) -> CheckVal {
    use CheckVal::*;
    if let Some(b) = truthy(c) {
        return if b { True } else { False };
    }
    if is_self_plus_k(c) {
        return False;
    }
    if has_member(c, "navigator", "webdriver") {
        return False;
    }
    if has_call(c, "isSealed") {
        return False;
    }
    if has_prop(c, "contentWindow") && has_prop(c, "srcdoc") {
        return False;
    }
    if has_call(c, "endsWith") && has_member(c, "window", "top") {
        return False;
    }
    if has_call(c, "getComputedStyle") && has_call(c, "getPropertyValue") {
        return True;
    }
    if has_prop(c, "offsetWidth")
        || has_prop(c, "offsetHeight")
            || has_call(c, "getBoundingClientRect")
                || has_prop(c, "scrollHeight")
    {
        return if ctx.attached_styled { True } else { False };
    }
    if has_str(c, "[native code]") && has_call(c, "includes") {
        return True;
    }
    if has_str(c, "[object Window]") {
        return True;
    }
    if has_str(c, "NodeList") {
        return True;
    }
    if matches!(c, Sx::Un { op: "!", .. }) && has_call(c, "isArray") && has_call(c, "querySelectorAll") {
        return True;
    }
    if has_prop(c, "captureStackTrace") {
        return True;
    }
    if let Sx::Bin { op: "instanceof", .. } = c {
        return True;
    }
    // #jsa self-verification: getAttribute("<attr>") === "<literal>".
    // Значение = ТОЧНОЕ сравнение литерала челленджа с фактом бандла
    // (verify_attrs: бандл сам ставит sandbox/CSP на #jsa). Совпало → True,
    // разошлось → False. Ноль угадывания: смена значений в бандле меняет
    // факты — сравнение адаптируется само.
    if let Sx::Bin { op: "===", l, r } = c {
        for (a, b) in [(l.as_ref(), r.as_ref()), (r.as_ref(), l.as_ref())] {
            if let Sx::Call { callee, args } = a
                && let Sx::Member { prop, .. } = callee.as_ref()
                    && prop == "getAttribute"
                        && let Some(Sx::Str(attr)) = args.first()
                            && let Sx::Str(expected) = b
            {
                // attr = имя атрибута ("sandbox"/"content"), expected = значение
                // с которым челлендж себя сверяет. True только если бандл реально
                // ставит ЭТОТ атрибут в ЭТО значение — точное совпадение пары фактов.
                return if ctx.verify_attrs.iter().any(|(a, v)| a.as_ref() == attr.as_str() && v.as_ref() == expected.as_str())
                {
                    True
                } else {
                    False
                };
            }
        }
    }
    // window.top.hasOwnProperty("<global>") — имя сверяется с фактами бандла.
    if let Sx::Call { callee, args } = c
        && let Sx::Member { prop, .. } = callee.as_ref()
            && prop == "hasOwnProperty"
                && let Some(Sx::Str(g)) = args.first()
    {
        return if ctx.verify_globals.iter().any(|x| x.as_ref() == g.as_str()) { True } else { False };
    }
    if let Sx::Bin { op: "===", l, r } = c {
        let is_win = |s: &Sx| matches!(s, Sx::Ref(w) if w == "window");
        let is_fncall = |s: &Sx| {
            matches!(s, Sx::Call { callee, args } if args.is_empty() && matches!(callee.as_ref(), Sx::Fn { .. }))
        };
        if (is_fncall(l) && is_win(r)) || (is_win(l) && is_fncall(r)) {
            return True;
        }
    }
    Unknown
}

#[derive(Debug, Clone)]
pub struct Model {
    pub rotation: usize,
    pub rotate_left: bool,
    pub strings: Vec<String>,
    pub delta: f64,
    pub target: f64,
    pub egg: mba::Report,
    pub checksum: Program,
    pub checksum_vars: Vec<f64>,
    pub checksum_raw: Program,
    pub checksum_raw_vars: Vec<f64>,
    pub server_hashes: Vec<String>,
    pub v: String,
    pub challenge_id: String,
    pub timestamp: String,
    pub key: String,
    pub ua_first: bool,
    pub spec: Vec<(String, bool)>,
    pub probes: Vec<Probe>,
    pub body: Vec<Sx>,
}

fn mod_i64(x: i64, n: usize) -> usize {
    let n = n as i64;
    (((x % n) + n) % n) as usize
}

fn binding_name(p: &ast::BindingPattern) -> Option<String> {
    match p {
        ast::BindingPattern::BindingIdentifier(b) => Some(b.name.to_string()),
        _ => None,
    }
}

fn ident_name<'a>(e: &'a Expression<'a>) -> Option<&'a str> {
    match e {
        Expression::Identifier(i) => Some(i.name.as_str()),
        _ => None,
    }
}

fn string_array(arr: &ast::ArrayExpression<'_>) -> Option<Vec<String>> {
    if arr.elements.len() < 20 {
        return None;
    }
    let mut out = Vec::with_capacity(arr.elements.len());
    for el in &arr.elements {
        match el.as_expression() {
            Some(Expression::StringLiteral(s)) => out.push(s.value.as_str().to_string()),
            _ => return None,
        }
    }
    Some(out)
}

fn class_body_exprs(body: &ast::ClassBody, f: &mut impl FnMut(&Expression)) {
    for m in &body.body {
        match m {
            ast::ClassElement::MethodDefinition(md) => {
                if let Some(b) = &md.value.body {
                    for x in &b.statements {
                        stmt_exprs(x, f);
                    }
                }
            }
            ast::ClassElement::StaticBlock(sb) => {
                for x in &sb.body {
                    stmt_exprs(x, f);
                }
            }
            _ => {}
        }
    }
}

fn stmt_exprs(s: &Statement, f: &mut impl FnMut(&Expression)) {
    fn go(e: &Expression, f: &mut impl FnMut(&Expression)) {
        f(e);
        match e {
            Expression::BinaryExpression(b) => {
                go(&b.left, f);
                go(&b.right, f);
            }
            Expression::LogicalExpression(b) => {
                go(&b.left, f);
                go(&b.right, f);
            }
            Expression::UnaryExpression(u) => go(&u.argument, f),
            Expression::AwaitExpression(a) => go(&a.argument, f),
            Expression::ParenthesizedExpression(p) => go(&p.expression, f),
            Expression::SequenceExpression(sq) => {
                for x in &sq.expressions {
                    go(x, f);
                }
            }
            Expression::ConditionalExpression(c) => {
                go(&c.test, f);
                go(&c.consequent, f);
                go(&c.alternate, f);
            }
            Expression::AssignmentExpression(a) => {
                go(&a.right, f);
                match &a.left {
                    ast::AssignmentTarget::ComputedMemberExpression(m) => {
                        go(&m.object, f);
                        go(&m.expression, f);
                    }
                    ast::AssignmentTarget::StaticMemberExpression(m) => go(&m.object, f),
                    _ => {}
                }
            }
            Expression::CallExpression(c) => {
                go(&c.callee, f);
                for a in &c.arguments {
                    if let Some(x) = a.as_expression() {
                        go(x, f);
                    }
                }
            }
            Expression::NewExpression(n) => {
                go(&n.callee, f);
                for a in &n.arguments {
                    if let Some(x) = a.as_expression() {
                        go(x, f);
                    }
                }
            }
            Expression::StaticMemberExpression(m) => go(&m.object, f),
            Expression::ComputedMemberExpression(m) => {
                go(&m.object, f);
                go(&m.expression, f);
            }
            Expression::ArrayExpression(arr) => {
                for el in &arr.elements {
                    if let Some(x) = el.as_expression() {
                        go(x, f);
                    }
                }
            }
            Expression::ObjectExpression(o) => {
                for p in &o.properties {
                    if let ast::ObjectPropertyKind::ObjectProperty(p) = p {
                        go(&p.value, f);
                    }
                }
            }
            Expression::FunctionExpression(fe) => {
                if let Some(b) = &fe.body {
                    for x in &b.statements {
                        stmt_exprs(x, f);
                    }
                }
            }
            Expression::ArrowFunctionExpression(ae) => {
                if let Some(fb) = ae.get_function_body() {
                    for x in &fb.statements {
                        stmt_exprs(x, f);
                    }
                } else if let Some(e) = ae.get_expression() {
                    go(e, f);
                }
            }
            Expression::ClassExpression(c) => class_body_exprs(&c.body, f),
            _ => {}
        }
    }
    match s {
        Statement::ExpressionStatement(e) => go(&e.expression, f),
        Statement::VariableDeclaration(v) => {
            for d in &v.declarations {
                if let Some(i) = &d.init {
                    go(i, f);
                }
            }
        }
        Statement::FunctionDeclaration(fd) => {
            if let Some(b) = &fd.body {
                for x in &b.statements {
                    stmt_exprs(x, f);
                }
            }
        }
        Statement::ReturnStatement(r) => {
            if let Some(a) = &r.argument {
                go(a, f);
            }
        }
        Statement::IfStatement(i) => {
            go(&i.test, f);
            stmt_exprs(&i.consequent, f);
            if let Some(a) = &i.alternate {
                stmt_exprs(a, f);
            }
        }
        Statement::WhileStatement(w) => {
            go(&w.test, f);
            stmt_exprs(&w.body, f);
        }
        Statement::DoWhileStatement(w) => {
            stmt_exprs(&w.body, f);
            go(&w.test, f);
        }
        Statement::ForStatement(fs) => {
            match &fs.init {
                Some(ast::ForStatementInit::VariableDeclaration(v)) => {
                    for d in &v.declarations {
                        if let Some(i) = &d.init {
                            go(i, f);
                        }
                    }
                }
                _ => {}
            }
            if let Some(t) = &fs.test {
                go(t, f);
            }
            if let Some(u) = &fs.update {
                go(u, f);
            }
            stmt_exprs(&fs.body, f);
        }
        Statement::ForOfStatement(fs) => {
            go(&fs.right, f);
            stmt_exprs(&fs.body, f);
        }
        Statement::ForInStatement(fs) => {
            go(&fs.right, f);
            stmt_exprs(&fs.body, f);
        }
        Statement::BlockStatement(b) => {
            for x in &b.body {
                stmt_exprs(x, f);
            }
        }
        Statement::TryStatement(t) => {
            for x in &t.block.body {
                stmt_exprs(x, f);
            }
            if let Some(h) = &t.handler {
                for x in &h.body.body {
                    stmt_exprs(x, f);
                }
            }
            if let Some(fi) = &t.finalizer {
                for x in &fi.body {
                    stmt_exprs(x, f);
                }
            }
        }
        Statement::SwitchStatement(sw) => {
            go(&sw.discriminant, f);
            for c in &sw.cases {
                if let Some(t) = &c.test {
                    go(t, f);
                }
                for x in &c.consequent {
                    stmt_exprs(x, f);
                }
            }
        }
        Statement::ThrowStatement(t) => go(&t.argument, f),
        Statement::LabeledStatement(l) => stmt_exprs(&l.body, f),
        Statement::ClassDeclaration(c) => class_body_exprs(&c.body, f),
        _ => {}
    }
}

fn each_stmt_deep<'a>(s: &'a Statement<'a>, f: &mut impl FnMut(&'a Statement<'a>)) {
    f(s);
    let mut stmts: Vec<&'a Statement<'a>> = Vec::new();
    match s {
        Statement::BlockStatement(b) => {
            for x in &b.body {
                stmts.push(x);
            }
        }
        Statement::FunctionDeclaration(fd) => {
            if let Some(b) = &fd.body {
                for x in &b.statements {
                    stmts.push(x);
                }
            }
        }
        Statement::IfStatement(i) => {
            stmts.push(&i.consequent);
            if let Some(a) = &i.alternate {
                stmts.push(a);
            }
        }
        Statement::WhileStatement(w) => stmts.push(&w.body),
        Statement::DoWhileStatement(w) => stmts.push(&w.body),
        Statement::ForStatement(fs) => stmts.push(&fs.body),
        Statement::ForOfStatement(fs) => stmts.push(&fs.body),
        Statement::ForInStatement(fs) => stmts.push(&fs.body),
        Statement::TryStatement(t) => {
            for x in &t.block.body {
                stmts.push(x);
            }
            if let Some(h) = &t.handler {
                for x in &h.body.body {
                    stmts.push(x);
                }
            }
            if let Some(fi) = &t.finalizer {
                for x in &fi.body {
                    stmts.push(x);
                }
            }
        }
        Statement::SwitchStatement(sw) => {
            for c in &sw.cases {
                for x in &c.consequent {
                    stmts.push(x);
                }
            }
        }
        Statement::LabeledStatement(l) => stmts.push(&l.body),
        Statement::ExpressionStatement(es) => {
            each_expr_deep(&es.expression, f);
        }
        Statement::VariableDeclaration(v) => {
            for d in &v.declarations {
                if let Some(i) = &d.init {
                    each_expr_deep(i, f);
                }
            }
        }
        Statement::ReturnStatement(r) => {
            if let Some(a) = &r.argument {
                each_expr_deep(a, f);
            }
        }
        Statement::ThrowStatement(t) => each_expr_deep(&t.argument, f),
        Statement::ClassDeclaration(c) => class_body_stmts_deep(&c.body, f),
        _ => {}
    }
    for x in stmts {
        each_stmt_deep(x, f);
    }
}

fn class_body_stmts_deep<'a>(body: &'a ast::ClassBody<'a>, f: &mut impl FnMut(&'a Statement<'a>)) {
    for m in &body.body {
        match m {
            ast::ClassElement::MethodDefinition(md) => {
                if let Some(b) = &md.value.body {
                    for x in &b.statements {
                        each_stmt_deep(x, f);
                    }
                }
            }
            ast::ClassElement::StaticBlock(sb) => {
                for x in &sb.body {
                    each_stmt_deep(x, f);
                }
            }
            _ => {}
        }
    }
}

fn each_expr_deep<'a>(e: &'a Expression<'a>, f: &mut impl FnMut(&'a Statement<'a>)) {
    match e {
        Expression::FunctionExpression(fe) => {
            if let Some(b) = &fe.body {
                for x in &b.statements {
                    each_stmt_deep(x, f);
                }
            }
        }
        Expression::ArrowFunctionExpression(ae) => {
            if let Some(fb) = ae.get_function_body() {
                for x in &fb.statements {
                    each_stmt_deep(x, f);
                }
            } else if let Some(x) = ae.get_expression() {
                each_expr_deep(x, f);
            }
        }
        Expression::ClassExpression(c) => class_body_stmts_deep(&c.body, f),
        Expression::CallExpression(cc) => {
            each_expr_deep(&cc.callee, f);
            for a in &cc.arguments {
                if let Some(x) = a.as_expression() {
                    each_expr_deep(x, f);
                }
            }
        }
        Expression::NewExpression(ne) => {
            each_expr_deep(&ne.callee, f);
            for a in &ne.arguments {
                if let Some(x) = a.as_expression() {
                    each_expr_deep(x, f);
                }
            }
        }
        Expression::BinaryExpression(b) => {
            each_expr_deep(&b.left, f);
            each_expr_deep(&b.right, f);
        }
        Expression::LogicalExpression(b) => {
            each_expr_deep(&b.left, f);
            each_expr_deep(&b.right, f);
        }
        Expression::UnaryExpression(u) => each_expr_deep(&u.argument, f),
        Expression::AwaitExpression(a) => each_expr_deep(&a.argument, f),
        Expression::ParenthesizedExpression(p) => each_expr_deep(&p.expression, f),
        Expression::SequenceExpression(sq) => {
            for x in &sq.expressions {
                each_expr_deep(x, f);
            }
        }
        Expression::ConditionalExpression(c) => {
            each_expr_deep(&c.test, f);
            each_expr_deep(&c.consequent, f);
            each_expr_deep(&c.alternate, f);
        }
        Expression::AssignmentExpression(a) => {
            each_expr_deep(&a.right, f);
            match &a.left {
                ast::AssignmentTarget::ComputedMemberExpression(m) => {
                    each_expr_deep(&m.object, f);
                    each_expr_deep(&m.expression, f);
                }
                ast::AssignmentTarget::StaticMemberExpression(m) => each_expr_deep(&m.object, f),
                _ => {}
            }
        }
        Expression::ArrayExpression(arr) => {
            for el in &arr.elements {
                if let Some(x) = el.as_expression() {
                    each_expr_deep(x, f);
                }
            }
        }
        Expression::ObjectExpression(o) => {
            for p in &o.properties {
                if let ast::ObjectPropertyKind::ObjectProperty(p) = p {
                    each_expr_deep(&p.value, f);
                }
            }
        }
        Expression::StaticMemberExpression(m) => each_expr_deep(&m.object, f),
        Expression::ComputedMemberExpression(m) => {
            each_expr_deep(&m.object, f);
            each_expr_deep(&m.expression, f);
        }
        _ => {}
    }
}

struct Statics {
    providers: HashMap<String, Vec<String>>,
    decoders: HashMap<String, f64>,
    aliases: HashMap<String, String>,
}

fn collect(program: &ast::Program<'_>) -> Statics {
    let mut providers: HashMap<String, Vec<String>> = HashMap::new();
    let mut decoders: HashMap<String, f64> = HashMap::new();
    let mut aliases: HashMap<String, String> = HashMap::new();

    for s in &program.body {
        each_stmt_deep(s, &mut |st| {
            if let Statement::VariableDeclaration(v) = st {
                for d in &v.declarations {
                    let Some(name) = binding_name(&d.id) else { continue };
                    match &d.init {
                        Some(Expression::ArrayExpression(arr)) => {
                            if let Some(strings) = string_array(arr) {
                                providers.entry(name).or_insert(strings);
                            }
                        }
                        Some(Expression::Identifier(i)) => {
                            aliases.entry(name).or_insert_with(|| i.name.to_string());
                        }
                        Some(Expression::CallExpression(ce)) => {
                            if let Some(n) = ident_name(&ce.callee) {
                                aliases.entry(name).or_insert_with(|| n.to_string());
                            }
                        }
                        _ => {}
                    }
                }
            }
            if let Statement::FunctionDeclaration(fd) = st {
                let Some(fname) = fd.id.as_ref().map(|i| i.name.to_string()) else { return };
                let Some(body) = &fd.body else { return };
                for inner in &body.statements {
                    if let Statement::VariableDeclaration(v) = inner {
                        for d in &v.declarations {
                            if let Some(Expression::ArrayExpression(arr)) = &d.init
                                && let Some(strings) = string_array(arr)
                            {
                                providers.entry(fname.clone()).or_insert(strings);
                            }
                        }
                    }
                }
                let mut subs: Vec<(String, f64)> = Vec::new();
                let mut members: Vec<(String, String)> = Vec::new();
                for bs in &body.statements {
                    stmt_exprs(bs, &mut |e| {
                        if let Expression::AssignmentExpression(a) = e
                            && let ast::AssignmentTarget::AssignmentTargetIdentifier(t) = &a.left
                        {
                            let hit = match (&a.operator, &a.right) {
                                (ast::AssignmentOperator::Assign, Expression::BinaryExpression(b)) => {
                                    ident_name(&b.left) == Some(t.name.as_ref())
                                        && num_lit(&b.right).is_some()
                                        && matches!(
                                            b.operator,
                                            ast::BinaryOperator::Subtraction
                                                | ast::BinaryOperator::Addition
                                                | ast::BinaryOperator::BitwiseXOR
                                        )
                                }
                                (ast::AssignmentOperator::Subtraction, r)
                                | (ast::AssignmentOperator::Addition, r)
                                | (ast::AssignmentOperator::BitwiseXOR, r) => num_lit(r).is_some(),
                                _ => false,
                            };
                            if hit {
                                let d = match (&a.operator, &a.right) {
                                    (ast::AssignmentOperator::Assign, Expression::BinaryExpression(b)) => num_lit(&b.right),
                                    (_, r) => num_lit(r),
                                };
                                if let Some(d) = d {
                                    subs.push((t.name.as_ref().to_string(), d));
                                }
                            }
                        }
                        if let Expression::ComputedMemberExpression(m) = e
                            && let (Some(idx), Some(obj)) = (ident_name(&m.expression), ident_name(&m.object))
                        {
                            members.push((idx.to_string(), obj.to_string()));
                        }
                    });
                }
                if subs.iter().any(|(x, _)| members.iter().any(|(i, _)| i == x))
                    && let Some((_, d)) = subs.first()
                {
                    decoders.entry(fname).or_insert(*d);
                }
            }
        });
    }
    Statics { providers, decoders, aliases }
}

fn resolve_alias<'a>(st: &'a Statics, name: &str) -> Option<&'a str> {
    let mut cur: Option<&'a str> = None;
    for _ in 0..16 {
        let key = cur.unwrap_or(name);
        if let Some(d) = st.decoders.get_key_value(key) {
            return Some(d.0.as_str());
        }
        match st.aliases.get(key) {
            Some(n) => cur = Some(n.as_str()),
            None => return None,
        }
    }
    None
}

fn call_name(e: &Expression) -> Option<String> {
    match unwrap_parens(e) {
        Expression::Identifier(i) => Some(i.name.to_string()),
        Expression::StaticMemberExpression(m) => Some(m.property.name.to_string()),
        Expression::ComputedMemberExpression(m) => match unwrap_parens(&m.expression) {
            Expression::StringLiteral(s) => Some(s.value.to_string()),
            _ => None,
        },
        _ => None,
    }
}

fn top_body<'a>(program: &'a ast::Program<'a>) -> &'a [Statement<'a>] {
    for s in &program.body {
        if let Statement::ExpressionStatement(es) = s
            && let Expression::CallExpression(c) = unwrap_parens(&es.expression)
        {
            match unwrap_parens(&c.callee) {
                Expression::FunctionExpression(fe) => {
                    return fe.body.as_ref().map(|b| b.statements.as_slice()).unwrap_or(&[]);
                }
                Expression::ArrowFunctionExpression(ae) => {
                    return ae.get_function_body().map(|b| b.statements.as_slice()).unwrap_or(&[]);
                }
                _ => {}
            }
        }
    }
    program.body.as_slice()
}

fn find_rotator<'e>(program: &'e ast::Program<'e>, st: &Statics) -> Result<(f64, bool, &'e Expression<'e>), FlowErr> {
    let mut found: Option<(f64, bool, &Expression)> = None;
    'outer: for s in &program.body {
        let mut stack: Vec<&Statement> = Vec::new();
        each_stmt_deep(s, &mut |x| stack.push(x));
        for cur in stack {
            let Statement::ExpressionStatement(es) = cur else { continue };
            let Expression::CallExpression(call) = unwrap_parens(&es.expression) else { continue };
            let Expression::FunctionExpression(fun) = unwrap_parens(&call.callee) else { continue };
            if fun.params.items.len() != 2 || call.arguments.len() < 2 {
                continue;
            }
            let Some(target) = call.arguments[1].as_expression().and_then(num_lit) else { continue };
            let Some(body) = &fun.body else { continue };
            let mut left = false;
            let mut has_rot = false;
            for bs in &body.statements {
                stmt_exprs(bs, &mut |e| {
                    let Expression::CallExpression(c) = e else { return };
                    let Some(outer_name) = call_name(&c.callee) else { return };
                    let Some(inner) = c.arguments.first().and_then(|a| a.as_expression()) else { return };
                    let Expression::CallExpression(inner) = unwrap_parens(inner) else { return };
                    if !inner.arguments.is_empty() {
                        return;
                    }
                    let Some(inner_name) = call_name(&inner.callee) else { return };
                    match (outer_name.as_str(), inner_name.as_str()) {
                        ("push", "shift") => {
                            left = true;
                            has_rot = true;
                        }
                        ("unshift", "pop") => {
                            left = false;
                            has_rot = true;
                        }
                        _ => {}
                    }
                });
            }
            if !has_rot {
                continue;
            }
            for bs in &body.statements {
                let Statement::WhileStatement(w) = bs else { continue };
                let try_stmt = match &w.body {
                    Statement::TryStatement(t) => Some(t),
                    Statement::BlockStatement(b) => b.body.iter().find_map(|x| match x {
                        Statement::TryStatement(t) => Some(t),
                        _ => None,
                    }),
                    _ => None,
                };
                let Some(t) = try_stmt else { continue };
                for ts in &t.block.body {
                    let Statement::VariableDeclaration(vd) = ts else { continue };
                    for d in &vd.declarations {
                        let Some(init) = &d.init else { continue };
                        let mut has_dec = false;
                        stmt_exprs(ts, &mut |e| {
                            if let Expression::CallExpression(ce) = e
                                && let Some(nm) = ident_name(&ce.callee)
                                && resolve_alias(st, nm).is_some()
                            {
                                has_dec = true;
                            }
                        });
                        if has_dec {
                            found = Some((target, left, init));
                            break 'outer;
                        }
                    }
                }
            }
        }
    }
    found.ok_or_else(|| FlowErr::NoRotator("нет IIFE (fn(arr,target)) с push/shift и checksum-вызовом декодера".into()))
}

fn checksum_expr_walk(e: &Expression, f: &mut impl FnMut(&Expression)) {
    fn go(e: &Expression, f: &mut impl FnMut(&Expression)) {
        f(e);
        match e {
            Expression::BinaryExpression(b) => {
                go(&b.left, f);
                go(&b.right, f);
            }
            Expression::LogicalExpression(b) => {
                go(&b.left, f);
                go(&b.right, f);
            }
            Expression::UnaryExpression(u) => go(&u.argument, f),
            Expression::ParenthesizedExpression(p) => go(&p.expression, f),
            Expression::SequenceExpression(s) => {
                for x in &s.expressions {
                    go(x, f);
                }
            }
            Expression::CallExpression(c) => {
                go(&c.callee, f);
                for a in &c.arguments {
                    if let Some(x) = a.as_expression() {
                        go(x, f);
                    }
                }
            }
            Expression::StaticMemberExpression(m) => go(&m.object, f),
            Expression::ComputedMemberExpression(m) => {
                go(&m.object, f);
                go(&m.expression, f);
            }
            _ => {}
        }
    }
    go(e, f);
}

pub fn run(
    src: &str,
    verify_attrs: &[(Box<str>, Box<str>)],
    verify_globals: &[Box<str>],
) -> Result<Model, FlowErr> {
    let allocator = Allocator::default();
    let ret = Parser::new(&allocator, src, SourceType::default()).parse();
    if ret.fatal_error {
        return Err(FlowErr::Parse(
            ret.diagnostics.iter().take(3).map(|d| d.to_string()).collect::<Vec<_>>().join("; "),
        ));
    }
    let program = &ret.program;
    let st = collect(program);
    if st.providers.is_empty() {
        return Err(FlowErr::NoStrings);
    }
    if st.decoders.is_empty() {
        return Err(FlowErr::NoDecoder("нет функции с самотрансформацией индекса".into()));
    }

    let (target, left, checksum_expr) = find_rotator(program, &st)?;

    let mut used_dec: Option<String> = None;
    checksum_expr_walk(checksum_expr, &mut |e| {
        if used_dec.is_none()
            && let Expression::CallExpression(ce) = e
            && let Some(nm) = ident_name(&ce.callee)
            && let Some(d) = resolve_alias(&st, nm)
        {
            used_dec = Some(d.to_string());
        }
    });
    let dec_name = used_dec
        .as_deref()
        .or_else(|| st.decoders.keys().next().map(|s| s.as_str()))
        .ok_or_else(|| FlowErr::NoDecoder("ни один декодер не вызван в checksum".into()))?;
    let delta = *st.decoders.get(dec_name).ok_or_else(|| FlowErr::NoDecoder(dec_name.into()))?;

    let orig = st
        .providers
        .values()
        .max_by_key(|v| v.len())
        .cloned()
        .ok_or(FlowErr::NoStrings)?;
    let n = orig.len();

    let is_dec = |nm: &str| resolve_alias(&st, nm).map(|s| s.to_string());
    let mut tr = Translator::new(&is_dec);
    tr.expr(checksum_expr).map_err(|e| FlowErr::Read(format!("перевод checksum: {e}")))?;
    let t = tr.finish();
    let simp = mba::simplify(&t.recexpr);
    // egg-канон → cranelift: компиляция ОДИН раз на full_hash канона, дальше
    // thread_local кэш. rotation-цикл гоняет нативный fn вместо интерпретатора.
    // Канарейка: первый прогон сверяет jit с интерпретатором бит-в-бит на
    // реальных данных; расхождение → jit отключается, fallback Program::eval.
    let jit = crate::pipeline::jit::compile_cached(simp.report.full_hash, &simp.program).ok();

    let vals: Vec<f64> = orig.iter().map(|s| crate::core::jsnum::js_parse_int(s)).collect();
    let delta_i = delta as i64;
    let mut buf = vec![0f64; t.var_args.len().max(1)];
    let mut rot_k: Option<usize> = None;
    let mut best: Option<(usize, f64)> = None;
    let mut jit_ok: Option<bool> = None;
    for k in 0..n {
        for (vi, &a) in t.var_args.iter().enumerate() {
            let idx = if left {
                mod_i64(a as i64 - delta_i + k as i64, n)
            } else {
                mod_i64(a as i64 - delta_i - k as i64, n)
            };
            buf[vi] = vals[idx];
        }
        let v = match (&jit, jit_ok) {
            (Some(j), None) => {
                let iv = simp.program.eval(&buf);
                jit_ok = Some(j.call(&buf).to_bits() == iv.to_bits());
                iv
            }
            (Some(j), Some(true)) => j.call(&buf),
            _ => simp.program.eval(&buf),
        };
        if v == target {
            rot_k = Some(k);
            break;
        }
        let d = (v - target).abs();
        if d.is_finite() && best.map(|(_, bd)| d < bd).unwrap_or(true) {
            best = Some((k, d));
        }
    }
    let k = rot_k.ok_or_else(|| {
        FlowErr::Rotation(format!(
            "цель {target}, лучший k={:?} |Δ|={}",
            best.map(|(k, _)| k),
            best.map(|(_, d)| d).unwrap_or(f64::NAN)
        ))
    })?;

    let strings: Vec<String> = if left {
        orig.iter().cycle().skip(k % n).take(n).cloned().collect()
    } else {
        let s = (n - k % n) % n;
        orig.iter().cycle().skip(s).take(n).cloned().collect()
    };

    let dec = |arg: f64| -> String {
        let idx = mod_i64(arg as i64 - delta_i, n);
        strings[idx].clone()
    };
    let mut canon_vars: Vec<f64> = Vec::with_capacity(simp.slot_symbols.len());
    for sym in &simp.slot_symbols {
        let arg = t
            .var_pairs
            .iter()
            .find(|(nm, _)| nm == sym)
            .map(|&(_, a)| a)
            .ok_or_else(|| FlowErr::Read(format!("канон ссылается на неизвестный слот {sym}")))?;
        canon_vars.push(crate::core::jsnum::js_parse_int(&dec(arg)));
    }
    let raw_vars: Vec<f64> = t.var_args.iter().map(|&a| crate::core::jsnum::js_parse_int(&dec(a))).collect();
    let canon_v = simp.program.eval(&canon_vars);
    if canon_v != target {
        return Err(FlowErr::Rotation(format!("канон после ротации {canon_v} != цель {target}")));
    }
    let raw_v = t.program.eval(&raw_vars);
    if raw_v != target {
        return Err(FlowErr::Rotation(format!("сырой перевод {raw_v} != цель {target}")));
    }

    let mut d = Deob {
        strings: &strings,
        st: &st,
        scopes: vec![HashMap::new()],
        mutated: HashMap::new(),
        depth: 0,
    };
    let body = d.stmts(top_body(program))?;

    let mut server_hashes: Vec<String> = Vec::new();
    let mut v = String::new();
    let mut challenge_id = String::new();
    let mut timestamp = String::new();
    let mut key: Option<String> = None;
    let mut spec: Vec<(String, bool)> = Vec::new();

    harvest(&body, &mut |sx| {
        if let Sx::Ret(Some(bx)) = sx
            && let Sx::Obj(fields) = bx.as_ref()
        {
            for (k2, val) in fields {
                match k2.as_str() {
                    "server_hashes" => {
                        if let Sx::Arr(items) = val {
                            for it in items {
                                if let Sx::Str(s) = it {
                                    server_hashes.push(s.clone());
                                }
                            }
                        }
                    }
                    "meta" => {
                        if let Sx::Obj(mf) = val {
                            for (mk, mv) in mf {
                                match mk.as_str() {
                                    "v" => {
                                        if let Sx::Str(s) = mv {
                                            v = s.clone();
                                        }
                                    }
                                    "challenge_id" => {
                                        if let Sx::Str(s) = mv {
                                            challenge_id = s.clone();
                                        }
                                    }
                                    "timestamp" => {
                                        if let Sx::Str(s) = mv {
                                            timestamp = s.clone();
                                        }
                                    }
                                    "debug" => {
                                        if key.is_none() {
                                            key = find_xor_key(mv, &body);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        if let Sx::Var { value, .. } = sx
            && let Sx::Arr(pairs) = value.as_ref()
            && (2..=12).contains(&pairs.len())
            && spec.is_empty()
        {
            let mut local: Vec<(String, bool)> = Vec::new();
            let mut ok = true;
            for p in pairs {
                match p {
                    Sx::Arr(pp) if pp.len() == 2 => match (&pp[0], &pp[1]) {
                        (Sx::Str(nm), Sx::Bool(fl)) => local.push((nm.clone(), *fl)),
                        _ => {
                            ok = false;
                            break;
                        }
                    },
                    _ => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                spec = local;
            }
        }
    });

    let Some(key) = key else {
        return Err(FlowErr::Payload("XOR-ключ debug не найден".into()));
    };
    if server_hashes.len() != 3 {
        return Err(FlowErr::Payload(format!("server_hashes: {} шт", server_hashes.len())));
    }
    if challenge_id.is_empty() || timestamp.is_empty() {
        return Err(FlowErr::Payload("challenge_id/timestamp пусты".into()));
    }

    let (ua_first, probes) = extract_probes(&body, verify_attrs, verify_globals)?;

    Ok(Model {
        rotation: k,
        rotate_left: left,
        strings,
        delta,
        target,
        egg: simp.report,
        checksum: simp.program,
        checksum_vars: canon_vars,
        checksum_raw: t.program,
        checksum_raw_vars: raw_vars,
        server_hashes,
        v,
        challenge_id,
        timestamp,
        key,
        ua_first,
        spec,
        probes,
        body,
    })
}

fn walk_all(v: &[Sx], f: &mut impl FnMut(&Sx)) {
    for x in v {
        walk_sx(x, f);
    }
}

fn harvest(body: &[Sx], f: &mut impl FnMut(&Sx)) {
    walk_all(body, f);
}

fn walk_sx(sx: &Sx, f: &mut impl FnMut(&Sx)) {
    f(sx);
    match sx {
        Sx::Member { obj, .. } | Sx::Un { a: obj, .. } | Sx::Throw(obj) | Sx::Ret(Some(obj)) | Sx::Var { value: obj, .. } => {
            walk_sx(obj, f);
        }
        Sx::Index { obj, idx } => {
            walk_sx(obj, f);
            walk_sx(idx, f);
        }
        Sx::Call { callee, args } | Sx::New { callee, args } => {
            walk_sx(callee, f);
            walk_all(args, f);
        }
        Sx::Bin { l, r, .. } | Sx::Log { l, r, .. } => {
            walk_sx(l, f);
            walk_sx(r, f);
        }
        Sx::Cond { t, c, a } => {
            walk_sx(t, f);
            walk_sx(c, f);
            walk_sx(a, f);
        }
        Sx::Arr(v) | Sx::Seq(v) | Sx::Block(v) => walk_all(v, f),
        Sx::Obj(kv) => {
            for (_, x) in kv {
                walk_sx(x, f);
            }
        }
        Sx::Fn { body, .. } => walk_all(body, f),
        Sx::Class { super_: Some(s), .. } => walk_sx(s, f),
        Sx::Assign { target, value, .. } => {
            walk_sx(target, f);
            walk_sx(value, f);
        }
        Sx::If { t, c, a } => {
            walk_sx(t, f);
            walk_all(c, f);
            walk_all(a, f);
        }
        Sx::For { init, t, u, body } => {
            if let Some(x) = init {
                walk_sx(x, f);
            }
            if let Some(x) = t {
                walk_sx(x, f);
            }
            if let Some(x) = u {
                walk_sx(x, f);
            }
            walk_all(body, f);
        }
        Sx::While { t, body } => {
            walk_sx(t, f);
            walk_all(body, f);
        }
        Sx::Try { body, handler, fin } => {
            walk_all(body, f);
            if let Some((_, hb)) = handler {
                walk_all(hb, f);
            }
            walk_all(fin, f);
        }
        _ => {}
    }
}

fn find_xor_key(debug: &Sx, body: &[Sx]) -> Option<String> {
    let mut out: Option<String> = None;
    walk_sx(debug, &mut |s| {
        if out.is_some() {
            return;
        }
        let Sx::Bin { op: "^", l, r } = s else { return };
        for (a, b) in [(l.as_ref(), r.as_ref()), (r.as_ref(), l.as_ref())] {
            if let Sx::Call { callee, .. } = a
                && let Sx::Member { prop, obj } = callee.as_ref()
                && prop == "charCodeAt"
                && is_charcodeat(b)
            {
                match obj.as_ref() {
                    Sx::Str(s) => out = Some(s.clone()),
                    Sx::Ref(nm) => {
                        let nm = nm.clone();
                        harvest(body, &mut |v| {
                            if out.is_none()
                                && let Sx::Var { name, value } = v
                                && *name == nm
                                && let Sx::Str(s) = value.as_ref()
                            {
                                out = Some(s.clone());
                            }
                        });
                    }
                    _ => {}
                }
            }
        }
    });
    out
}

fn is_charcodeat(sx: &Sx) -> bool {
    matches!(sx, Sx::Call { callee, .. } if matches!(callee.as_ref(), Sx::Member { prop, .. } if prop == "charCodeAt"))
}


fn extract_probes<'a>(
    body: &[Sx],
    attrs: &'a [(Box<str>, Box<str>)],
    globals: &'a [Box<str>],
) -> Result<(bool, Vec<Probe>), FlowErr> {
    let mut ua_first = false;
    let mut probes: Vec<Probe> = Vec::new();
    let mut found = false;
    harvest(body, &mut |sx| {
        if found {
            return;
        }
        let Sx::Call { callee, args } = sx else { return };
        let Sx::Member { obj, prop } = callee.as_ref() else { return };
        if prop != "all" {
            return;
        }
        let Sx::Ref(r) = obj.as_ref() else { return };
        if r != "Promise" {
            return;
        }
        let Some(Sx::Arr(items)) = args.first() else { return };
        found = true;
        for it in items {
            if let Sx::Member { obj: o, prop: p } = it
                && let Sx::Ref(r) = o.as_ref()
                && r == "navigator"
                && p == "userAgent"
            {
                if probes.is_empty() {
                    ua_first = true;
                }
                continue;
            }
            if let Some(p) = classify_probe(it, attrs, globals) {
                probes.push(p);
            } else {
                probes.push(Probe { reads: vec![Read::Env { desc: render_sx(it) }], base: None, value: None });
            }
        }
    });
    if !found {
        return Err(FlowErr::Read("Promise.all не найден".into()));
    }
    Ok((ua_first, probes))
}

fn probe_ctx<'a>(
    fn_body: Option<&[Sx]>,
    attrs: &'a [(Box<str>, Box<str>)],
    globals: &'a [Box<str>],
) -> ProbeCtx<'a> {
    let mut ctx = ProbeCtx { attached_styled: false, verify_attrs: attrs, verify_globals: globals };
    if let Some(body) = fn_body {
        let seq = Sx::Seq(body.to_vec());
        let mut styled = false;
        let mut attached = false;
        walk_sx(&seq, &mut |s| {
            if let Sx::Assign { target, .. } = s
                && let Sx::Member { prop, .. } = target.as_ref()
                    && prop == "cssText"
            {
                styled = true;
            }
            if let Sx::Call { callee, .. } = s
                && let Sx::Member { prop, .. } = callee.as_ref()
                    && prop == "appendChild"
            {
                attached = true;
            }
        });
        ctx.attached_styled = styled && attached;
    }
    ctx
}

fn classify_probe<'a>(
    sx: &Sx,
    attrs: &'a [(Box<str>, Box<str>)],
    globals: &'a [Box<str>],
) -> Option<Probe> {
    let (inner_call, fn_body) = match sx {
        Sx::Call { callee, args } if args.is_empty() => match callee.as_ref() {
            Sx::Fn { body, .. } => (find_return_string(body)?, Some(body)),
            _ => (sx, None),
        },
        _ => (sx, None),
    };
    let Sx::Call { callee, args } = inner_call else { return None };
    let Sx::Ref(r) = callee.as_ref() else { return None };
    if r != "String" || args.len() != 1 {
        return None;
    }
    let inner = &args[0];
    let body = fn_body.map(|v| v.as_slice());

    if let Some(p) = metric_probe(inner, body) {
        return Some(p);
    }
    let (base, checks) = resolve_reduce(inner, body).or_else(|| reduce_chain(inner))?;
    Some(sum_probe(base, &checks, body, attrs, globals))
}

// Числовой операнд верхнего сложения: String(base + …) → base из Num-узла.
fn addend_const(sx: &Sx) -> Option<f64> {
    let Sx::Bin { op: "+", l, r } = sx else { return None };
    if let Sx::Num(n) = l.as_ref() {
        return Some(*n);
    }
    if let Sx::Num(n) = r.as_ref() {
        return Some(*n);
    }
    addend_const(l).or_else(|| addend_const(r))
}

// Метрическая проба: String(base + innerHTML.length * querySelectorAll("*").length).
// Структура читается из AST: base — Num-операнд "+", форма — наличие узлов innerHTML
// и querySelectorAll, литерал — из Assign{innerHTML = Str} в теле пробы. Значение
// считает детерминированный WHATWG-парсер (html::metrics), не таблица и не хром.
fn metric_probe(inner: &Sx, fn_body: Option<&[Sx]>) -> Option<Probe> {
    if !(has_prop(inner, "innerHTML") && has_call(inner, "querySelectorAll")) {
        return None;
    }
    let base = addend_const(inner)?;
    let body = fn_body?;
    let mut lit: Option<String> = None;
    harvest(body, &mut |s| {
        if lit.is_none()
            && let Sx::Assign { target, op: "=", value } = s
                && let Sx::Member { prop, .. } = target.as_ref()
                    && prop == "innerHTML"
                        && let Sx::Str(t) = value.as_ref()
        {
            lit = Some(t.clone());
        }
    });
    let html = lit?;
    let (len, count) = crate::pipeline::html::metrics(&html);
    Some(Probe {
        reads: vec![Read::Env {
            desc: format!("innerHTML({html:?}) → len={len} count={count} [WHATWG-парсер]"),
        }],
        base: Some(base),
        value: Some(base + (len * count) as f64),
    })
}

// Значение пробы = base + Σ Number(check). Каждый check решается структурно
// (check_value по форме AST-узла). Любая нераспознанная форма → value=None,
// честный отказ вместо угадывания. Никаких таблиц и снапшотов.
fn sum_probe<'a>(
    base: f64,
    checks: &[Sx],
    fn_body: Option<&[Sx]>,
    attrs: &'a [(Box<str>, Box<str>)],
    globals: &'a [Box<str>],
) -> Probe {
    let ctx = probe_ctx(fn_body, attrs, globals);
    let mut reads: Vec<Read> = Vec::new();
    let mut sum = base;
    let mut unsolvable = false;
    for c in checks {
        if reads_user_agent(c) {
            unsolvable = true;
            reads.push(Read::NavUa);
            continue;
        }
        let cv = check_value(c, ctx);
        match cv {
            CheckVal::True => sum += 1.0,
            CheckVal::False => {}
            CheckVal::Unknown => {
                unsolvable = true;
                reads.push(Read::Env { desc: render_sx(c) });
            }
        }
    }
    Probe { reads, base: Some(base), value: if unsolvable { None } else { Some(sum) } }
}

fn resolve_reduce(inner: &Sx, fn_body: Option<&[Sx]>) -> Option<(f64, Vec<Sx>)> {
    let body = fn_body?;
    let Sx::Call { callee, args } = inner else { return None };
    let Sx::Member { obj, prop } = callee.as_ref() else { return None };
    if prop != "reduce" || args.len() != 2 {
        return None;
    }
    let Sx::Num(base) = &args[1] else { return None };
    let reduced = match obj.as_ref() {
        Sx::Call { callee: mc, .. } => {
            let Sx::Member { prop: mp, obj: mobj } = mc.as_ref() else { return None };
            if mp != "map" {
                return None;
            }
            mobj.as_ref()
        }
        other => other,
    };
    let Sx::Ref(name) = reduced else { return None };
    let mut items: Option<Vec<Sx>> = None;
    harvest(body, &mut |s| {
        if items.is_some() {
            return;
        }
        if let Sx::Var { name: vn, value } = s
            && vn == name
            && let Sx::Arr(arr) = value.as_ref()
        {
            items = Some(arr.clone());
        }
    });
    let arr = items?;
    if arr.is_empty() {
        let mut pushed: Vec<Sx> = Vec::new();
        harvest(body, &mut |s| {
            if let Sx::Call { callee: pc, args: pargs } = s
                && let Sx::Member { obj: po, prop: pp } = pc.as_ref()
                && pp == "push"
                && let Sx::Ref(pn) = po.as_ref()
                && pn == name
                && !pargs.is_empty()
            {
                pushed.push(pargs[0].clone());
            }
        });
        if pushed.is_empty() {
            return None;
        }
        return Some((*base, pushed));
    }
    Some((*base, arr))
}

// Основной return пробы — тот, что возвращает String(...). Гарды (return "5465")
// в #jsa-пробе идут раньше; структурно выбираем String-вызов, иначе первый.
fn find_return_string(body: &[Sx]) -> Option<&Sx> {
    fn walk<'a>(body: &'a [Sx], string_ret: &mut Option<&'a Sx>, fallback: &mut Option<&'a Sx>) {
        for s in body {
            match s {
                Sx::Ret(Some(x)) => {
                    let e = unseq_last(x);
                    let is_string = matches!(e, Sx::Call { callee, args }
                        if !args.is_empty() && matches!(callee.as_ref(), Sx::Ref(r) if r == "String"));
                    if is_string && string_ret.is_none() {
                        *string_ret = Some(e);
                    } else if fallback.is_none() {
                        *fallback = Some(e);
                    }
                }
                Sx::Block(inner) | Sx::Seq(inner) => walk(inner, string_ret, fallback),
                Sx::If { c, a, .. } => {
                    walk(c, string_ret, fallback);
                    walk(a, string_ret, fallback);
                }
                Sx::Try { body: tb, handler, fin } => {
                    walk(tb, string_ret, fallback);
                    if let Some((_, hb)) = handler {
                        walk(hb, string_ret, fallback);
                    }
                    walk(fin, string_ret, fallback);
                }
                Sx::For { body: fb, .. } | Sx::While { body: fb, .. } => walk(fb, string_ret, fallback),
                Sx::Fn { body: fb, .. } => walk(fb, string_ret, fallback),
                _ => {}
            }
        }
    }
    let mut string_ret: Option<&Sx> = None;
    let mut fallback: Option<&Sx> = None;
    walk(body, &mut string_ret, &mut fallback);
    string_ret.or(fallback)
}


fn unseq_last(x: &Sx) -> &Sx {
    match x {
        Sx::Seq(v) if !v.is_empty() => unseq_last(v.last().expect("непустой Seq")),
        _ => x,
    }
}


fn reduce_chain(sx: &Sx) -> Option<(f64, Vec<Sx>)> {
    let Sx::Call { callee, args } = sx else { return None };
    let Sx::Member { obj, prop } = callee.as_ref() else { return None };
    if prop != "reduce" || args.len() != 2 {
        return None;
    }
    let Sx::Num(base) = &args[1] else { return None };
    let reduced = match obj.as_ref() {
        Sx::Call { callee: mc, .. } => {
            let Sx::Member { prop: mp, obj: mobj } = mc.as_ref() else { return None };
            if mp != "map" {
                return None;
            }
            mobj.as_ref()
        }
        other => other,
    };
    let Sx::Arr(items) = reduced else { return None };
    Some((*base, items.clone()))
}

fn render_sx(sx: &Sx) -> String {
    let mut s = String::new();
    render(sx, &mut s, 0);
    s
}

fn reads_user_agent(sx: &Sx) -> bool {
    let mut hit = false;
    walk_sx(sx, &mut |s| {
        if let Sx::Member { obj, prop } = s
            && prop == "userAgent"
            && let Sx::Ref(r) = obj.as_ref()
            && r == "navigator"
        {
            hit = true;
        }
    });
    hit
}

fn truthy(sx: &Sx) -> Option<bool> {
    match sx {
        Sx::Bool(b) => Some(*b),
        Sx::Num(n) => Some(!(n.is_nan() || *n == 0.0)),
        Sx::Str(s) => Some(!s.is_empty()),
        Sx::Undef | Sx::Null => Some(false),
        Sx::Arr(_) | Sx::Obj(_) | Sx::Fn { .. } | Sx::Class { .. } => Some(true),
        _ => None,
    }
}

struct Deob<'a> {
    strings: &'a [String],
    st: &'a Statics,
    scopes: Vec<HashMap<String, Sx>>,
    mutated: HashMap<String, u32>,
    depth: u32,
}

impl<'a> Deob<'a> {
    fn lookup(&self, name: &str) -> Option<&Sx> {
        for sc in self.scopes.iter().rev() {
            if let Some(v) = sc.get(name) {
                return Some(v);
            }
        }
        None
    }

    fn bind(&mut self, name: String, v: Sx) {
        if let Some(sc) = self.scopes.last_mut() {
            sc.insert(name, v);
        }
    }

    fn decode(&self, name: &str, arg: f64) -> Option<String> {
        let dname = resolve_alias(self.st, name)?;
        let d = *self.st.decoders.get(dname)?;
        let n = self.strings.len();
        let idx = mod_i64(arg as i64 - d as i64, n);
        self.strings.get(idx).cloned()
    }

    fn subst(&self, name: &str) -> Sx {
        let mut cur: Option<&str> = None;
        for _ in 0..16 {
            let key = cur.unwrap_or(name);
            if self.mutated.get(key).copied().unwrap_or(0) > 1 {
                return Sx::Ref(key.to_string());
            }
            match self.lookup(key) {
                Some(v @ (Sx::Num(_) | Sx::Str(_) | Sx::Bool(_) | Sx::Null | Sx::Undef)) => return v.clone(),
                Some(v @ (Sx::Member { .. } | Sx::Index { .. } | Sx::Call { .. } | Sx::New { .. })) => return v.clone(),
                Some(Sx::Ref(alias)) if alias != key => {
                    if self.lookup(alias).is_none() {
                        return Sx::Ref(alias.clone());
                    }
                    cur = Some(alias);
                }
                _ => return Sx::Ref(key.to_string()),
            }
        }
        Sx::Ref(name.to_string())
    }

    fn push_scope(&mut self) {
        self.scopes.push(HashMap::new());
    }

    fn pop_scope(&mut self) {
        self.scopes.pop();
    }

    fn stmts(&mut self, body: &'a [Statement<'a>]) -> Result<Vec<Sx>, FlowErr> {
        let mut out = Vec::with_capacity(body.len());
        for s in body {
            if let Some(x) = self.stmt(s)? {
                out.push(x);
            }
        }
        Ok(out)
    }

    fn stmt(&mut self, s: &'a Statement<'a>) -> Result<Option<Sx>, FlowErr> {
        if self.depth > 64 {
            return Err(FlowErr::Read("превышена глубина вложенности".into()));
        }
        self.depth += 1;
        let r = self.stmt_inner(s);
        self.depth -= 1;
        r
    }

    fn stmt_inner(&mut self, s: &'a Statement<'a>) -> Result<Option<Sx>, FlowErr> {
        match s {
            Statement::ExpressionStatement(e) => Ok(Some(self.expr(&e.expression)?)),
            Statement::VariableDeclaration(v) => {
                let mut out = Vec::new();
                for d in &v.declarations {
                    let Some(name) = binding_name(&d.id) else {
                        return Err(FlowErr::Read("деструктуризация вне модели".into()));
                    };
                    let val = match &d.init {
                        Some(i) => self.expr(i)?,
                        None => Sx::Undef,
                    };
                    *self.mutated.entry(name.clone()).or_insert(0) += 1;
                    self.bind(name.clone(), val.clone());
                    out.push(Sx::Var { name, value: Box::new(val) });
                }
                Ok(Some(Sx::Seq(out)))
            }
            Statement::FunctionDeclaration(f) => {
                let Some(nm) = f.id.as_ref().map(|i| i.name.to_string()) else { return Ok(None) };
                if self.lookup(&nm).is_some() {
                    return Ok(None);
                }
                let params = f.params.items.iter().filter_map(|p| binding_name(&p.pattern)).collect();
                let b = f.body.as_ref().map(|x| x.statements.as_slice()).unwrap_or(&[]);
                self.push_scope();
                let inner = self.stmts(b)?;
                self.pop_scope();
                self.bind(nm.clone(), Sx::Fn { params, body: inner, arrow: false });
                Ok(None)
            }
            Statement::ReturnStatement(r) => Ok(Some(Sx::Ret(match &r.argument {
                Some(a) => Some(Box::new(self.expr(a)?)),
                None => None,
            }))),
            Statement::BlockStatement(b) => Ok(Some(Sx::Block(self.block(&b.body)?))),
            Statement::IfStatement(i) => {
                let t = self.expr(&i.test)?;
                if let Some(b) = truthy(&t) {
                    let branch = if b {
                        &i.consequent
                    } else {
                        match &i.alternate {
                            Some(a) => a,
                            None => return Ok(None),
                        }
                    };
                    return Ok(Some(Sx::Seq(self.one(branch)?)));
                }
                let c = self.one(&i.consequent)?;
                let a = match &i.alternate {
                    Some(x) => self.one(x)?,
                    None => vec![],
                };
                Ok(Some(Sx::If { t: Box::new(t), c, a }))
            }
            Statement::WhileStatement(w) => {
                let t = self.expr(&w.test)?;
                let body = self.one(&w.body)?;
                Ok(Some(Sx::While { t: Box::new(t), body }))
            }
            Statement::ForStatement(fs) => {
                let init = match &fs.init {
                    Some(ast::ForStatementInit::VariableDeclaration(v)) => {
                        let mut out = Vec::new();
                        for d in &v.declarations {
                            let Some(name) = binding_name(&d.id) else {
                                return Err(FlowErr::Read("for-init деструктуризация".into()));
                            };
                            let val = match &d.init {
                                Some(i) => self.expr(i)?,
                                None => Sx::Undef,
                            };
                            *self.mutated.entry(name.clone()).or_insert(0) += 1;
                            self.bind(name.clone(), val.clone());
                            out.push(Sx::Var { name, value: Box::new(val) });
                        }
                        Some(Box::new(Sx::Seq(out)))
                    }
                    other => match other.as_ref().and_then(|i| i.as_expression()) {
                        Some(e) => Some(Box::new(self.expr(e)?)),
                        None => None,
                    },
                };
                let t = fs.test.as_ref().map(|x| self.expr(x)).transpose()?.map(Box::new);
                let u = fs.update.as_ref().map(|x| self.expr(x)).transpose()?.map(Box::new);
                let body = self.one(&fs.body)?;
                Ok(Some(Sx::For { init, t, u, body }))
            }
            Statement::TryStatement(t) => {
                let body = self.block(&t.block.body)?;
                let handler = match &t.handler {
                    Some(h) => {
                        let name = h.param.as_ref().and_then(|p| binding_name(&p.pattern)).unwrap_or_else(|| "_".into());
                        self.push_scope();
                        let hb = self.block(&h.body.body)?;
                        self.pop_scope();
                        Some((name, hb))
                    }
                    None => None,
                };
                let fin = match &t.finalizer {
                    Some(fb) => self.block(&fb.body)?,
                    None => vec![],
                };
                Ok(Some(Sx::Try { body, handler, fin }))
            }
            Statement::ThrowStatement(t) => Ok(Some(Sx::Throw(Box::new(self.expr(&t.argument)?)))),
            Statement::BreakStatement(_) => Ok(Some(Sx::Break)),
            Statement::ClassDeclaration(c) => {
                let name = c.id.as_ref().map(|i| i.name.to_string()).unwrap_or_default();
                let sup = c.heritage_expression().map(|x| self.expr(x)).transpose()?.map(Box::new);
                self.bind(name.clone(), Sx::Class { name: name.clone(), super_: sup.clone() });
                Ok(Some(Sx::Class { name, super_: sup }))
            }
            other => Err(FlowErr::Read(format!("statement @{}", other.span().start))),
        }
    }

    fn one(&mut self, s: &'a Statement<'a>) -> Result<Vec<Sx>, FlowErr> {
        match s {
            Statement::BlockStatement(b) => self.block(&b.body),
            other => Ok(self.stmt(other)?.into_iter().collect()),
        }
    }

    fn block(&mut self, body: &'a [Statement<'a>]) -> Result<Vec<Sx>, FlowErr> {
        self.push_scope();
        let r = self.stmts(body);
        self.pop_scope();
        r
    }

    fn expr(&mut self, e: &'a Expression<'a>) -> Result<Sx, FlowErr> {
        if self.depth > 64 {
            return Err(FlowErr::Read("превышена глубина выражения".into()));
        }
        self.depth += 1;
        let r = self.expr_inner(e);
        self.depth -= 1;
        r
    }

    fn expr_inner(&mut self, e: &'a Expression<'a>) -> Result<Sx, FlowErr> {
        match unwrap_parens(e) {
            Expression::NumericLiteral(n) => Ok(Sx::Num(n.value)),
            Expression::StringLiteral(s) => Ok(Sx::Str(s.value.to_string())),
            Expression::BooleanLiteral(b) => Ok(Sx::Bool(b.value)),
            Expression::NullLiteral(_) => Ok(Sx::Null),
            Expression::ThisExpression(_) => Ok(Sx::Ref("this".into())),
            Expression::Identifier(i) => {
                let nm = i.name.as_str();
                if nm == "undefined" {
                    return Ok(Sx::Undef);
                }
                Ok(self.subst(nm))
            }
            Expression::StaticMemberExpression(m) => {
                let obj = self.expr(&m.object)?;
                Ok(Sx::Member { obj: Box::new(obj), prop: m.property.name.to_string() })
            }
            Expression::ComputedMemberExpression(m) => {
                let obj = self.expr(&m.object)?;
                let idx = self.expr(&m.expression)?;
                if let Sx::Str(p) = &idx {
                    return Ok(Sx::Member { obj: Box::new(obj), prop: p.clone() });
                }
                Ok(Sx::Index { obj: Box::new(obj), idx: Box::new(idx) })
            }
            Expression::CallExpression(c) => self.call(c),
            Expression::NewExpression(n) => {
                let callee = self.expr(&n.callee)?;
                let mut args = Vec::new();
                for a in &n.arguments {
                    let Some(x) = a.as_expression() else {
                        return Err(FlowErr::Read("spread в new".into()));
                    };
                    args.push(self.expr(x)?);
                }
                Ok(Sx::New { callee: Box::new(callee), args })
            }
            Expression::UnaryExpression(u) => {
                let a = self.expr(&u.argument)?;
                let op = match u.operator {
                    ast::UnaryOperator::LogicalNot => "!",
                    ast::UnaryOperator::UnaryNegation => "-",
                    ast::UnaryOperator::UnaryPlus => "+",
                    ast::UnaryOperator::BitwiseNot => "~",
                    ast::UnaryOperator::Typeof => "typeof",
                    ast::UnaryOperator::Void => "void",
                    ast::UnaryOperator::Delete => "delete",
                };
                Ok(fold_un(op, a))
            }
            Expression::UpdateExpression(u) => {
                let nm = match &u.argument {
                    ast::SimpleAssignmentTarget::AssignmentTargetIdentifier(i) => i.name.to_string(),
                    _ => return Err(FlowErr::Read("цель ++ вне модели".into())),
                };
                *self.mutated.entry(nm.clone()).or_insert(0) += 1;
                let op = match u.operator {
                    ast::UpdateOperator::Increment => "++",
                    ast::UpdateOperator::Decrement => "--",
                };
                Ok(Sx::Assign { target: Box::new(Sx::Ref(nm)), op, value: Box::new(Sx::Num(1.0)) })
            }
            Expression::BinaryExpression(b) => {
                let l = self.expr(&b.left)?;
                let r = self.expr(&b.right)?;
                Ok(fold_bin(binop_of(b.operator), l, r))
            }
            Expression::LogicalExpression(l) => {
                let lv = self.expr(&l.left)?;
                let rv = self.expr(&l.right)?;
                let op = match l.operator {
                    ast::LogicalOperator::And => "&&",
                    ast::LogicalOperator::Or => "||",
                    ast::LogicalOperator::Coalesce => "??",
                };
                if let Some(b) = truthy(&lv) {
                    return Ok(match op {
                        "&&" => if b { rv } else { lv },
                        "||" => if b { lv } else { rv },
                        _ => Sx::Log { op, l: Box::new(lv), r: Box::new(rv) },
                    });
                }
                Ok(Sx::Log { op, l: Box::new(lv), r: Box::new(rv) })
            }
            Expression::ConditionalExpression(c) => {
                let t = self.expr(&c.test)?;
                let a = self.expr(&c.consequent)?;
                let b = self.expr(&c.alternate)?;
                if let Some(v) = truthy(&t) {
                    return Ok(if v { a } else { b });
                }
                Ok(Sx::Cond { t: Box::new(t), c: Box::new(a), a: Box::new(b) })
            }
            Expression::AssignmentExpression(a) => {
                let val = self.expr(&a.right)?;
                let tgt = match &a.left {
                    ast::AssignmentTarget::AssignmentTargetIdentifier(t) => {
                        let nm = t.name.to_string();
                        *self.mutated.entry(nm.clone()).or_insert(0) += 1;
                        self.bind(nm.clone(), val.clone());
                        Sx::Ref(nm)
                    }
                    ast::AssignmentTarget::StaticMemberExpression(m) => {
                        let obj = self.expr(&m.object)?;
                        Sx::Member { obj: Box::new(obj), prop: m.property.name.to_string() }
                    }
                    ast::AssignmentTarget::ComputedMemberExpression(m) => {
                        let obj = self.expr(&m.object)?;
                        let idx = self.expr(&m.expression)?;
                        if let Sx::Str(p) = &idx {
                            Sx::Member { obj: Box::new(obj), prop: p.clone() }
                        } else {
                            Sx::Index { obj: Box::new(obj), idx: Box::new(idx) }
                        }
                    }
                    _ => return Err(FlowErr::Read("цель присваивания вне модели".into())),
                };
                let op = match a.operator {
                    ast::AssignmentOperator::Assign => "=",
                    ast::AssignmentOperator::Addition => "+=",
                    ast::AssignmentOperator::Subtraction => "-=",
                    ast::AssignmentOperator::Multiplication => "*=",
                    ast::AssignmentOperator::Division => "/=",
                    ast::AssignmentOperator::Remainder => "%=",
                    ast::AssignmentOperator::BitwiseXOR => "^=",
                    ast::AssignmentOperator::BitwiseAnd => "&=",
                    ast::AssignmentOperator::BitwiseOR => "|=",
                    _ => "?=",
                };
                Ok(Sx::Assign { target: Box::new(tgt), op, value: Box::new(val) })
            }
            Expression::SequenceExpression(s) => {
                let mut out = Vec::new();
                for x in &s.expressions {
                    out.push(self.expr(x)?);
                }
                Ok(if out.len() == 1 { out.pop().unwrap_or(Sx::Undef) } else { Sx::Seq(out) })
            }
            Expression::ArrayExpression(arr) => {
                let mut out = Vec::with_capacity(arr.elements.len());
                for el in &arr.elements {
                    let Some(x) = el.as_expression() else {
                        return Err(FlowErr::Read("spread/дыра в массиве".into()));
                    };
                    out.push(self.expr(x)?);
                }
                Ok(Sx::Arr(out))
            }
            Expression::ObjectExpression(o) => {
                let mut out = Vec::new();
                for p in &o.properties {
                    let ast::ObjectPropertyKind::ObjectProperty(p) = p else {
                        return Err(FlowErr::Read("spread в объекте".into()));
                    };
                    let key = match &p.key {
                        ast::PropertyKey::StaticIdentifier(i) => i.name.to_string(),
                        ast::PropertyKey::StringLiteral(s) => s.value.to_string(),
                        ast::PropertyKey::NumericLiteral(nn) => crate::core::jsnum::format_js_num(nn.value),
                        k => {
                            let Some(ke) = k.as_expression() else {
                                return Err(FlowErr::Read("ключ объекта вне модели".into()));
                            };
                            match self.expr(ke)? {
                                Sx::Str(s) => s,
                                Sx::Num(x) => crate::core::jsnum::format_js_num(x),
                                _ => return Err(FlowErr::Read("вычисляемый ключ объекта".into())),
                            }
                        }
                    };
                    out.push((key, self.expr(&p.value)?));
                }
                Ok(Sx::Obj(out))
            }
            Expression::AwaitExpression(a) => self.expr(&a.argument),
            Expression::FunctionExpression(fe) => {
                let params = fe.params.items.iter().filter_map(|p| binding_name(&p.pattern)).collect();
                self.push_scope();
                for param in &fe.params.items {
                    if let Some(nm) = binding_name(&param.pattern) {
                        self.bind(nm.clone(), Sx::Ref(nm));
                    }
                }
                let body = match &fe.body {
                    Some(b) => self.stmts(b.statements.as_slice())?,
                    None => vec![],
                };
                self.pop_scope();
                Ok(Sx::Fn { params, body, arrow: false })
            }
            Expression::ArrowFunctionExpression(ae) => {
                let params = ae.params.items.iter().filter_map(|p| binding_name(&p.pattern)).collect();
                self.push_scope();
                for param in &ae.params.items {
                    if let Some(nm) = binding_name(&param.pattern) {
                        self.bind(nm.clone(), Sx::Ref(nm));
                    }
                }
                let body = if let Some(e) = ae.get_expression() {
                    vec![Sx::Ret(Some(Box::new(self.expr(e)?)))]
                } else if let Some(fb) = ae.get_function_body() {
                    self.stmts(fb.statements.as_slice())?
                } else {
                    vec![]
                };
                self.pop_scope();
                Ok(Sx::Fn { params, body, arrow: true })
            }
            Expression::ClassExpression(c) => {
                let name = c.id.as_ref().map(|i| i.name.to_string()).unwrap_or_default();
                let sup = c.heritage_expression().map(|x| self.expr(x)).transpose()?.map(Box::new);
                Ok(Sx::Class { name, super_: sup })
            }
            other => Err(FlowErr::Read(format!("выражение @{}", other.span().start))),
        }
    }

    fn call(&mut self, c: &'a ast::CallExpression<'a>) -> Result<Sx, FlowErr> {
        if let Some(nm) = ident_name(&c.callee)
            && resolve_alias(self.st, nm).is_some()
        {
            if let Some(arg) = c.arguments.first().and_then(|a| a.as_expression()).and_then(num_lit) {
                return match self.decode(nm, arg) {
                    Some(s) => Ok(Sx::Str(s)),
                    None => Err(FlowErr::Read(format!("декодер {nm}({arg}) вне массива"))),
                };
            }
        }
        if let Some(nm) = ident_name(&c.callee) {
            if matches!(nm, "parseInt" | "Number" | "String" | "Boolean") {
                let Some(a) = c.arguments.first().and_then(|x| x.as_expression()) else {
                    return Ok(Sx::Call { callee: Box::new(Sx::Ref(nm.to_string())), args: vec![] });
                };
                let v = self.expr(a)?;
                return Ok(match nm {
                    "parseInt" => match &v {
                        Sx::Str(s) => Sx::Num(crate::core::jsnum::js_parse_int(s)),
                        Sx::Num(x) => Sx::Num(*x),
                        _ => Sx::Call { callee: Box::new(Sx::Ref(nm.to_string())), args: vec![v] },
                    },
                    "Number" => match &v {
                        Sx::Str(s) => Sx::Num(js_to_number(s)),
                        Sx::Num(x) => Sx::Num(*x),
                        Sx::Bool(b) => Sx::Num(if *b { 1.0 } else { 0.0 }),
                        Sx::Undef => Sx::Num(f64::NAN),
                        Sx::Null => Sx::Num(0.0),
                        _ => Sx::Call { callee: Box::new(Sx::Ref(nm.to_string())), args: vec![v] },
                    },
                    "String" => match &v {
                        Sx::Str(_) => v,
                        Sx::Num(x) => Sx::Str(crate::core::jsnum::format_js_num(*x)),
                        Sx::Bool(b) => Sx::Str(if *b { "true".into() } else { "false".into() }),
                        Sx::Undef => Sx::Str("undefined".into()),
                        Sx::Null => Sx::Str("null".into()),
                        _ => Sx::Call { callee: Box::new(Sx::Ref(nm.to_string())), args: vec![v] },
                    },
                    _ => match truthy(&v) {
                        Some(b) => Sx::Bool(b),
                        None => Sx::Call { callee: Box::new(Sx::Ref(nm.to_string())), args: vec![v] },
                    },
                });
            }
        }
        let callee = self.expr(&c.callee)?;
        let mut args = Vec::new();
        for a in &c.arguments {
            let Some(x) = a.as_expression() else {
                return Err(FlowErr::Read("spread-аргумент".into()));
            };
            args.push(self.expr(x)?);
        }
        if let Sx::Member { obj, prop } = &callee {
            if prop == "charCodeAt"
                && args.len() == 1
                && let Sx::Str(s) = obj.as_ref()
                && let Sx::Num(i) = &args[0]
                && *i >= 0.0
            {
                let units: Vec<u16> = s.encode_utf16().collect();
                let idx = *i as usize;
                return Ok(if idx < units.len() { Sx::Num(f64::from(units[idx])) } else { Sx::Num(f64::NAN) });
            }
            if prop == "length" {
                match obj.as_ref() {
                    Sx::Str(s) => return Ok(Sx::Num(s.encode_utf16().count() as f64)),
                    Sx::Arr(v) => return Ok(Sx::Num(v.len() as f64)),
                    _ => {}
                }
            }
        }
        Ok(Sx::Call { callee: Box::new(callee), args })
    }
}

fn js_to_number(s: &str) -> f64 {
    let t = s.trim();
    if t.is_empty() {
        return 0.0;
    }
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return i64::from_str_radix(h, 16).map(|v| v as f64).unwrap_or(f64::NAN);
    }
    t.parse::<f64>().unwrap_or(f64::NAN)
}

fn binop_of(op: ast::BinaryOperator) -> &'static str {
    use ast::BinaryOperator as B;
    match op {
        B::Addition => "+",
        B::Subtraction => "-",
        B::Multiplication => "*",
        B::Division => "/",
        B::Remainder => "%",
        B::Exponential => "**",
        B::ShiftLeft => "<<",
        B::ShiftRight => ">>",
        B::ShiftRightZeroFill => ">>>",
        B::BitwiseAnd => "&",
        B::BitwiseOR => "|",
        B::BitwiseXOR => "^",
        B::Equality => "==",
        B::Inequality => "!=",
        B::StrictEquality => "===",
        B::StrictInequality => "!==",
        B::LessThan => "<",
        B::LessEqualThan => "<=",
        B::GreaterThan => ">",
        B::GreaterEqualThan => ">=",
        B::Instanceof => "instanceof",
        B::In => "in",
    }
}

fn fold_un(op: &'static str, a: Sx) -> Sx {
    match op {
        "!" => match truthy(&a) {
            Some(b) => Sx::Bool(!b),
            None => Sx::Un { op: "!", a: Box::new(a) },
        },
        "-" => match &a {
            Sx::Num(n) => Sx::Num(-n),
            _ => Sx::Un { op: "-", a: Box::new(a) },
        },
        "+" => match &a {
            Sx::Num(_) => a,
            Sx::Str(s) => Sx::Num(js_to_number(s)),
            _ => Sx::Un { op: "+", a: Box::new(a) },
        },
        "~" => match &a {
            Sx::Num(n) => Sx::Num(f64::from(!crate::core::jsnum::to_int32(*n))),
            _ => Sx::Un { op: "~", a: Box::new(a) },
        },
        "typeof" => {
            let t = match &a {
                Sx::Undef => "undefined",
                Sx::Null => "object",
                Sx::Bool(_) => "boolean",
                Sx::Num(_) => "number",
                Sx::Str(_) => "string",
                Sx::Fn { .. } => "function",
                Sx::Arr(_) | Sx::Obj(_) | Sx::Class { .. } => "object",
                _ => return Sx::Un { op: "typeof", a: Box::new(a) },
            };
            Sx::Str(t.to_string())
        }
        "void" => Sx::Undef,
        "delete" => Sx::Bool(true),
        _ => Sx::Un { op: "!", a: Box::new(a) },
    }
}

fn fold_bin(op: &'static str, l: Sx, r: Sx) -> Sx {
    use crate::core::jsnum::{to_int32, to_uint32};
    match op {
        "===" | "==" => {
            if let Some(b) = strict_eq(&l, &r) {
                return Sx::Bool(b);
            }
        }
        "!==" | "!=" => {
            if let Some(b) = strict_eq(&l, &r) {
                return Sx::Bool(!b);
            }
        }
        _ => {}
    }
    if let (Sx::Num(a), Sx::Num(b)) = (&l, &r) {
        let v: Option<f64> = match op {
            "+" => Some(a + b),
            "-" => Some(a - b),
            "*" => Some(a * b),
            "/" => Some(a / b),
            "%" => Some(a % b),
            "**" => Some(a.powf(*b)),
            "<<" => Some(f64::from(to_int32(*a).wrapping_shl(to_uint32(*b) & 31))),
            ">>" => Some(f64::from(to_int32(*a).wrapping_shr(to_uint32(*b) & 31))),
            ">>>" => Some(f64::from(to_uint32(*a).wrapping_shr(to_uint32(*b) & 31))),
            "&" => Some(f64::from(to_int32(*a) & to_int32(*b))),
            "|" => Some(f64::from(to_int32(*a) | to_int32(*b))),
            "^" => Some(f64::from(to_int32(*a) ^ to_int32(*b))),
            _ => None,
        };
        if let Some(v) = v {
            return Sx::Num(v);
        }
        let cmp: Option<bool> = match op {
            "<" => Some(a < b),
            "<=" => Some(a <= b),
            ">" => Some(a > b),
            ">=" => Some(a >= b),
            _ => None,
        };
        if let Some(b) = cmp {
            return Sx::Bool(b);
        }
    }
    if op == "+" {
        if let (Sx::Str(a), Sx::Str(b)) = (&l, &r) {
            return Sx::Str(format!("{a}{b}"));
        }
        if let (Sx::Str(a), Sx::Num(b)) = (&l, &r) {
            return Sx::Str(format!("{a}{}", crate::core::jsnum::format_js_num(*b)));
        }
        if let (Sx::Num(a), Sx::Str(b)) = (&l, &r) {
            return Sx::Str(format!("{}{b}", crate::core::jsnum::format_js_num(*a)));
        }
    }
    Sx::Bin { op, l: Box::new(l), r: Box::new(r) }
}

fn strict_eq(l: &Sx, r: &Sx) -> Option<bool> {
    match (l, r) {
        (Sx::Num(a), Sx::Num(b)) => Some(a == b),
        (Sx::Str(a), Sx::Str(b)) => Some(a == b),
        (Sx::Bool(a), Sx::Bool(b)) => Some(a == b),
        (Sx::Undef, Sx::Undef) | (Sx::Null, Sx::Null) | (Sx::Undef, Sx::Null) | (Sx::Null, Sx::Undef) => Some(true),
        (Sx::Undef | Sx::Null | Sx::Bool(_), Sx::Num(_) | Sx::Str(_))
        | (Sx::Num(_) | Sx::Str(_), Sx::Undef | Sx::Null | Sx::Bool(_)) => Some(false),
        _ => None,
    }
}

pub fn render(sx: &Sx, out: &mut String, ind: usize) {
    let pad = "  ".repeat(ind);
    match sx {
        Sx::Num(n) => out.push_str(&crate::core::jsnum::format_js_num(*n)),
        Sx::Str(s) => out.push_str(&js_quote(s)),
        Sx::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Sx::Null => out.push_str("null"),
        Sx::Undef => out.push_str("undefined"),
        Sx::Ref(n) => out.push_str(n),
        Sx::Member { obj, prop } => {
            render(obj, out, ind);
            if ident_ok(prop) {
                out.push('.');
                out.push_str(prop);
            } else {
                out.push('[');
                out.push_str(&js_quote(prop));
                out.push(']');
            }
        }
        Sx::Index { obj, idx } => {
            render(obj, out, ind);
            out.push('[');
            render(idx, out, ind);
            out.push(']');
        }
        Sx::Call { callee, args } => {
            render(callee, out, ind);
            out.push('(');
            for (i, a) in args.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                render(a, out, ind);
            }
            out.push(')');
        }
        Sx::New { callee, args } => {
            out.push_str("new ");
            render(callee, out, ind);
            out.push('(');
            for (i, a) in args.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                render(a, out, ind);
            }
            out.push(')');
        }
        Sx::Bin { op, l, r } | Sx::Log { op, l, r } => {
            render(l, out, ind);
            out.push(' ');
            out.push_str(op);
            out.push(' ');
            render(r, out, ind);
        }
        Sx::Un { op, a } => {
            out.push_str(op);
            if matches!(*op, "typeof" | "delete" | "void") {
                out.push(' ');
            }
            render(a, out, ind);
        }
        Sx::Cond { t, c, a } => {
            render(t, out, ind);
            out.push_str(" ? ");
            render(c, out, ind);
            out.push_str(" : ");
            render(a, out, ind);
        }
        Sx::Arr(v) => {
            out.push('[');
            for (i, x) in v.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                render(x, out, ind);
            }
            out.push(']');
        }
        Sx::Obj(kv) => {
            out.push('{');
            for (i, (k, x)) in kv.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                if ident_ok(k) {
                    out.push_str(k);
                } else {
                    out.push_str(&js_quote(k));
                }
                out.push_str(": ");
                render(x, out, ind);
            }
            out.push('}');
        }
        Sx::Fn { params, body, arrow } => {
            if *arrow {
                out.push('(');
                out.push_str(&params.join(", "));
                out.push_str(") => {\n");
            } else {
                out.push_str("function(");
                out.push_str(&params.join(", "));
                out.push_str(") {\n");
            }
            for s in body {
                render_stmt(s, out, ind + 1);
            }
            out.push_str(&pad);
            out.push('}');
        }
        Sx::Class { name, super_ } => {
            out.push_str("class ");
            out.push_str(name);
            if let Some(s) = super_ {
                out.push_str(" extends ");
                render(s, out, ind);
            }
            out.push_str(" {}");
        }
        Sx::Seq(v) => {
            for (i, x) in v.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                render(x, out, ind);
            }
        }
        Sx::Block(v) => {
            out.push_str("{\n");
            for s in v {
                render_stmt(s, out, ind + 1);
            }
            out.push_str(&pad);
            out.push('}');
        }
        Sx::Var { name, value } => {
            out.push_str("const ");
            out.push_str(name);
            out.push_str(" = ");
            render(value, out, ind);
            out.push(';');
        }
        Sx::Assign { target, op, value } => {
            render(target, out, ind);
            out.push(' ');
            out.push_str(op);
            out.push(' ');
            render(value, out, ind);
            out.push(';');
        }
        Sx::If { t, c, a } => {
            out.push_str("if (");
            render(t, out, ind);
            out.push_str(") {\n");
            for s in c {
                render_stmt(s, out, ind + 1);
            }
            if !a.is_empty() {
                out.push_str(&pad);
                out.push_str("} else {\n");
                for s in a {
                    render_stmt(s, out, ind + 1);
                }
            }
            out.push_str(&pad);
            out.push('}');
        }
        Sx::For { init, t, u, body } => {
            out.push_str("for (");
            if let Some(x) = init {
                render(x, out, ind);
            }
            out.push(';');
            if let Some(x) = t {
                out.push(' ');
                render(x, out, ind);
            }
            out.push(';');
            if let Some(x) = u {
                out.push(' ');
                render(x, out, ind);
            }
            out.push_str(") {\n");
            for s in body {
                render_stmt(s, out, ind + 1);
            }
            out.push_str(&pad);
            out.push('}');
        }
        Sx::While { t, body } => {
            out.push_str("while (");
            render(t, out, ind);
            out.push_str(") {\n");
            for s in body {
                render_stmt(s, out, ind + 1);
            }
            out.push_str(&pad);
            out.push('}');
        }
        Sx::Try { body, handler, fin } => {
            out.push_str("try {\n");
            for s in body {
                render_stmt(s, out, ind + 1);
            }
            out.push_str(&pad);
            out.push('}');
            if let Some((nm, hb)) = handler {
                out.push_str(" catch (");
                out.push_str(nm);
                out.push_str(") {\n");
                for s in hb {
                    render_stmt(s, out, ind + 1);
                }
                out.push_str(&pad);
                out.push('}');
            }
            if !fin.is_empty() {
                out.push_str(" finally {\n");
                for s in fin {
                    render_stmt(s, out, ind + 1);
                }
                out.push_str(&pad);
                out.push('}');
            }
        }
        Sx::Ret(None) => out.push_str("return;"),
        Sx::Ret(Some(x)) => {
            out.push_str("return ");
            render(x, out, ind);
            out.push(';');
        }
        Sx::Throw(x) => {
            out.push_str("throw ");
            render(x, out, ind);
            out.push(';');
        }
        Sx::Break => out.push_str("break;"),
        Sx::Continue => out.push_str("continue;"),
        Sx::Empty => {}
    }
}

pub fn render_stmt(sx: &Sx, out: &mut String, ind: usize) {
    if matches!(sx, Sx::Empty) {
        return;
    }
    out.push_str(&"  ".repeat(ind));
    render(sx, out, ind);
    if !matches!(
        sx,
        Sx::If { .. }
            | Sx::For { .. }
            | Sx::While { .. }
            | Sx::Try { .. }
            | Sx::Block(_)
            | Sx::Var { .. }
            | Sx::Assign { .. }
            | Sx::Ret(_)
            | Sx::Throw(_)
            | Sx::Break
            | Sx::Continue
            | Sx::Fn { .. }
            | Sx::Class { .. }
    ) {
        out.push(';');
    }
    out.push('\n');
}

fn ident_ok(s: &str) -> bool {
    !s.is_empty()
        && s.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == '$')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

fn js_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
