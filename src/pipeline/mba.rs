use std::cmp::Ordering;
use std::str::FromStr;

use egg::{rewrite as rw, Analysis, DidMerge, EGraph, Extractor, Id, RecExpr, Runner, Symbol};

use crate::pipeline::ops::{Op, Program};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct F(pub f64);

impl Eq for F {}

impl PartialOrd for F {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for F {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.total_cmp(&other.0)
    }
}

impl std::hash::Hash for F {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_bits().hash(state);
    }
}

impl FromStr for F {
    type Err = std::num::ParseFloatError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<f64>().map(F)
    }
}

impl std::fmt::Display for F {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.fract() == 0.0 && self.0.abs() < 1e15 {
            write!(f, "{}", self.0 as i64)
        } else {
            write!(f, "{}", self.0)
        }
    }
}

#[inline]
fn to_i32(x: f64) -> i64 {
    let m = x.trunc();
    if !m.is_finite() {
        return 0;
    }
    let m32 = m.rem_euclid(4_294_967_296.0);
    if m32 >= 2_147_483_648.0 {
        (m32 - 4_294_967_296.0) as i64
    } else {
        m32 as i64
    }
}

#[inline]
fn to_u32(x: f64) -> u32 {
    let m = x.trunc();
    if !m.is_finite() {
        return 0;
    }
    m.rem_euclid(4_294_967_296.0) as u32
}

egg::define_language! {
    pub enum Math {
        "+" = Add([Id; 2]),
        "-" = Sub([Id; 2]),
        "*" = Mul([Id; 2]),
        "/" = Div([Id; 2]),
        "%" = Mod([Id; 2]),
        "neg" = Neg([Id; 1]),
        "^" = BitXor([Id; 2]),
        "&" = BitAnd([Id; 2]),
        "|" = BitOr([Id; 2]),
        "<<" = Shl([Id; 2]),
        ">>" = Shr([Id; 2]),
        ">>>" = Ushr([Id; 2]),
        Num(F),
        Var(Symbol),
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ConstantFold;

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Const(pub Option<f64>);

impl Analysis<Math> for ConstantFold {
    type Data = Const;

    fn make(egraph: &mut EGraph<Math, Self>, enode: &Math, _id: Id) -> Self::Data {
        let pair = |a: &Id, b: &Id| -> Option<(f64, f64)> {
            let x = |i: &Id| egraph[*i].data.0;
            Some((x(a)?, x(b)?))
        };
        let v = match enode {
            Math::Num(F(n)) => return Const(Some(*n)),
            Math::Add([a, b]) => pair(a, b).map(|(x, y)| x + y),
            Math::Sub([a, b]) => pair(a, b).map(|(x, y)| x - y),
            Math::Mul([a, b]) => pair(a, b).map(|(x, y)| x * y),
            Math::Div([a, b]) => pair(a, b).map(|(x, y)| x / y),
            Math::Mod([a, b]) => pair(a, b).map(|(x, y)| x % y),
            Math::Neg([a]) => egraph[*a].data.0.map(|x| -x),
            Math::BitXor([a, b]) => pair(a, b).map(|(x, y)| (to_i32(x) ^ to_i32(y)) as f64),
            Math::BitAnd([a, b]) => pair(a, b).map(|(x, y)| (to_i32(x) & to_i32(y)) as f64),
            Math::BitOr([a, b]) => pair(a, b).map(|(x, y)| (to_i32(x) | to_i32(y)) as f64),
            Math::Shl([a, b]) => pair(a, b).map(|(x, y)| (to_i32(x) << (to_u32(y) & 31)) as f64),
            Math::Shr([a, b]) => pair(a, b).map(|(x, y)| (to_i32(x) >> (to_u32(y) & 31)) as f64),
            Math::Ushr([a, b]) => pair(a, b).map(|(x, y)| ((to_i32(x) as u64) >> (to_u32(y) & 31)) as f64),
            Math::Var(_) => None,
        };
        Const(v)
    }

    fn merge(&mut self, a: &mut Self::Data, b: Self::Data) -> DidMerge {
        egg::merge_option(&mut a.0, b.0, |_, _| DidMerge(false, true))
    }
}

fn comm_guard(a: &str, b: &str) -> impl Fn(&mut EGraph<Math, ConstantFold>, Id, &egg::Subst) -> bool + Send + Sync + 'static {
    let a: egg::Var = a.parse().unwrap();
    let b: egg::Var = b.parse().unwrap();
    move |_, _, subst| subst[b] < subst[a]
}

fn rules() -> Vec<egg::Rewrite<Math, ConstantFold>> {
    vec![
        rw!("add-0-l"; "(+ ?x 0)" => "?x"),
        rw!("add-0-r"; "(+ 0 ?x)" => "?x"),
        rw!("sub-0"; "(- ?x 0)" => "?x"),
        rw!("mul-1-l"; "(* ?x 1)" => "?x"),
        rw!("mul-1-r"; "(* 1 ?x)" => "?x"),
        rw!("div-1"; "(/ ?x 1)" => "?x"),
        rw!("neg-neg"; "(neg (neg ?x))" => "?x"),
        rw!("neg-0"; "(neg 0)" => "0"),
        rw!("sub-add"; "(- ?a ?b)" => "(+ ?a (neg ?b))"),
        rw!("mul-neg-l"; "(* (neg ?x) ?y)" => "(neg (* ?x ?y))"),
        rw!("mul-neg-r"; "(* ?y (neg ?x))" => "(neg (* ?y ?x))"),
        rw!("xor-0-l"; "(^ ?x 0)" => "?x"),
        rw!("xor-0-r"; "(^ 0 ?x)" => "?x"),
        rw!("xor-self"; "(^ ?x ?x)" => "0"),
        rw!("xor-cancel"; "(^ (^ ?a ?b) ?b)" => "?a"),
        rw!("xor-assoc"; "(^ (^ ?a ?b) ?c)" => "(^ ?a (^ ?b ?c))"),
        rw!("xor-comm"; "(^ ?a ?b)" => "(^ ?b ?a)" if comm_guard("?a", "?b")),
        rw!("and-self"; "(& ?x ?x)" => "?x"),
        rw!("and-0"; "(& ?x 0)" => "0"),
        rw!("and-m1"; "(& ?x -1)" => "?x"),
        rw!("and-comm"; "(& ?a ?b)" => "(& ?b ?a)" if comm_guard("?a", "?b")),
        rw!("or-self"; "(| ?x ?x)" => "?x"),
        rw!("or-0"; "(| ?x 0)" => "?x"),
        rw!("or-comm"; "(| ?a ?b)" => "(| ?b ?a)" if comm_guard("?a", "?b")),
        rw!("shl-0"; "(<< ?x 0)" => "?x"),
        rw!("shr-0"; "(>> ?x 0)" => "?x"),
        rw!("ushr-0"; "(>>> ?x 0)" => "?x"),
        rw!("mba-or-minus-and"; "(- (| ?a ?b) (& ?a ?b))" => "(^ ?a ?b)"),
        rw!("mba-or-add-and"; "(+ (& ?a ?b) (^ ?a ?b))" => "(| ?a ?b)"),
    ]
}

#[derive(Debug, Clone)]
pub struct Report {
    pub raw_ops: usize,
    pub canonical_ops: usize,
    pub template_hash: u64,
    pub family_hash: u64,
    pub family: String,
    pub full_hash: u64,
    pub canonical_sexpr: String,
}

#[derive(Debug, Clone)]
pub struct SimplifyOut {
    pub program: Program,
    pub slot_symbols: Vec<String>,
    pub report: Report,
}

pub fn simplify(expr: &RecExpr<Math>) -> SimplifyOut {
    let raw_ops = expr.as_ref().len();
    let runner: Runner<Math, ConstantFold, ()> = Runner::new(ConstantFold)
        .with_iter_limit(30)
        .with_node_limit(120_000)
        .with_expr(expr)
        .run(&rules());
    let root = runner.roots[0];
    let (_cost, canonical) = Extractor::new(&runner.egraph, egg::AstSize).find_best(root);

    let mut var_slot = std::collections::HashMap::<Symbol, usize>::new();
    let mut program = Program::default();
    let mut order: Vec<Symbol> = Vec::new();
    emit_ops(canonical.as_ref(), canonical.as_ref().len() - 1, &mut program, &mut var_slot, &mut order);
    program.n_vars = var_slot.len();

    let (terms, raw_terms) = structural_terms(canonical.as_ref());
    let (family, template_hash) = family_and_template(&terms, raw_terms);
    let canonical_sexpr = canonical.to_string();
    let report = Report {
        raw_ops,
        canonical_ops: program.ops.len(),
        template_hash,
        family_hash: xxh3(family.as_bytes()),
        family,
        full_hash: xxh3(canonical_sexpr.as_bytes()),
        canonical_sexpr,
    };
    SimplifyOut { program, slot_symbols: order.iter().map(|s| s.as_str().to_string()).collect(), report }
}

fn emit_ops(
    nodes: &[Math],
    idx: usize,
    program: &mut Program,
    var_slot: &mut std::collections::HashMap<Symbol, usize>,
    order: &mut Vec<Symbol>,
) {
    match &nodes[idx] {
        Math::Num(F(n)) => program.ops.push(Op::Const(*n)),
        Math::Var(s) => {
            let slot = match var_slot.get(s) {
                Some(&v) => v,
                None => {
                    let next = var_slot.len();
                    var_slot.insert(*s, next);
                    order.push(*s);
                    next
                }
            };
            program.ops.push(Op::Var(slot as u8));
        }
        Math::Add([a, b]) | Math::Sub([a, b]) | Math::Mul([a, b]) | Math::Div([a, b])
        | Math::Mod([a, b])
        | Math::BitXor([a, b]) | Math::BitAnd([a, b]) | Math::BitOr([a, b])
        | Math::Shl([a, b]) | Math::Shr([a, b]) | Math::Ushr([a, b]) => {
            emit_ops(nodes, usize::from(*a), program, var_slot, order);
            emit_ops(nodes, usize::from(*b), program, var_slot, order);
            program.ops.push(match &nodes[idx] {
                Math::Add(_) => Op::Add,
                Math::Sub(_) => Op::Sub,
                Math::Mul(_) => Op::Mul,
                Math::Div(_) => Op::Div,
                Math::Mod(_) => Op::Mod,
                Math::BitXor(_) => Op::Xor,
                Math::BitAnd(_) => Op::And,
                Math::BitOr(_) => Op::Or,
                Math::Shl(_) => Op::Shl,
                Math::Shr(_) => Op::Shr,
                _ => Op::Ushr,
            });
        }
        Math::Neg([a]) => {
            emit_ops(nodes, usize::from(*a), program, var_slot, order);
            program.ops.push(Op::Neg);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Term {
    num: Vec<u8>,
    den: Vec<u8>,
}

fn leaf_tag(node: &Math) -> u8 {
    match node {
        Math::Num(_) => b'N',
        Math::Var(_) => b'V',
        Math::Neg(_) => b'S',
        Math::BitXor(_) => b'x',
        Math::BitAnd(_) => b'a',
        Math::BitOr(_) => b'o',
        Math::Shl(_) => b'L',
        Math::Shr(_) => b'R',
        Math::Ushr(_) => b'U',
        Math::Mod(_) => b'm',
        _ => b'?',
    }
}

fn collect_product(nodes: &[Math], idx: usize, num: &mut Vec<u8>, den: &mut Vec<u8>) {
    match &nodes[idx] {
        Math::Mul([a, b]) => {
            collect_product(nodes, usize::from(*a), num, den);
            collect_product(nodes, usize::from(*b), num, den);
        }
        Math::Div([a, b]) => {
            collect_product(nodes, usize::from(*a), num, den);
            collect_product(nodes, usize::from(*b), den, num);
        }
        Math::Neg([a]) => {
            num.push(b'S');
            collect_product(nodes, usize::from(*a), num, den);
        }
        other => num.push(leaf_tag(other)),
    }
}

fn collect_sum(nodes: &[Math], idx: usize, neg: bool, out: &mut Vec<Term>) {
    match &nodes[idx] {
        Math::Add([a, b]) => {
            collect_sum(nodes, usize::from(*a), neg, out);
            collect_sum(nodes, usize::from(*b), neg, out);
        }
        Math::Sub([a, b]) => {
            collect_sum(nodes, usize::from(*a), neg, out);
            collect_sum(nodes, usize::from(*b), !neg, out);
        }
        _ => {
            let mut t = Term { num: Vec::new(), den: Vec::new() };
            collect_product(nodes, idx, &mut t.num, &mut t.den);
            if neg {
                t.num.push(b'S');
            }
            t.num.sort_unstable();
            t.den.sort_unstable();
            out.push(t);
        }
    }
}

fn structural_terms(nodes: &[Math]) -> (Vec<Term>, usize) {
    let mut terms = Vec::new();
    collect_sum(nodes, nodes.len() - 1, false, &mut terms);
    let raw = terms.len();
    terms.sort_unstable();
    terms.dedup_by(|a, b| {
        a.num == b.num && a.den == b.den
            || (a.num.last() == Some(&b'N')
                && b.num.last() == Some(&b'N')
                && a.num[..a.num.len() - 1] == b.num[..b.num.len() - 1]
                && a.den == b.den
                && (a.num.contains(&b'S') ^ b.num.contains(&b'S')))
    });
    (terms, raw)
}

fn family_and_template(terms: &[Term], raw_terms: usize) -> (String, u64) {
    let mut buf = Vec::new();
    let mut family_ok = raw_terms >= 4;
    for t in terms {
        buf.extend_from_slice(&t.num);
        if !t.den.is_empty() {
            buf.push(b'/');
            buf.extend_from_slice(&t.den);
        }
        buf.push(b'+');
        let known = |&c: &u8| matches!(c, b'S' | b'V' | b'N' | b'x' | b'a' | b'o' | b'L' | b'R' | b'U' | b'm');
        if !t.num.iter().all(known) || !t.den.iter().all(|&c| c == b'N') || !t.num.contains(&b'V') {
            family_ok = false;
        }
    }
    let template_hash = xxh3(&buf);
    if family_ok {
        ("duck-vqd-checksum-v1:sum_of_SVN_products".to_string(), template_hash)
    } else {
        (format!("DRIFT:{}", buf.len()), template_hash)
    }
}

fn xxh3(b: &[u8]) -> u64 {
    crate::core::xxh3_64(b)
}

pub fn var_name_for_arg(arg: f64) -> String {
    if arg.fract() == 0.0 && (0.0..1e9).contains(&arg) {
        format!("a{:x}", arg as i64)
    } else {
        format!("a{arg}")
    }
}
