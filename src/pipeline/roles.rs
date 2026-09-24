use std::collections::HashMap;

use oxc_ast::ast::{self, Expression};

use crate::pipeline::mba::{self, Math};
use crate::pipeline::ops::{Op, Program};

pub fn unwrap_parens<'a>(e: &'a Expression<'a>) -> &'a Expression<'a> {
    match e {
        Expression::ParenthesizedExpression(p) => unwrap_parens(&p.expression),
        other => other,
    }
}

pub fn ident_of<'a>(e: &'a Expression<'a>) -> Option<&'a str> {
    match e {
        Expression::Identifier(i) => Some(i.name.as_str()),
        _ => None,
    }
}

pub fn num_lit<'a>(e: &'a Expression<'a>) -> Option<f64> {
    match unwrap_parens(e) {
        Expression::NumericLiteral(n) => Some(n.value),
        Expression::UnaryExpression(u) if u.operator == ast::UnaryOperator::UnaryNegation => {
            num_lit(&u.argument).map(|v| -v)
        }
        Expression::BinaryExpression(b) => {
            let (l, r) = (num_lit(&b.left)?, num_lit(&b.right)?);
            fold_binop(l, b.operator, r)
        }
        _ => None,
    }
}

fn fold_binop(l: f64, op: ast::BinaryOperator, r: f64) -> Option<f64> {
    use ast::BinaryOperator as B;
    let i32v = |x: f64| crate::core::jsnum::to_int32(x);
    let u32v = |x: f64| crate::core::jsnum::to_uint32(x);
    Some(match op {
        B::Addition => l + r,
        B::Subtraction => l - r,
        B::Multiplication => l * r,
        B::Division => l / r,
        B::Remainder => l % r,
        B::BitwiseXOR => f64::from(i32v(l) ^ i32v(r)),
        B::BitwiseOR => f64::from(i32v(l) | i32v(r)),
        B::BitwiseAnd => f64::from(i32v(l) & i32v(r)),
        B::ShiftLeft => f64::from(i32v(l).wrapping_shl(u32v(r) & 31)),
        B::ShiftRight => f64::from(i32v(l).wrapping_shr(u32v(r) & 31)),
        _ => return None,
    })
}

pub struct TransErr(String);

impl std::fmt::Display for TransErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "перевод checksum: {}", self.0)
    }
}

pub struct Translator<'a> {
    is_dec: &'a dyn Fn(&str) -> Option<String>,
    ops: Vec<Op>,
    n_vars: usize,
    var_slot: HashMap<String, usize>,
    var_args: Vec<f64>,
    nodes: Vec<Math>,
}

pub struct Translated {
    pub program: Program,
    pub var_args: Vec<f64>,
    pub var_pairs: Vec<(String, f64)>,
    pub recexpr: egg::RecExpr<Math>,
}

impl<'a> Translator<'a> {
    pub fn new(is_dec: &'a dyn Fn(&str) -> Option<String>) -> Self {
        Self { is_dec, ops: Vec::new(), n_vars: 0, var_slot: HashMap::new(), var_args: Vec::new(), nodes: Vec::new() }
    }

    pub fn finish(self) -> Translated {
        let pairs = self
            .var_slot
            .into_iter()
            .map(|(k, slot)| (k.as_str().to_string(), self.var_args[slot]))
            .collect::<Vec<_>>();
        Translated {
            program: Program { ops: self.ops, n_vars: self.n_vars },
            var_args: self.var_args,
            var_pairs: pairs,
            recexpr: egg::RecExpr::from(self.nodes),
        }
    }

    pub fn expr(&mut self, e: &Expression) -> Result<usize, TransErr> {
        match e {
            Expression::NumericLiteral(n) => {
                self.nodes.push(Math::Num(mba::F(n.value)));
                self.ops.push(Op::Const(n.value));
                Ok(self.nodes.len() - 1)
            }
            Expression::ParenthesizedExpression(p) => self.expr(&p.expression),
            Expression::UnaryExpression(u) => match u.operator {
                ast::UnaryOperator::UnaryNegation => {
                    let c = self.expr(&u.argument)?;
                    self.nodes.push(Math::Neg([egg::Id::from(c)]));
                    self.ops.push(Op::Neg);
                    Ok(self.nodes.len() - 1)
                }
                ast::UnaryOperator::UnaryPlus => self.expr(&u.argument),
                op => Err(TransErr(format!("unary {op:?}"))),
            },
            Expression::BinaryExpression(b) => {
                let l = self.expr(&b.left)?;
                let r = self.expr(&b.right)?;
                use ast::BinaryOperator as B;
                let (node, op) = match b.operator {
                    B::Addition => (Math::Add([egg::Id::from(l), egg::Id::from(r)]), Op::Add),
                    B::Subtraction => (Math::Sub([egg::Id::from(l), egg::Id::from(r)]), Op::Sub),
                    B::Multiplication => (Math::Mul([egg::Id::from(l), egg::Id::from(r)]), Op::Mul),
                    B::Division => (Math::Div([egg::Id::from(l), egg::Id::from(r)]), Op::Div),
                    B::Remainder => (Math::Mod([egg::Id::from(l), egg::Id::from(r)]), Op::Mod),
                    B::BitwiseXOR => (Math::BitXor([egg::Id::from(l), egg::Id::from(r)]), Op::Xor),
                    B::BitwiseAnd => (Math::BitAnd([egg::Id::from(l), egg::Id::from(r)]), Op::And),
                    B::BitwiseOR => (Math::BitOr([egg::Id::from(l), egg::Id::from(r)]), Op::Or),
                    B::ShiftLeft => (Math::Shl([egg::Id::from(l), egg::Id::from(r)]), Op::Shl),
                    B::ShiftRight => (Math::Shr([egg::Id::from(l), egg::Id::from(r)]), Op::Shr),
                    B::ShiftRightZeroFill => (Math::Ushr([egg::Id::from(l), egg::Id::from(r)]), Op::Ushr),
                    op => return Err(TransErr(format!("binary {op:?}"))),
                };
                self.nodes.push(node);
                self.ops.push(op);
                Ok(self.nodes.len() - 1)
            }
            Expression::CallExpression(c) => {
                if is_parse_int(c) || is_number(c) {
                    let arg = c.arguments.first().and_then(|a| a.as_expression());
                    return match arg {
                        Some(e) => self.expr(e),
                        None => Err(TransErr("преобразование без аргумента".into())),
                    };
                }
                let Some(name) = ident_of(&c.callee) else {
                    return Err(TransErr("выражение-калли".into()));
                };
                if (self.is_dec)(name).is_none() {
                    return Err(TransErr(format!("неизвестный вызов {name}")));
                }
                let arg = c
                    .arguments
                    .first()
                    .and_then(|a| a.as_expression())
                    .and_then(num_lit)
                    .ok_or_else(|| TransErr(format!("нелитеральный аргумент декодера {name}")))?;
                let var_name = mba::var_name_for_arg(arg);
                let slot = match self.var_slot.get(&var_name) {
                    Some(s) => *s,
                    None => {
                        let s = self.n_vars;
                        self.var_slot.insert(var_name.clone(), s);
                        self.var_args.push(arg);
                        self.n_vars += 1;
                        s
                    }
                };
                self.nodes.push(Math::Var(egg::Symbol::from(var_name.as_str())));
                self.ops.push(Op::Var(slot as u8));
                Ok(self.nodes.len() - 1)
            }
            other => Err(TransErr(format!("{other:?}").chars().take(120).collect())),
        }
    }
}

fn is_parse_int<'a>(c: &'a ast::CallExpression<'a>) -> bool {
    match &c.callee {
        Expression::Identifier(i) => i.name.as_ref() == "parseInt",
        Expression::StaticMemberExpression(m) => m.property.name.as_ref() == "parseInt",
        Expression::ComputedMemberExpression(m) => {
            matches!(&m.expression, Expression::StringLiteral(s) if s.value == "parseInt")
        }
        _ => false,
    }
}

fn is_number<'a>(c: &'a ast::CallExpression<'a>) -> bool {
    match &c.callee {
        Expression::Identifier(i) => i.name.as_ref() == "Number",
        _ => false,
    }
}
