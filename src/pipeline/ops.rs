#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Op {
    Const(f64),
    Var(u8),
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Neg,
    Xor,
    And,
    Or,
    Shl,
    Shr,
    Ushr,
}

#[derive(Debug, Clone, Default)]
pub struct Program {
    pub ops: Vec<Op>,
    pub n_vars: usize,
}

impl Program {
    // Хэш СОДЕРЖИМОГО программы: последовательность опкодов (Const-значения +
    // позиционные Var-слоты + арифметика). Имена варов не участвуют — Var(slot)
    // это индекс, не имя. Две программы с идентичной структурой дают один хэш →
    // один скомпилированный cranelift-код. Это правильный ключ кэша (не full_hash,
    // который включает имена варов и потому никогда не бьёт между челленджами).
    pub fn content_hash(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.n_vars.hash(&mut h);
        for op in &self.ops {
            match op {
                Op::Const(c) => {
                    0u8.hash(&mut h);
                    c.to_bits().hash(&mut h);
                }
                Op::Var(i) => {
                    1u8.hash(&mut h);
                    i.hash(&mut h);
                }
                other => {
                    std::mem::discriminant(other).hash(&mut h);
                }
            }
        }
        h.finish()
    }

    pub fn eval(&self, vars: &[f64]) -> f64 {
        let mut stack = [0f64; 64];
        let mut sp: usize = 0;
        macro_rules! bin {
            ($f:expr) => {{
                sp -= 1;
                let b = stack[sp];
                let a = stack[sp - 1];
                stack[sp - 1] = $f(a, b);
            }};
        }
        for &op in &self.ops {
            match op {
                Op::Const(c) => {
                    if sp >= 64 {
                        return f64::NAN;
                    }
                    stack[sp] = c;
                    sp += 1;
                }
                Op::Var(i) => {
                    if sp >= 64 || (i as usize) >= vars.len() {
                        return f64::NAN;
                    }
                    stack[sp] = vars[i as usize];
                    sp += 1;
                }
                Op::Add => bin!(|a, b| a + b),
                Op::Sub => bin!(|a, b| a - b),
                Op::Mul => bin!(|a, b| a * b),
                Op::Div => bin!(|a, b| a / b),
                Op::Mod => bin!(|a, b| a % b),
                Op::Neg => {
                    let i = sp - 1;
                    stack[i] = -stack[i];
                }
                Op::Xor => bin!(|a, b| f64::from(crate::core::jsnum::to_int32(a) ^ crate::core::jsnum::to_int32(b))),
                Op::And => bin!(|a, b| f64::from(crate::core::jsnum::to_int32(a) & crate::core::jsnum::to_int32(b))),
                Op::Or => bin!(|a, b| f64::from(crate::core::jsnum::to_int32(a) | crate::core::jsnum::to_int32(b))),
                Op::Shl => bin!(|a, b| f64::from(crate::core::jsnum::to_int32(a).wrapping_shl(crate::core::jsnum::to_uint32(b) & 31))),
                Op::Shr => bin!(|a, b| f64::from(crate::core::jsnum::to_int32(a).wrapping_shr(crate::core::jsnum::to_uint32(b) & 31))),
                Op::Ushr => bin!(|a, b| f64::from(crate::core::jsnum::to_uint32(a).wrapping_shr(crate::core::jsnum::to_uint32(b) & 31))),
            }
        }
        sp.checked_sub(1).map(|i| stack[i]).unwrap_or(f64::NAN)
    }
}
