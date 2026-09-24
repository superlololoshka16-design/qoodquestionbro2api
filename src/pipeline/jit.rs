// cranelift-JIT канонической программы (egg-канон) + thread_local кэш.
// Поток: oxc парсит челлендж → egg схлопывает checksum в канон → cranelift
// компилит канон в машинный код ОДИН РАЗ → кэш по full_hash → повторные
// прогоны того же канона берут готовый fn-указатель, ноль перекомпиляции.
// Ключ — full_hash (точный канон с константами), НЕ template_hash: Op::Const
// запекается в f64const, у каждого челленджа свои константы при том же
// структурном семействе. Канарейка: jit vs интерпретатор на известном наборе
// перед доверием; расхождение/ошибка → fallback на Program::eval.

use std::cell::RefCell;
use std::collections::HashMap;

use cranelift::prelude::*;
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{Linkage, Module};

use crate::pipeline::ops::{Op, Program};

extern "C" fn js_fmod(a: f64, b: f64) -> f64 {
    a % b
}

pub struct Jit {
    _module: JITModule,
    fptr: unsafe extern "C" fn(*const f64) -> f64,
}

#[derive(Debug, thiserror::Error)]
pub enum JitErr {
    #[error("isa: {0}")]
    Isa(String),
    #[error("define: {0}")]
    Define(String),
    #[error("не реализовано: {0}")]
    NotImplemented(&'static str),
    #[error("канарейка: jit разошёлся с интерпретатором")]
    Canary,
}

impl Jit {
    #[inline]
    pub fn call(&self, vars: &[f64]) -> f64 {
        unsafe { (self.fptr)(vars.as_ptr()) }
    }
}

thread_local! {
    static CACHE: RefCell<HashMap<u64, std::rc::Rc<Jit>>> = RefCell::new(HashMap::new());
}

// Компилирует канон и кэширует по full_hash. Rc — owned-ручка без утечки:
// clone отдаёт совместное владение, кэш держит свою копию, всё освобождается
// при дропе. thread_local ⇒ один поток, Sync не нужен. Повторный вызов с тем
// же хэшем возвращает готовый Rc, ноль перекомпиляции.
pub fn compile_cached(key: u64, program: &Program) -> Result<std::rc::Rc<Jit>, JitErr> {
    CACHE.with(|c| {
        if let Some(jit) = c.borrow().get(&key) {
            return Ok(jit.clone());
        }
        let jit = std::rc::Rc::new(compile(program)?);
        c.borrow_mut().insert(key, jit.clone());
        Ok(jit)
    })
}

pub fn cached_len() -> usize {
    CACHE.with(|c| c.borrow().len())
}
fn to_i32(b: &mut FunctionBuilder, v: Value) -> Value {
    let nan = b.ins().fcmp(FloatCC::Unordered, v, v);
    let abs = b.ins().fabs(v);
    let limit = b.ins().f64const(9.223372036854775e18);
    let huge = b.ins().fcmp(FloatCC::GreaterThan, abs, limit);
    let bad = b.ins().bor(nan, huge);
    let zero = b.ins().f64const(0.0);
    let safe = b.ins().select(bad, zero, v);
    let wide = b.ins().fcvt_to_sint_sat(types::I64, safe);
    b.ins().ireduce(types::I32, wide)
}

#[inline]
fn from_i32(b: &mut FunctionBuilder, v: Value) -> Value {
    b.ins().fcvt_from_sint(types::F64, v)
}

pub fn compile(program: &Program) -> Result<Jit, JitErr> {
    if program.ops.iter().any(|op| matches!(op, Op::Var(i) if usize::from(*i) >= 256)) {
        return Err(JitErr::NotImplemented("слот переменной >= 256"));
    }
    let mut flag_builder = settings::builder();
    flag_builder.set("opt_level", "speed").map_err(|e| JitErr::Isa(e.to_string()))?;
    let isa = isa::lookup_by_name("x86_64")
        .map_err(|e| JitErr::Isa(e.to_string()))?
        .finish(settings::Flags::new(flag_builder))
        .map_err(|e| JitErr::Isa(e.to_string()))?;
    let mut builder = JITBuilder::with_isa(isa, cranelift_module::default_libcall_names());
    builder.symbol("js_fmod", js_fmod as *const u8);
    let mut module = JITModule::new(builder);

    let mut fmod_sig = module.make_signature();
    fmod_sig.params.push(AbiParam::new(types::F64));
    fmod_sig.params.push(AbiParam::new(types::F64));
    fmod_sig.returns.push(AbiParam::new(types::F64));
    let fmod_id = module
        .declare_function("js_fmod", Linkage::Import, &fmod_sig)
        .map_err(|e| JitErr::Define(e.to_string()))?;

    let mut ctx = module.make_context();
    let mut sig = module.make_signature();
    sig.params.push(AbiParam::new(types::I64));
    sig.returns.push(AbiParam::new(types::F64));
    ctx.func.signature = sig;
    let fmod_ref = module.declare_func_in_func(fmod_id, &mut ctx.func);
    let mut fn_builder_ctx = FunctionBuilderContext::new();
    let mut builder = FunctionBuilder::new(&mut ctx.func, &mut fn_builder_ctx);
    let block = builder.create_block();
    builder.append_block_params_for_function_params(block);
    builder.switch_to_block(block);
    let arg0 = builder.block_params(block)[0];

    let mut stack: Vec<Value> = Vec::with_capacity(64);
    macro_rules! pop2 {
        ($b:expr) => {{
            let b2 = stack.pop().ok_or(JitErr::NotImplemented("стек пуст"))?;
            let a2 = stack.pop().ok_or(JitErr::NotImplemented("стек пуст"))?;
            (a2, b2)
        }};
    }
    for op in &program.ops {
        let b = &mut builder;
        match op {
            Op::Const(c) => stack.push(b.ins().f64const(*c)),
            Op::Var(i) => {
                let off = (usize::from(*i) as i32) * 8;
                stack.push(b.ins().load(types::F64, MemFlags::new(), arg0, off));
            }
            Op::Add => {
                let (a, c) = pop2!(b);
                stack.push(b.ins().fadd(a, c));
            }
            Op::Sub => {
                let (a, c) = pop2!(b);
                stack.push(b.ins().fsub(a, c));
            }
            Op::Mul => {
                let (a, c) = pop2!(b);
                stack.push(b.ins().fmul(a, c));
            }
            Op::Div => {
                let (a, c) = pop2!(b);
                stack.push(b.ins().fdiv(a, c));
            }
            Op::Mod => {
                let (a, c) = pop2!(b);
                let call = b.ins().call(fmod_ref, &[a, c]);
                stack.push(b.inst_results(call)[0]);
            }
            Op::Neg => {
                let a = stack.pop().ok_or(JitErr::NotImplemented("стек пуст"))?;
                stack.push(b.ins().fneg(a));
            }
            Op::Xor => {
                let (a, c) = pop2!(b);
                let (x, y) = (to_i32(b, a), to_i32(b, c));
                let r = b.ins().bxor(x, y);
                stack.push(from_i32(b, r));
            }
            Op::And => {
                let (a, c) = pop2!(b);
                let (x, y) = (to_i32(b, a), to_i32(b, c));
                let r = b.ins().band(x, y);
                stack.push(from_i32(b, r));
            }
            Op::Or => {
                let (a, c) = pop2!(b);
                let (x, y) = (to_i32(b, a), to_i32(b, c));
                let r = b.ins().bor(x, y);
                stack.push(from_i32(b, r));
            }
            Op::Shl => {
                let (a, c) = pop2!(b);
                let x = to_i32(b, a);
                let y = to_i32(b, c);
                let c31 = b.ins().iconst(types::I32, 31);
                let m = b.ins().band(y, c31);
                let r = b.ins().ishl(x, m);
                stack.push(from_i32(b, r));
            }
            Op::Shr => {
                let (a, c) = pop2!(b);
                let x = to_i32(b, a);
                let y = to_i32(b, c);
                let c31 = b.ins().iconst(types::I32, 31);
                let m = b.ins().band(y, c31);
                let r = b.ins().sshr(x, m);
                stack.push(from_i32(b, r));
            }
            Op::Ushr => {
                let (a, c) = pop2!(b);
                let x = to_i32(b, a);
                let y = to_i32(b, c);
                let c31 = b.ins().iconst(types::I32, 31);
                let m = b.ins().band(y, c31);
                let r = b.ins().ushr(x, m);
                stack.push(from_i32(b, r));
            }
        }
    }
    let top = stack.pop().ok_or(JitErr::NotImplemented("нет результата"))?;
    builder.ins().return_(&[top]);
    builder.seal_all_blocks();
    builder.finalize();

    let func_id = module
        .declare_function("solve", Linkage::Local, &ctx.func.signature)
        .map_err(|e| JitErr::Define(e.to_string()))?;
    module
        .define_function(func_id, &mut ctx)
        .map_err(|e| JitErr::Define(e.to_string()))?;
    module.clear_context(&mut ctx);
    module
        .finalize_definitions()
        .map_err(|e| JitErr::Define(e.to_string()))?;
    let code_ptr = module.get_finalized_function(func_id);
    let fptr: unsafe extern "C" fn(*const f64) -> f64 = unsafe { std::mem::transmute(code_ptr) };
    Ok(Jit { _module: module, fptr })
}

// Канарейка: jit должен совпасть с интерпретатором бит-в-бит на известных vars.
pub fn verify(program: &Program, jit: &Jit, vars: &[f64]) -> bool {
    jit.call(vars).to_bits() == program.eval(vars).to_bits()
}
