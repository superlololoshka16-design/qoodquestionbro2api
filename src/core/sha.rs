use std::arch::x86_64::*;
use std::sync::OnceLock;

use crate::core::b64::std_encode;

pub const K32: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn sha_ni() -> bool {
    static V: OnceLock<bool> = OnceLock::new();
    *V.get_or_init(|| __cpuid_count(7, 0).ebx & (1 << 29) != 0)
}

#[inline(always)]
unsafe fn load_be(p: *const u8, mask: __m128i) -> __m128i {
    unsafe { _mm_shuffle_epi8(_mm_loadu_si128(p as *const __m128i), mask) }
}

#[inline(always)]
unsafe fn state_in(state: *const u32) -> (__m128i, __m128i) {
    unsafe {
        let dcba = _mm_loadu_si128(state as *const __m128i);
        let efgh = _mm_loadu_si128(state.add(4) as *const __m128i);
        let cdab = _mm_shuffle_epi32(dcba, 0xB1);
        let efgh = _mm_shuffle_epi32(efgh, 0x1B);
        let abef = _mm_alignr_epi8(cdab, efgh, 8);
        let cdgh = _mm_blend_epi16(efgh, cdab, 0xF0);
        (abef, cdgh)
    }
}

#[inline(always)]
unsafe fn state_out(state: *mut u32, abef: __m128i, cdgh: __m128i, abef0: __m128i, cdgh0: __m128i) {
    unsafe {
        let abef = _mm_add_epi32(abef, abef0);
        let cdgh = _mm_add_epi32(cdgh, cdgh0);
        let feba = _mm_shuffle_epi32(abef, 0x1B);
        let dchg = _mm_shuffle_epi32(cdgh, 0xB1);
        let dcba = _mm_blend_epi16(feba, dchg, 0xF0);
        let hgef = _mm_alignr_epi8(dchg, feba, 8);
        _mm_storeu_si128(state as *mut __m128i, dcba);
        _mm_storeu_si128(state.add(4) as *mut __m128i, hgef);
    }
}

#[inline(always)]
unsafe fn schedule(v0: __m128i, v1: __m128i, v2: __m128i, v3: __m128i) -> __m128i {
    unsafe {
        let t1 = _mm_sha256msg1_epu32(v0, v1);
        let t2 = _mm_alignr_epi8(v3, v2, 4);
        _mm_sha256msg2_epu32(_mm_add_epi32(t1, t2), v3)
    }
}

macro_rules! rounds4 {
    ($abef:ident, $cdgh:ident, $rest:expr, $i:expr) => {{
        let kv = _mm_set_epi32(
            K32[($i) * 4 + 3] as i32,
            K32[($i) * 4 + 2] as i32,
            K32[($i) * 4 + 1] as i32,
            K32[($i) * 4] as i32,
        );
        let t1 = _mm_add_epi32($rest, kv);
        $cdgh = _mm_sha256rnds2_epu32($cdgh, $abef, t1);
        let t2 = _mm_shuffle_epi32(t1, 0x0E);
        $abef = _mm_sha256rnds2_epu32($abef, $cdgh, t2);
    }};
}

macro_rules! sched4 {
    ($abef:ident, $cdgh:ident, $w0:expr, $w1:expr, $w2:expr, $w3:expr, $w4:expr, $i:expr) => {{
        $w4 = schedule($w0, $w1, $w2, $w3);
        rounds4!($abef, $cdgh, $w4, $i);
    }};
}

#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
unsafe fn sha256_block_ni(state: &mut [u32; 8], block: &[u8; 64]) {
    unsafe {
        let mask: __m128i =
            _mm_set_epi64x(0x0C0D_0E0F_0809_0A0Bu64 as i64, 0x0405_0607_0001_0203u64 as i64);
        let dp = block.as_ptr();
        let (mut abef, mut cdgh) = state_in(state.as_ptr());
        let (abef0, cdgh0) = (abef, cdgh);
        let mut w0 = load_be(dp, mask);
        let mut w1 = load_be(dp.add(16), mask);
        let mut w2 = load_be(dp.add(32), mask);
        let mut w3 = load_be(dp.add(48), mask);
        let mut w4;
        rounds4!(abef, cdgh, w0, 0);
        rounds4!(abef, cdgh, w1, 1);
        rounds4!(abef, cdgh, w2, 2);
        rounds4!(abef, cdgh, w3, 3);
        sched4!(abef, cdgh, w0, w1, w2, w3, w4, 4);
        sched4!(abef, cdgh, w1, w2, w3, w4, w0, 5);
        sched4!(abef, cdgh, w2, w3, w4, w0, w1, 6);
        sched4!(abef, cdgh, w3, w4, w0, w1, w2, 7);
        sched4!(abef, cdgh, w4, w0, w1, w2, w3, 8);
        sched4!(abef, cdgh, w0, w1, w2, w3, w4, 9);
        sched4!(abef, cdgh, w1, w2, w3, w4, w0, 10);
        sched4!(abef, cdgh, w2, w3, w4, w0, w1, 11);
        sched4!(abef, cdgh, w3, w4, w0, w1, w2, 12);
        sched4!(abef, cdgh, w4, w0, w1, w2, w3, 13);
        sched4!(abef, cdgh, w0, w1, w2, w3, w4, 14);
        sched4!(abef, cdgh, w1, w2, w3, w4, w0, 15);
        state_out(state.as_mut_ptr(), abef, cdgh, abef0, cdgh0);
    }
}

fn soft_block(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) =
        (state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]);
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K32[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
    }
}

#[inline(always)]
fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    if sha_ni() {
        unsafe { sha256_block_ni(state, block) }
    } else {
        soft_block(state, block);
    }
}

pub struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    buflen: usize,
    total: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Self { h: H0, buf: [0u8; 64], buflen: 0, total: 0 }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buflen > 0 {
            let take = (64 - self.buflen).min(data.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
            self.buflen += take;
            data = &data[take..];
            if self.buflen == 64 {
                compress(&mut self.h, &self.buf);
                self.buflen = 0;
            }
        }
        if self.buflen == 0 {
            let (chunks, rem) = data.as_chunks::<64>();
            for block in chunks {
                compress(&mut self.h, block);
            }
            self.buf[..rem.len()].copy_from_slice(rem);
            self.buflen = rem.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bitlen = self.total.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buflen != 56 {
            self.update(&[0]);
        }
        self.buf[56..64].copy_from_slice(&bitlen.to_be_bytes());
        compress(&mut self.h, &self.buf);
        let mut out = [0u8; 32];
        for (i, v) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
        }
        out
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut s = Sha256::new();
    s.update(data);
    s.finalize()
}

pub fn sha256_b64(data: &[u8]) -> String {
    let mut out = [0u8; 44];
    sha256_b64_into(data, &mut out);
    String::from_utf8(out.to_vec()).expect("b64 ASCII")
}

pub fn sha256_b64_into(data: &[u8], out: &mut [u8; 44]) {
    let d = sha256(data);
    std_encode(&d, out);
}
