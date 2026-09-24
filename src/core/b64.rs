const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const REV: [u8; 256] = {
    let mut t = [255u8; 256];
    let mut i = 0;
    while i < 64 {
        t[STD[i] as usize] = i as u8;
        i += 1;
    }
    t[b'-' as usize] = 62;
    t[b'_' as usize] = 63;
    t
};

pub fn decode_slice(src: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    let mut w = 0usize;
    for &c in src {
        if c == b'=' || c == b'\n' || c == b'\r' || c == b' ' || c == b'\t' {
            continue;
        }
        let v = REV[c as usize];
        if v == 255 {
            return None;
        }
        acc = (acc << 6) | u32::from(v);
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            *out.get_mut(w)? = (acc >> nbits) as u8;
            w += 1;
        }
    }
    Some(w)
}

pub fn decode(src: &[u8]) -> Option<Vec<u8>> {
    let mut out = vec![0u8; src.len() / 4 * 3 + 4];
    let n = decode_slice(src, &mut out)?;
    out.truncate(n);
    Some(out)
}

#[inline]
pub fn encoded_len(raw_len: usize) -> usize {
    raw_len.div_ceil(3) * 4
}

pub fn std_encode(src: &[u8], out: &mut [u8]) {
    let mut w = 0usize;
    let (chunks, rem) = src.as_chunks::<3>();
    for c in chunks {
        let n = (u32::from(c[0]) << 16) | (u32::from(c[1]) << 8) | u32::from(c[2]);
        out[w] = STD[(n >> 18) as usize & 63];
        out[w + 1] = STD[(n >> 12) as usize & 63];
        out[w + 2] = STD[(n >> 6) as usize & 63];
        out[w + 3] = STD[n as usize & 63];
        w += 4;
    }
    match rem {
        [a] => {
            let n = u32::from(*a) << 16;
            out[w] = STD[(n >> 18) as usize & 63];
            out[w + 1] = STD[(n >> 12) as usize & 63];
            out[w + 2] = b'=';
            out[w + 3] = b'=';
        }
        [a, b] => {
            let n = (u32::from(*a) << 16) | (u32::from(*b) << 8);
            out[w] = STD[(n >> 18) as usize & 63];
            out[w + 1] = STD[(n >> 12) as usize & 63];
            out[w + 2] = STD[(n >> 6) as usize & 63];
            out[w + 3] = b'=';
        }
        _ => {}
    }
}

pub fn encode_string(src: &[u8]) -> String {
    let mut buf = vec![0u8; encoded_len(src.len())];
    std_encode(src, &mut buf);
    String::from_utf8(buf).expect("b64-алфавит ASCII")
}
