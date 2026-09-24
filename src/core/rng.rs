pub fn fill(buf: &mut [u8]) -> bool {
    use std::io::Read;
    let mut f = match std::fs::File::open("/dev/urandom") {
        Ok(f) => f,
        Err(_) => return false,
    };
    f.read_exact(buf).is_ok()
}

pub fn seed() -> u64 {
    let mut b = [0u8; 8];
    if !fill(&mut b) {
        return 0x9E3779B97F4A7C15;
    }
    u64::from_ne_bytes(b)
}
