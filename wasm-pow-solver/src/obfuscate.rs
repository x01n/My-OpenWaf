use sha2::{Sha256, Digest};

#[inline(never)]
pub fn sha256_compute(data: &[u8]) -> [u8; 32] {
    let path = data.len() & 0x03;
    match path {
        0 => path_alpha(data),
        1 => path_beta(data),
        2 => path_gamma(data),
        _ => path_delta(data),
    }
}

#[inline(never)]
fn path_alpha(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

#[inline(never)]
fn path_beta(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let mid = data.len() / 2;
    hasher.update(&data[..mid]);
    hasher.update(&data[mid..]);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

#[inline(never)]
fn path_gamma(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for chunk in data.chunks(8) {
        hasher.update(chunk);
    }
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

#[inline(never)]
fn path_delta(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let third = data.len() / 3;
    if third > 0 {
        hasher.update(&data[..third]);
        hasher.update(&data[third..third * 2]);
        hasher.update(&data[third * 2..]);
    } else {
        hasher.update(data);
    }
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

#[inline(never)]
pub fn sha256_raw(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}
