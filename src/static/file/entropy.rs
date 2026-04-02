pub fn shannon(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut freq = [0usize; 256];
    for &b in bytes {
        freq[b as usize] += 1;
    }

    let len = bytes.len() as f64;
    freq.iter()
        .filter(|&&n| n > 0)
        .map(|&n| {
            let p = n as f64 / len;
            -p * p.log2()
        })
        .sum()
}
