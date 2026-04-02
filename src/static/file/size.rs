pub fn bytes_len(bytes: &[u8]) -> u64 {
    bytes.len() as u64
}

pub fn is_unusually_small(size: u64) -> bool {
    size > 0 && size < 512
}
