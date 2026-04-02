pub fn single_byte_xor(bytes: &[u8], key: u8) -> Vec<u8> {
    bytes.iter().map(|b| b ^ key).collect()
}
