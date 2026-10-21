pub fn split(data: &[u8]) -> Option<([u8; 48], &[u8], &[u8], usize)> {
    if data.len() < 52 {
        return None;
    }
    let mut key = [0; 48];
    key.copy_from_slice(&data[..48]);
    let context_length = usize::from(u16::from_le_bytes([data[48], data[49]])) % 4098;
    let rest = &data[52..];
    let context_length = context_length.min(rest.len());
    let (context, payload) = rest.split_at(context_length);
    let mutation = usize::from(u16::from_le_bytes([data[50], data[51]]));
    Some((key, context, payload, mutation))
}
