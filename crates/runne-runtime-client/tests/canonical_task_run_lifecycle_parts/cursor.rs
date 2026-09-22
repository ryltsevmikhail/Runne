// Cursor hex helper: opaque runtime cursors are `gocode-replay-cursor-v1.`
// followed by lower-hex of a JSON object.
fn cursor_hex(json_object: &str) -> String {
    let mut encoded = String::with_capacity(json_object.len() * 2);
    for byte in json_object.bytes() {
        encoded.push(char::from_digit(u32::from(byte >> 4), 16).expect("hex digit"));
        encoded.push(char::from_digit(u32::from(byte & 0xF), 16).expect("hex digit"));
    }
    encoded
}
