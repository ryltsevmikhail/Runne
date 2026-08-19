#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum StringKind {
    Ordinary,
    Raw,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Token {
    Ident(String),
    String { value: String, kind: StringKind },
    Punct(char),
}

pub(super) fn tokenize(source: &str) -> Result<Vec<Token>, String> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if let Some(next) = skip_comment(bytes, index)? {
            index = next;
        } else if let Some((token, next)) = string_token(source, index)? {
            tokens.push(token);
            index = next;
        } else if let Some(next) = byte_char(bytes, index) {
            index = next;
        } else if let Some(next) = char_literal(source, index) {
            index = next;
        } else if let Some((name, next)) = raw_identifier(source, index) {
            tokens.push(Token::Ident(name));
            index = next;
        } else if bytes[index].is_ascii_alphabetic() || bytes[index] == b'_' {
            let start = index;
            index += 1;
            while bytes
                .get(index)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                index += 1;
            }
            tokens.push(Token::Ident(source[start..index].to_owned()));
        } else if bytes[index].is_ascii_whitespace() {
            index += 1;
        } else if bytes[index].is_ascii() {
            tokens.push(Token::Punct(char::from(bytes[index])));
            index += 1;
        } else {
            return Err(format!("lexer at byte {index}: non-ASCII code token"));
        }
    }
    Ok(tokens)
}

fn skip_comment(bytes: &[u8], index: usize) -> Result<Option<usize>, String> {
    if bytes.get(index..index + 2) == Some(b"//") {
        let mut next = index + 2;
        while bytes.get(next).is_some_and(|byte| *byte != b'\n') {
            next += 1;
        }
        return Ok(Some(next));
    }
    if bytes.get(index..index + 2) != Some(b"/*") {
        return Ok(None);
    }
    let mut depth = 1;
    let mut next = index + 2;
    while next + 1 < bytes.len() {
        match (bytes[next], bytes[next + 1]) {
            (b'/', b'*') => {
                depth += 1;
                next += 2;
            }
            (b'*', b'/') => {
                depth -= 1;
                next += 2;
                if depth == 0 {
                    return Ok(Some(next));
                }
            }
            _ => next += 1,
        }
    }
    Err(format!("lexer at byte {index}: unterminated block comment"))
}

fn string_token(source: &str, index: usize) -> Result<Option<(Token, usize)>, String> {
    let bytes = source.as_bytes();
    if let Some((prefix, hashes, ordinary_raw)) = raw_prefix(bytes, index) {
        return raw_string(source, index, prefix, hashes, ordinary_raw).map(Some);
    }
    let (prefix, kind) = match bytes.get(index..index + 2) {
        Some(b"b\"") | Some(b"c\"") => (1, StringKind::Other),
        _ if bytes.get(index) == Some(&b'\"') => (0, StringKind::Ordinary),
        _ => return Ok(None),
    };
    quoted_string(source, index + prefix + 1, kind).map(Some)
}

fn raw_prefix(bytes: &[u8], index: usize) -> Option<(usize, usize, bool)> {
    let (prefix, ordinary) = match bytes.get(index) {
        Some(b'r') => (1, true),
        Some(b'b' | b'c') if bytes.get(index + 1) == Some(&b'r') => (2, false),
        _ => return None,
    };
    let mut hashes = 0;
    while bytes.get(index + prefix + hashes) == Some(&b'#') {
        hashes += 1;
    }
    (bytes.get(index + prefix + hashes) == Some(&b'\"')).then_some((prefix, hashes, ordinary))
}

fn raw_identifier(source: &str, index: usize) -> Option<(String, usize)> {
    let bytes = source.as_bytes();
    if bytes.get(index..index + 2) != Some(b"r#") {
        return None;
    }
    let start = index + 2;
    if !bytes
        .get(start)
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
    {
        return None;
    }
    let mut end = start + 1;
    while bytes
        .get(end)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        end += 1;
    }
    Some((source[start..end].to_owned(), end))
}

fn quoted_string(source: &str, start: usize, kind: StringKind) -> Result<(Token, usize), String> {
    let bytes = source.as_bytes();
    let mut index = start;
    let mut escaped = false;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            escaped = true;
            index += 1;
            if index == bytes.len() {
                break;
            }
        } else if bytes[index] == b'\"' {
            let kind = if escaped { StringKind::Other } else { kind };
            return Ok((
                Token::String {
                    value: source[start..index].to_owned(),
                    kind,
                },
                index + 1,
            ));
        }
        index += 1;
    }
    Err(format!("lexer at byte {}: unterminated string", start - 1))
}

fn raw_string(
    source: &str,
    start: usize,
    prefix: usize,
    hashes: usize,
    ordinary: bool,
) -> Result<(Token, usize), String> {
    let bytes = source.as_bytes();
    let content = start + prefix + hashes + 1;
    let mut index = content;
    while index < bytes.len() {
        if bytes[index] == b'\"'
            && bytes
                .get(index + 1..index + hashes + 1)
                .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
            && bytes.get(index + hashes + 1) != Some(&b'#')
        {
            return Ok((
                Token::String {
                    value: source[content..index].to_owned(),
                    kind: if ordinary {
                        StringKind::Raw
                    } else {
                        StringKind::Other
                    },
                },
                index + hashes + 1,
            ));
        }
        index += 1;
    }
    Err(format!("lexer at byte {start}: unterminated raw string"))
}

fn char_literal(source: &str, index: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    if bytes.get(index) != Some(&b'\'') {
        return None;
    }
    let next = index + 1;
    if bytes.get(next) == Some(&b'\\') {
        let escape_end = escape_end(bytes, next)?;
        return (bytes.get(escape_end) == Some(&b'\'')).then_some(escape_end + 1);
    }
    let value = source.get(next..)?.chars().next()?;
    let end = next + value.len_utf8();
    (bytes.get(end) == Some(&b'\'')).then_some(end + 1)
}

fn byte_char(bytes: &[u8], index: usize) -> Option<usize> {
    if bytes.get(index..index + 2) != Some(b"b'") {
        return None;
    }
    let next = index + 2;
    if bytes.get(next) == Some(&b'\\') {
        let end = byte_escape_end(bytes, next)?;
        return (bytes.get(end) == Some(&b'\'')).then_some(end + 1);
    }
    bytes
        .get(next)
        .filter(|byte| byte.is_ascii() && **byte != b'\'')
        .and_then(|_| (bytes.get(next + 1) == Some(&b'\'')).then_some(next + 2))
}

fn byte_escape_end(bytes: &[u8], slash: usize) -> Option<usize> {
    match *bytes.get(slash + 1)? {
        b'\\' | b'\'' | b'\"' | b'n' | b'r' | b't' | b'0' => Some(slash + 2),
        b'x' if bytes.get(slash + 2)?.is_ascii_hexdigit()
            && bytes.get(slash + 3)?.is_ascii_hexdigit() =>
        {
            Some(slash + 4)
        }
        _ => None,
    }
}

fn escape_end(bytes: &[u8], slash: usize) -> Option<usize> {
    match *bytes.get(slash + 1)? {
        b'\\' | b'\'' | b'\"' | b'n' | b'r' | b't' | b'0' => Some(slash + 2),
        b'x' if bytes.get(slash + 2)?.is_ascii_hexdigit()
            && bytes.get(slash + 3)?.is_ascii_hexdigit() =>
        {
            Some(slash + 4)
        }
        b'u' if bytes.get(slash + 2) == Some(&b'{') => unicode_escape_end(bytes, slash + 3),
        _ => None,
    }
}

fn unicode_escape_end(bytes: &[u8], mut index: usize) -> Option<usize> {
    let start = index;
    while bytes
        .get(index)
        .is_some_and(|byte| byte.is_ascii_hexdigit())
    {
        index += 1;
    }
    if index == start || bytes.get(index) != Some(&b'}') {
        return None;
    }
    let digits = std::str::from_utf8(&bytes[start..index]).ok()?;
    let scalar = u32::from_str_radix(digits, 16).ok()?;
    char::from_u32(scalar).map(|_| index + 1)
}
