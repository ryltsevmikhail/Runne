#[derive(Debug, PartialEq, Eq)]
pub(super) struct ScannedRustSource {
    pub(super) code: String,
    pub(super) normalized_code: String,
    pub(super) string_literals: Vec<String>,
}
#[derive(Debug, PartialEq, Eq)]
pub(super) enum SourceScanError {
    BlockComment,
    String,
    RawString,
    Module,
}
pub(super) fn scan_rust_source(source: &str) -> Result<ScannedRustSource, SourceScanError> {
    let mut code = String::with_capacity(source.len());
    let mut string_literals = Vec::new();
    let mut index = 0;
    while index < source.len() {
        if source[index..].starts_with("//") {
            index = skip_line_comment(source, index + 2);
            push_separator(&mut code);
        } else if source[index..].starts_with("/*") {
            index = skip_block_comment(source, index + 2)?;
            push_separator(&mut code);
        } else if let Some(raw) = parse_raw_string(source, index) {
            let (end, literal) = raw?;
            string_literals.push(literal);
            push_separator(&mut code);
            index = end;
        } else if let Some(quote) = quoted_string_start(source, index) {
            let (end, literal) = parse_quoted_string(source, quote)?;
            string_literals.push(literal);
            push_separator(&mut code);
            index = end;
        } else if source[index..].starts_with("b'") {
            if let Some(end) = parse_char_literal(source, index + 1) {
                code.push_str(&source[index..end]);
                index = end;
            } else {
                copy_next_char(source, &mut code, &mut index);
            }
        } else if source[index..].starts_with('\'') {
            if let Some(end) = parse_char_literal(source, index) {
                code.push_str(&source[index..end]);
                index = end;
            } else {
                copy_next_char(source, &mut code, &mut index);
            }
        } else {
            copy_next_char(source, &mut code, &mut index);
        }
    }
    let normalized_code = code
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    Ok(ScannedRustSource {
        code,
        normalized_code,
        string_literals,
    })
}
pub(super) fn module_child_paths(path: &str, code: &str) -> Result<Vec<String>, SourceScanError> {
    let parent = path.strip_suffix(".rs").ok_or(SourceScanError::Module)?;
    Ok(module_names(code)?
        .into_iter()
        .map(|name| format!("{parent}/{name}.rs"))
        .collect())
}
fn module_names(code: &str) -> Result<Vec<String>, SourceScanError> {
    let tokens = module_tokens(code);
    let mut names = Vec::new();
    let mut index = 0;
    let mut test_gated = false;
    while index < tokens.len() {
        if tokens[index] == "#" && tokens.get(index + 1).is_some_and(|token| token == "[") {
            let end = tokens[index + 2..]
                .iter()
                .position(|token| token == "]")
                .ok_or(SourceScanError::Module)?
                + index
                + 2;
            test_gated |= test_only_cfg(&tokens[index + 2..end]);
            index = end + 1;
        } else if tokens[index] == "pub" && test_gated {
            index += 1;
            if tokens.get(index).is_some_and(|token| token == "(") {
                index = tokens[index + 1..]
                    .iter()
                    .position(|token| token == ")")
                    .ok_or(SourceScanError::Module)?
                    + index
                    + 2;
            }
        } else if tokens[index] == "mod" {
            let name = tokens
                .get(index + 1)
                .filter(|name| is_identifier(name))
                .ok_or(SourceScanError::Module)?;
            match tokens.get(index + 2).map(String::as_str) {
                Some(";") => {
                    if !test_gated {
                        names.push(name.clone());
                    }
                    index += 3;
                    test_gated = false;
                }
                Some("{") => {
                    index += 3;
                    test_gated = false;
                }
                _ => return Err(SourceScanError::Module),
            }
        } else {
            index += 1;
            test_gated = false;
        }
    }
    Ok(names)
}
fn module_tokens(code: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    for character in code.chars() {
        if character == '_' || character.is_alphanumeric() {
            token.push(character);
        } else {
            if !token.is_empty() {
                tokens.push(std::mem::take(&mut token));
            }
            if !character.is_whitespace() {
                tokens.push(character.to_string());
            }
        }
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    tokens
}

fn test_only_cfg(tokens: &[String]) -> bool {
    tokens == ["cfg", "(", "test", ")"]
        || (tokens.starts_with(&[
            "cfg".to_owned(),
            "(".to_owned(),
            "all".to_owned(),
            "(".to_owned(),
        ]) && tokens.iter().any(|token| token == "test")
            && !tokens.iter().any(|token| token == "not"))
}

fn is_identifier(value: &str) -> bool {
    value
        .chars()
        .next()
        .is_some_and(|character| character == '_' || character.is_alphabetic())
        && value
            .chars()
            .all(|character| character == '_' || character.is_alphanumeric())
}

fn skip_line_comment(source: &str, mut index: usize) -> usize {
    while index < source.len() {
        let (character, width) = next_char(source, index);
        index += width;
        if character == '\n' {
            break;
        }
    }
    index
}

fn skip_block_comment(source: &str, mut index: usize) -> Result<usize, SourceScanError> {
    let mut depth = 1;
    while index < source.len() {
        if source[index..].starts_with("/*") {
            depth += 1;
            index += 2;
        } else if source[index..].starts_with("*/") {
            depth -= 1;
            index += 2;
            if depth == 0 {
                return Ok(index);
            }
        } else {
            index += next_char(source, index).1;
        }
    }
    Err(SourceScanError::BlockComment)
}

fn parse_raw_string(
    source: &str,
    index: usize,
) -> Option<Result<(usize, String), SourceScanError>> {
    let prefix_len = ["br", "rb", "cr", "rc", "r"]
        .iter()
        .find(|prefix| source[index..].starts_with(**prefix))
        .map(|prefix| prefix.len())?;
    let mut quote = index + prefix_len;
    while source.as_bytes().get(quote) == Some(&b'#') {
        quote += 1;
    }
    if source.as_bytes().get(quote) != Some(&b'"') {
        return None;
    }

    let hash_count = quote - index - prefix_len;
    let content_start = quote + 1;
    let mut cursor = content_start;
    while cursor < source.len() {
        if source.as_bytes()[cursor] == b'"' {
            let hashes_end = cursor + 1 + hash_count;
            if source
                .as_bytes()
                .get(cursor + 1..hashes_end)
                .is_some_and(|hashes| hashes.iter().all(|hash| *hash == b'#'))
            {
                return Some(Ok((hashes_end, source[content_start..cursor].to_owned())));
            }
        }
        cursor += next_char(source, cursor).1;
    }
    Some(Err(SourceScanError::RawString))
}

fn quoted_string_start(source: &str, index: usize) -> Option<usize> {
    for prefix in ["b", "c", ""] {
        let quote = index + prefix.len();
        if source[index..].starts_with(prefix) && source.as_bytes().get(quote) == Some(&b'"') {
            return Some(quote);
        }
    }
    None
}

fn parse_quoted_string(source: &str, quote: usize) -> Result<(usize, String), SourceScanError> {
    let content_start = quote + 1;
    let mut index = content_start;
    while index < source.len() {
        match source.as_bytes()[index] {
            b'"' => return Ok((index + 1, source[content_start..index].to_owned())),
            b'\\' => {
                index += 1;
                if index == source.len() {
                    return Err(SourceScanError::String);
                }
                index += next_char(source, index).1;
            }
            _ => index += next_char(source, index).1,
        }
    }
    Err(SourceScanError::String)
}

fn parse_char_literal(source: &str, quote: usize) -> Option<usize> {
    let mut index = quote + 1;
    if source.as_bytes().get(index) == Some(&b'\\') {
        index += 1;
        if source.as_bytes().get(index) == Some(&b'u')
            && source.as_bytes().get(index + 1) == Some(&b'{')
        {
            index += 2;
            while source.as_bytes().get(index) != Some(&b'}') {
                index += source[index..].chars().next()?.len_utf8();
            }
            index += 1;
        } else {
            index += source[index..].chars().next()?.len_utf8();
        }
    } else {
        index += source[index..].chars().next()?.len_utf8();
    }
    (source.as_bytes().get(index) == Some(&b'\'')).then_some(index + 1)
}

fn copy_next_char(source: &str, code: &mut String, index: &mut usize) {
    let (_, width) = next_char(source, *index);
    code.push_str(&source[*index..*index + width]);
    *index += width;
}

fn next_char(source: &str, index: usize) -> (char, usize) {
    source[index..]
        .chars()
        .next()
        .map(|character| (character, character.len_utf8()))
        .expect("valid index")
}

fn push_separator(code: &mut String) {
    if code
        .chars()
        .last()
        .is_some_and(|character| !character.is_whitespace())
    {
        code.push(' ');
    }
}
