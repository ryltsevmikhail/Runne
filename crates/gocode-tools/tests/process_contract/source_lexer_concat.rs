pub(super) fn concat_literals(source: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut remaining = source;
    while let Some(offset) = remaining.find("concat!") {
        remaining = &remaining[offset + "concat!".len()..];
        let Some(arguments) = remaining.trim_start().strip_prefix('(') else {
            continue;
        };
        let Some((value, rest)) = literal_arguments(arguments) else {
            continue;
        };
        values.push(value);
        remaining = rest;
    }
    values
}

fn literal_arguments(source: &str) -> Option<(String, &str)> {
    let mut value = String::new();
    let mut source = source.trim_start();
    loop {
        let (literal, rest) = quoted_literal(source)?;
        value.push_str(literal);
        source = rest.trim_start();
        if let Some(rest) = source.strip_prefix(')') {
            return Some((value, rest));
        }
        source = source.strip_prefix(',')?.trim_start();
    }
}

fn quoted_literal(source: &str) -> Option<(&str, &str)> {
    let source = source.strip_prefix('"')?;
    let mut escaped = false;
    for (index, character) in source.char_indices() {
        if character == '"' && !escaped {
            return Some((&source[..index], &source[index + 1..]));
        }
        escaped = character == '\\' && !escaped;
        if character != '\\' {
            escaped = false;
        }
    }
    None
}
