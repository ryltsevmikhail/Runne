use super::super::super::lexer::Token;

pub(super) fn matching(
    tokens: &[Token],
    start: usize,
    open: char,
    close: char,
) -> Result<usize, String> {
    let mut depth = 0;
    for (index, token) in tokens.iter().enumerate().skip(start) {
        if punct(Some(token), open) {
            depth += 1;
        } else if punct(Some(token), close) {
            depth -= 1;
            if depth == 0 {
                return Ok(index);
            }
        }
    }
    Err(format!(
        "parser at token {start}: unterminated `{open}` group"
    ))
}

pub(super) fn ident(token: Option<&Token>, expected: &str) -> bool {
    matches!(token, Some(Token::Ident(value)) if value == expected)
}

pub(super) fn punct(token: Option<&Token>, expected: char) -> bool {
    matches!(token, Some(Token::Punct(value)) if *value == expected)
}

pub(super) fn group_open(token: Option<&Token>) -> Option<char> {
    match token {
        Some(Token::Punct(open @ ('(' | '[' | '{'))) => Some(*open),
        _ => None,
    }
}

pub(super) fn closing(open: char) -> char {
    match open {
        '(' => ')',
        '[' => ']',
        '{' => '}',
        _ => unreachable!(),
    }
}
