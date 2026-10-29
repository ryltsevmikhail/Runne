use self::attributes::{attribute_start, module_attributes, validate_non_module_attributes};
use self::tokens::{closing, group_open, ident, matching, punct};
use super::super::lexer::{StringKind, Token};
use std::path::PathBuf;

#[path = "attributes.rs"]
mod attributes;
#[path = "tokens.rs"]
mod tokens;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::closure) struct ModuleDeclaration {
    pub(in crate::closure) name: String,
    pub(in crate::closure) path: Option<String>,
    pub(in crate::closure) cfg_test: bool,
    pub(in crate::closure) directory: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::closure) struct ItemInclude {
    pub(in crate::closure) path: String,
    pub(in crate::closure) token_index: usize,
}

#[derive(Default)]
struct ParsedItems {
    declarations: Vec<ModuleDeclaration>,
    includes: Vec<ItemInclude>,
    cfg_test_ranges: Vec<(usize, usize)>,
}

pub(in crate::closure) fn declarations(tokens: &[Token]) -> Result<Vec<ModuleDeclaration>, String> {
    Ok(analyze(tokens)?.declarations)
}

pub(in crate::closure) fn item_includes(
    path: &str,
    tokens: &[Token],
) -> Result<Vec<ItemInclude>, String> {
    let includes = analyze(tokens)?.includes;
    if !includes.is_empty() && path != COMPOSITION {
        return Err("parser: include source is not approved".to_owned());
    }
    Ok(includes)
}

pub(in crate::closure) fn production_tokens(tokens: &[Token]) -> Result<Vec<Token>, String> {
    let ranges = analyze(tokens)?.cfg_test_ranges;
    Ok(tokens
        .iter()
        .enumerate()
        .filter(|(index, _)| {
            !ranges
                .iter()
                .any(|(start, end)| start <= index && index < end)
        })
        .map(|(_, token)| token.clone())
        .collect())
}

const COMPOSITION: &str = "crates/runne-daemon/src/canonical_provider/composition.rs";
const KNOWN_INCLUDE: &str = "composition/secondary_catalog_install.rs";

fn analyze(tokens: &[Token]) -> Result<ParsedItems, String> {
    let mut parsed = ParsedItems::default();
    parse_scope(tokens, 0, tokens.len(), PathBuf::new(), &mut parsed)?;
    Ok(parsed)
}

fn parse_scope(
    tokens: &[Token],
    mut index: usize,
    end: usize,
    directory: PathBuf,
    parsed: &mut ParsedItems,
) -> Result<(), String> {
    let mut attributes = Vec::new();
    let mut attribute_item_start = None;
    while index < end {
        if attribute_start(tokens, index) {
            attribute_item_start.get_or_insert(index);
            let open = index + usize::from(punct(tokens.get(index + 1), '!')) + 1;
            let close = matching(tokens, open, '[', ']')?;
            attributes.push(tokens[open + 1..close].to_vec());
            index = close + 1;
            continue;
        }
        let mut item = index;
        if ident(tokens.get(item), "pub") {
            item += 1;
            if punct(tokens.get(item), '(') {
                item = matching(tokens, item, '(', ')')? + 1;
            }
        }
        if ident(tokens.get(item), "mod") {
            let item_start = attribute_item_start.unwrap_or(index);
            index = parse_module(
                tokens,
                item,
                end,
                directory.clone(),
                item_start,
                attributes,
                parsed,
            )?;
            attributes = Vec::new();
            attribute_item_start = None;
            continue;
        }
        if macro_at(tokens, item, end) {
            if attributes.is_empty()
                && let Some((include, next)) = known_include(tokens, item, end)?
            {
                parsed.includes.push(include);
                index = next;
                continue;
            }
            return Err(format!(
                "parser at token {item}: unresolved item-position macro"
            ));
        }
        validate_non_module_attributes(&attributes)?;
        attributes.clear();
        attribute_item_start = None;
        if item_starts(tokens.get(item)) {
            index = skip_item(tokens, item, end)?;
        } else if let Some(open) = group_open(tokens.get(index)) {
            index = matching(tokens, index, open, closing(open))? + 1;
        } else if punct(tokens.get(index), '}') {
            return Err(format!("parser at token {index}: unexpected closing group"));
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn parse_module(
    tokens: &[Token],
    module: usize,
    end: usize,
    directory: PathBuf,
    item_start: usize,
    attributes: Vec<Vec<Token>>,
    parsed: &mut ParsedItems,
) -> Result<usize, String> {
    let Some(Token::Ident(name)) = tokens.get(module + 1) else {
        return Err(format!("parser at token {module}: module name is missing"));
    };
    let (cfg_test, path) = module_attributes(&attributes)?;
    let next = module + 2;
    match tokens.get(next) {
        Some(Token::Punct(';')) => {
            parsed.declarations.push(ModuleDeclaration {
                name: name.clone(),
                path,
                cfg_test,
                directory,
            });
            Ok(next + 1)
        }
        Some(Token::Punct('{')) => {
            let close = matching(tokens, next, '{', '}')?;
            if cfg_test {
                parsed.cfg_test_ranges.push((item_start, close + 1));
            } else {
                parse_scope(tokens, next + 1, close, directory.join(name), parsed)?;
            }
            Ok(close + 1)
        }
        _ if next >= end => Err(format!(
            "parser at token {module}: module terminator is missing"
        )),
        _ => Err(format!(
            "parser at token {module}: invalid module declaration"
        )),
    }
}

fn macro_at(tokens: &[Token], mut index: usize, end: usize) -> bool {
    if !matches!(tokens.get(index), Some(Token::Ident(_))) {
        return false;
    }
    index += 1;
    while index + 2 < end && punct(tokens.get(index), ':') && punct(tokens.get(index + 1), ':') {
        if !matches!(tokens.get(index + 2), Some(Token::Ident(_))) {
            return false;
        }
        index += 3;
    }
    punct(tokens.get(index), '!') && group_open(tokens.get(index + 1)).is_some()
}

fn known_include(
    tokens: &[Token],
    index: usize,
    end: usize,
) -> Result<Option<(ItemInclude, usize)>, String> {
    if ident(tokens.get(index), "include")
        && punct(tokens.get(index + 1), '!')
        && punct(tokens.get(index + 2), '(')
        && let [
            Token::String {
                value,
                kind: StringKind::Ordinary,
            },
            Token::Punct(')'),
        ] = tokens
            .get(index + 3..index + 5)
            .ok_or("parser: truncated include")?
        && value == KNOWN_INCLUDE
    {
        let after = if punct(tokens.get(index + 5), ';') {
            index + 6
        } else {
            index + 5
        };
        return Ok(Some((
            ItemInclude {
                path: value.clone(),
                token_index: index,
            },
            after.min(end),
        )));
    }
    Ok(None)
}

fn item_starts(token: Option<&Token>) -> bool {
    matches!(
        token,
        Some(Token::Ident(name))
            if matches!(
                name.as_str(),
                "const" | "enum" | "extern" | "fn" | "impl" | "static" | "struct" | "trait" | "type" | "union" | "use"
            )
    )
}

fn skip_item(tokens: &[Token], mut index: usize, end: usize) -> Result<usize, String> {
    let body_item = match tokens.get(index) {
        Some(Token::Ident(name)) if name == "const" => ident(tokens.get(index + 1), "fn"),
        Some(Token::Ident(name)) => matches!(
            name.as_str(),
            "enum" | "extern" | "fn" | "impl" | "struct" | "trait" | "union"
        ),
        _ => false,
    };
    while index < end {
        if punct(tokens.get(index), ';') {
            return Ok(index + 1);
        }
        if let Some(open) = group_open(tokens.get(index)) {
            let close = matching(tokens, index, open, closing(open))?;
            if open == '{' && body_item {
                return Ok(close + 1);
            }
            index = close + 1;
        } else {
            index += 1;
        }
    }
    Err("parser: unterminated item".to_owned())
}
