#[test]
fn process_generation_activation_releases_coordinators_in_order() {
    let body = function_body(
        include_str!("../runtime/process_activation.rs"),
        "activate_process_generation",
    );
    let authorization_statement = body.find("let mut authorization = composition").unwrap();
    let statement_end =
        authorization_statement + body[authorization_statement..].find("?;").unwrap() + 2;
    let suffix: String = body[statement_end..]
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();

    assert_eq!(
        suffix,
        "generation.apply_retaining_lock();authorization.apply_retaining_lock();*process_generation=Some(binding.generation());drop(generation);drop(authorization);Ok(())"
    );
}

fn function_body<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source.find(&format!("fn {name}(")).unwrap();
    let opening = start + source[start..].find('{').unwrap();
    let mut depth = 0;
    for (offset, character) in source[opening..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[opening + 1..opening + offset];
                }
            }
            _ => {}
        }
    }
    panic!("function body is not closed")
}
