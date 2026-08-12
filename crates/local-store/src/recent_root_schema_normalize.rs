pub fn normalize_sql(sql: &str) -> String {
    let mut output = String::with_capacity(sql.len());
    let mut quote = None;
    let mut characters = sql.chars().peekable();
    while let Some(character) = characters.next() {
        match quote {
            Some(delimiter) => {
                output.push(character);
                if character == delimiter {
                    if characters.peek().copied() == Some(delimiter) {
                        output.push(characters.next().expect("escaped delimiter"));
                    } else {
                        quote = None;
                    }
                }
            }
            None if character.is_whitespace() => {}
            None if matches!(character, '\'' | '"' | '`') => {
                output.push(character);
                quote = Some(character);
            }
            None if character == '[' => {
                output.push(character);
                quote = Some(']');
            }
            None => output.push(character.to_ascii_lowercase()),
        }
    }
    output
}
