use proc_macro2::Span;

pub(super) fn child(parent: &[String], name: &str, span: Span) -> Vec<String> {
    let start = span.start();
    let mut scope = parent.to_vec();
    scope.push(format!("{name}@{}:{}", start.line, start.column));
    scope
}

pub(super) fn position(span: Span) -> usize {
    let start = span.start();
    start
        .line
        .saturating_mul(1_000_000)
        .saturating_add(start.column)
}
