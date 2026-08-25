pub(crate) const fn sensitivity_label(
    sensitivity: runne_domain::event::Sensitivity,
) -> &'static str {
    match sensitivity {
        runne_domain::event::Sensitivity::Public => "public",
        runne_domain::event::Sensitivity::Internal => "internal",
        runne_domain::event::Sensitivity::Sensitive => "sensitive",
    }
}
