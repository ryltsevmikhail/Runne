/// Records a versioned tuple of closed `DeepSeek` decoder ordinals.
///
/// The caller supplies only enum codes; every dimension is range-checked before writing.
pub fn record_deepseek_decode_detail(ordinals: (u8, u8, u8, u8, u8)) {
    let (phase, event, node, field, issue) = ordinals;
    if phase > 3 || event > 18 || node > 10 || field > 47 || issue > 19 {
        return;
    }
    let Ok(Some(root)) = fixture_root_from_env() else {
        return;
    };
    let line = format!(
        "deepseek_decode_detail_v1 phase={phase} event={event} node={node} field={field} issue={issue}"
    );
    append_diagnostic_line(&root, &line);
}
