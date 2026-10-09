pub(super) const ADMIN_ROLE_SQL: &str = include_str!("admin_role.sql");
pub(super) const ADMIN_COMMANDS_SQL: &str = include_str!("admin_commands.sql");
pub(super) const ADMIN_RECEIPTS_SQL: &str = include_str!("admin_receipts.sql");
pub(super) const ADMIN_TRIGGERS_SQL: &str = include_str!("admin_triggers.sql");

pub(super) fn expected_objects() -> Vec<(&'static str, &'static str, &'static str)> {
    let mut objects = vec![
        ("table", "managed_policy_administrator", ADMIN_ROLE_SQL),
        ("table", "managed_policy_admin_commands", ADMIN_COMMANDS_SQL),
        ("table", "managed_policy_admin_receipts", ADMIN_RECEIPTS_SQL),
    ];
    for section in ADMIN_TRIGGERS_SQL.split("-- object: ").skip(1) {
        let Some((header, body)) = section.split_once('\n') else {
            continue;
        };
        let mut fields = header.split_whitespace();
        let (Some(kind), Some(name)) = (fields.next(), fields.next()) else {
            continue;
        };
        let sql = body
            .trim()
            .strip_suffix(';')
            .unwrap_or(body.trim())
            .trim_end();
        objects.push((
            if kind == "trigger" {
                "trigger"
            } else {
                "unknown"
            },
            name,
            sql,
        ));
    }
    objects.sort_by(|left, right| left.0.cmp(right.0).then_with(|| left.1.cmp(right.1)));
    objects
}
