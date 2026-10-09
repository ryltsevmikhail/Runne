use serde_json::Value;

pub(super) fn valid_projection(value: &Value, has_pending: bool) -> bool {
    let allowed = if has_pending {
        vec![
            "selectedMode",
            "effective",
            "authorizationRevision",
            "presetVersion",
            "managedPolicyVersion",
            "pendingApprovalIds",
            "containment",
            "networkState",
            "expiresAtUnixMs",
        ]
    } else {
        vec![
            "selectedMode",
            "effective",
            "authorizationRevision",
            "presetVersion",
            "managedPolicyVersion",
            "containment",
            "networkState",
            "expiresAtUnixMs",
        ]
    };
    let Some(effective) = value.get("effective") else {
        return false;
    };
    if !only_keys(value, &allowed) {
        return false;
    }
    let Some(state) = effective.get("state").and_then(Value::as_str) else {
        return false;
    };
    match state {
        "notReady" => only_keys(effective, &["state", "reason"]),
        "ready" => only_keys(
            effective,
            &[
                "state",
                "mode",
                "preset_version",
                "scope_digest",
                "containment",
            ],
        ),
        _ => false,
    }
}

fn only_keys(value: &Value, allowed: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.keys().all(|key| allowed.contains(&key.as_str())))
}
