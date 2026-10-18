use runne_api::{PermissionControlModeChallengeV1, PermissionModeSelectionV1};

#[expect(
    clippy::redundant_pub_crate,
    reason = "The private module re-exports this helper only within the crate."
)]
pub(crate) fn warning_message(challenge: &PermissionControlModeChallengeV1) -> String {
    let mode = match challenge.requested_mode {
        PermissionModeSelectionV1::AskAlways => {
            "Ask always (Запрашивать разрешение)\nRunne asks before each action that needs permission."
        }
        PermissionModeSelectionV1::RiskBased => {
            "Risk-based (Подтверждать за меня)\nRunne may allow actions under the current risk policy."
        }
        PermissionModeSelectionV1::FullAccess => {
            "Full access (Полный доступ)\nRunne may broadly access this user's files, run processes, and use the network. Managed Ask/Deny rules and OS limits still apply; fresh OS authentication is required."
        }
    };
    let expiry = format_mode_expiry(challenge.mode_expires_at_unix_ms);
    format!(
        "Workspace: {}\nWorkspace ID: {}\nPrincipal: {}\nRequested mode: {mode}\nMode expiry: {expiry}\n\nNative warning version {}. Continue only if you intend to change this permission mode.",
        sanitize_warning_text(&challenge.workspace_label),
        uuid::Uuid::from_bytes(challenge.workspace_id),
        sanitize_warning_text(&challenge.principal),
        challenge.native_warning_version,
    )
}

fn sanitize_warning_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if is_subject_format_control(character) {
                ' '
            } else {
                character
            }
        })
        .collect()
}

fn is_subject_format_control(character: char) -> bool {
    character.is_control()
        || matches!(
            character as u32,
            0x200e | 0x200f | 0x202a..=0x202e | 0x2066..=0x2069
        )
}

fn format_mode_expiry(value: Option<u64>) -> String {
    let Some(milliseconds) = value else {
        return "never".to_owned();
    };
    i64::try_from(milliseconds / 1_000)
        .ok()
        .and_then(|seconds| gtk::glib::DateTime::from_unix_utc(seconds).ok())
        .and_then(|date_time| date_time.format("%Y-%m-%d %H:%M:%S").ok())
        .map_or_else(
            || format!("Unix ms {milliseconds}"),
            |date_time| format!("{date_time}.{:03} UTC", milliseconds % 1_000),
        )
}
