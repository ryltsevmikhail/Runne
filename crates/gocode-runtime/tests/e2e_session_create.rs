//! L2-I: exact `POST /session` compatibility flow over real SQLite adapters.

#[path = "../../gocode-store/tests/support/validated_reopen.rs"]
mod validated_reopen;

include!("e2e_session_create_split_parts/part_01.rs");
include!("e2e_session_create_split_parts/part_02.rs");
