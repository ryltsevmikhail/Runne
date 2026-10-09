use std::ffi::CString;

pub(super) fn approved_target_race_environment() -> Vec<CString> {
    if std::env::var("RUNNE_TEST_T1_TRUST_COMPOSITION").as_deref() != Ok("1")
        || std::env::var("RUNNE_TEST_T1_APPROVED_TARGET_RACE").as_deref() != Ok("1")
        || std::env::var("RUNNE_TEST_D2_TOOL_SCENARIO").as_deref()
            != Ok("approved-target-create-race")
    {
        return Vec::new();
    }
    vec![
        CString::new("RUNNE_TEST_T1_TRUST_COMPOSITION=1").expect("fixed helper env"),
        CString::new("RUNNE_TEST_T1_APPROVED_TARGET_RACE=1").expect("fixed helper env"),
        CString::new("RUNNE_TEST_D2_TOOL_SCENARIO=approved-target-create-race")
            .expect("fixed helper env"),
    ]
}
