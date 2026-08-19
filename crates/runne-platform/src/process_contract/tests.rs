use super::{NATIVE_SANDBOX_STATUS, PROCESS_CONTRACT_STATUS};

#[test]
fn statuses_remain_contract_only() {
    assert_eq!(PROCESS_CONTRACT_STATUS, "CONTRACT_ONLY");
    assert_eq!(NATIVE_SANDBOX_STATUS, "NATIVE_SANDBOX_NOT_QUALIFIED");
}
