pub(super) fn assert_receipt_and_content_clear(receipt: &[u8], content: &[u8]) {
    crate::safe_tool_helper::credential_companion_test_support::assert_receipt_and_content_clear(
        receipt, content,
    );
}
