#[test]
fn text_generation_receipt_phase_tags_remain_byte_stable_and_fail_closed() {
    let codec = TextGenerationReceiptCodec;
    for (phase, expected_tag) in [
        (TextGenerationPhase::Started, 0x00),
        (TextGenerationPhase::Completed, 0x01),
        (TextGenerationPhase::Rejected, 0x02),
        (TextGenerationPhase::ProhibitedInputRejected, 0x03),
    ] {
        let receipt = text_receipt(phase);
        let bytes = codec.encode(&receipt).unwrap();
        assert_eq!(bytes[2], expected_tag);
        assert_eq!(codec.decode(&bytes).unwrap(), receipt);
    }

    let mut unknown_phase = codec
        .encode(&text_receipt(TextGenerationPhase::Started))
        .unwrap();
    unknown_phase[2] = 0xff;
    assert!(matches!(
        codec.decode(&unknown_phase),
        Err(StoreCodecError::UnknownTag {
            context: "TextGenerationPhase",
            ..
        })
    ));

    let mut trailing = codec
        .encode(&text_receipt(TextGenerationPhase::Rejected))
        .unwrap();
    trailing.push(0);
    assert_eq!(
        codec.decode(&trailing),
        Err(StoreCodecError::TrailingBytes { remaining: 1 })
    );
}
