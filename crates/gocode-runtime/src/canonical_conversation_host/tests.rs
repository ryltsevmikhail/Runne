    use super::*;

    #[test]
    fn deterministic_provider_is_stable_and_keeps_large_output_bounded() {
        let provider = DeterministicTextProvider;
        assert_eq!(
            provider
                .generate(&MessageText::new("hello").unwrap())
                .unwrap(),
            MessageText::new("GOCODE local response: hello").unwrap()
        );

        let maximum = MessageText::new("x".repeat(MAX_MESSAGE_TEXT_BYTES)).unwrap();
        let first = provider.generate(&maximum).unwrap();
        let second = provider.generate(&maximum).unwrap();
        assert_eq!(first, second);
        assert!(first.as_str().len() <= MAX_MESSAGE_TEXT_BYTES);
        assert!(first.as_str().starts_with(LOCAL_RESPONSE_PREFIX));
    }
