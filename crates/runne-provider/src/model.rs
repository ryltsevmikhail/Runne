include!("model/model_ref.rs");
include!("model/call.rs");
include!("model/extensions.rs");

#[cfg(test)]
mod digest_tests {
    use super::ModelRef;
    use crate::ProviderId;

    #[test]
    fn model_ref_digest_binds_each_exact_tuple_field() {
        let provider = ProviderId::new("openai-background").unwrap();
        let original = ModelRef::new(provider.clone(), "gpt-5.5", "2026-04-23").unwrap();
        assert_eq!(
            original.digest_v1(),
            ModelRef::new(provider.clone(), "gpt-5.5", "2026-04-23")
                .unwrap()
                .digest_v1()
        );
        assert_ne!(
            original.digest_v1(),
            ModelRef::new(provider.clone(), "gpt-5.5", "latest")
                .unwrap()
                .digest_v1()
        );
        assert_ne!(
            original.digest_v1(),
            ModelRef::new(ProviderId::new("openai").unwrap(), "gpt-5.5", "2026-04-23")
                .unwrap()
                .digest_v1()
        );
        assert_ne!(
            original.digest_v1(),
            ModelRef::new(provider, "gpt-5.4", "2026-04-23")
                .unwrap()
                .digest_v1()
        );
    }
}
