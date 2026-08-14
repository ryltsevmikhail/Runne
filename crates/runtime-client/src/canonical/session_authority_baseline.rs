impl RuntimeSessionAuthority {
    pub(crate) fn replay_baseline_v2_authenticator(
        &self,
    ) -> Result<gocode_api::replay::ReplayBaselineV2Authenticator, ()> {
        let binding = self.replay_binding.clone().ok_or(())?;
        gocode_api::replay::ReplayBaselineV2Authenticator::from_native_rust_tcb(
            **self.bytes,
            binding,
        )
        .map_err(|_| ())
    }

    #[allow(dead_code)] // consumed by the replay HTTP parser in the next wire slice
    pub(crate) fn replay_baseline_mac(
        &self,
        binding_digest: [u8; 32],
        wire: &gocode_api::ReplayRetentionBaselineWireV1,
    ) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<sha2::Sha256>;
        let mut derive =
            HmacSha256::new_from_slice(self.bytes.as_ref().as_ref()).expect("fixed HMAC key");
        derive.update(gocode_api::REPLAY_RETENTION_BASELINE_KEY_DOMAIN_V1);
        derive.update(&binding_digest);
        let key: [u8; 32] = derive.finalize().into_bytes().into();
        let mut mac = HmacSha256::new_from_slice(&key).expect("fixed HMAC key");
        mac.update(&gocode_api::replay_retention_baseline_transcript(wire));
        mac.finalize().into_bytes().into()
    }
}
