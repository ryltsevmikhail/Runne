impl RuntimeSessionBinding {
    /// Returns the canonical digest covering all stable, ephemeral and TLS
    /// certificate binding fields for one authenticated runtime session.
    pub fn canonical_digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        let stable = self.stable();
        let ephemeral = self.ephemeral();
        let mut hasher = Sha256::new();
        hasher.update(b"gocode.runtime-session-binding.v1\0");
        frame(&mut hasher, stable.authority_id());
        frame(&mut hasher, stable.principal_id().as_str().as_bytes());
        frame(&mut hasher, stable.lineage_id().as_bytes());
        frame(&mut hasher, stable.profile_id().as_bytes());
        frame(&mut hasher, stable.schema_hash());
        frame(&mut hasher, stable.capability_digest());
        frame(&mut hasher, ephemeral.daemon_instance_id().as_bytes());
        frame(&mut hasher, &ephemeral.launch_generation().to_be_bytes());
        frame(&mut hasher, ephemeral.session_id());
        frame(&mut hasher, &ephemeral.authorization_epoch().to_be_bytes());
        frame(
            &mut hasher,
            &[sensitivity_code(ephemeral.sensitivity_ceiling())],
        );
        frame(&mut hasher, self.certificate_sha256());
        hasher.finalize().into()
    }
}

fn frame(hasher: &mut sha2::Sha256, bytes: &[u8]) {
    use sha2::Digest;
    hasher.update(
        u32::try_from(bytes.len())
            .expect("runtime binding fields are bounded")
            .to_be_bytes(),
    );
    hasher.update(bytes);
}

const fn sensitivity_code(value: runne_domain::event::Sensitivity) -> u8 {
    match value {
        runne_domain::event::Sensitivity::Public => 1,
        runne_domain::event::Sensitivity::Internal => 2,
        runne_domain::event::Sensitivity::Sensitive => 3,
    }
}
