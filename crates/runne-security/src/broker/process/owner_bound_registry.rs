use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct OwnerBoundLaunchKey {
    owner: [u8; 16],
    attempt: [u8; 16],
    session: [u8; 16],
    generation: [u8; 16],
    tree_handle: [u8; 16],
    invocation: [u8; 16],
}

impl OwnerBoundLaunchKey {
    fn new(binding: &ProcessLifecycleBindingV1, invocation: ProcessInvocationIdV1) -> Self {
        Self {
            owner: *binding.owner().as_bytes(),
            attempt: *binding.attempt().as_bytes(),
            session: *binding.session().as_bytes(),
            generation: *binding.generation().as_bytes(),
            tree_handle: *binding.tree_handle().as_bytes(),
            invocation: invocation.as_bytes(),
        }
    }
}

enum OwnerBoundRegistryEntry {
    Launching { intent_digest: [u8; 32] },
    Active {
        handle: OwnedProcessHandleV1,
        intent_digest: [u8; 32],
    },
    Stopping {
        handle: OwnedProcessHandleV1,
        intent_digest: [u8; 32],
    },
    Uncertain {
        handle: OwnedProcessHandleV1,
        intent_digest: [u8; 32],
    },
}

fn process_intent_digest(
    spec: &ProcessSpec,
    prepared: &ProcessPlatformRequestV1,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"runne.owner-bound-process-intent.v1\0");
    digest_field(&mut digest, prepared.request_digest());
    digest_field(
        &mut digest,
        prepared.executable().identity().filesystem_identity_digest(),
    );
    digest_field(
        &mut digest,
        prepared.cwd().identity().filesystem_identity_digest(),
    );
    digest_field(&mut digest, spec.executable.as_bytes());
    digest_field(&mut digest, spec.executable_digest.as_ref().map_or(&[], AsRef::as_ref));
    digest.update((spec.argv.len() as u64).to_be_bytes());
    for argument in &spec.argv {
        digest_field(&mut digest, argument.as_bytes());
    }
    let mut environment = spec.env.iter().collect::<Vec<_>>();
    environment.sort_unstable_by_key(|(key, _)| key.as_str());
    digest.update((environment.len() as u64).to_be_bytes());
    for (key, value) in environment {
        digest_field(&mut digest, key.as_bytes());
        digest_field(&mut digest, value.as_bytes());
    }
    digest.update((spec.allowed_env_keys.len() as u64).to_be_bytes());
    for key in &spec.allowed_env_keys {
        digest_field(&mut digest, key.as_bytes());
    }
    digest.update([u8::from(spec.inherit_environment)]);
    digest_field(&mut digest, spec.cwd.as_bytes());
    digest_field(
        &mut digest,
        spec.authorized_cwd.as_deref().map_or(&[], str::as_bytes),
    );
    digest_field(
        &mut digest,
        spec.cleanup_reservation_id.as_deref().map_or(&[], str::as_bytes),
    );
    digest.update(spec.worker_generation.to_be_bytes());
    digest.update(spec.expected_generation.to_be_bytes());
    digest.update(spec.timeout_ms.to_be_bytes());
    digest.update([match spec.command_policy {
        CommandPolicy::StructuredOnly => 1,
        CommandPolicy::Forbidden => 2,
    }]);
    digest.finalize().into()
}

fn digest_field(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}
