use std::os::unix::net::UnixStream;

use runne_api::{
    ActivationDispositionV1, CredentialBrokerTransferAuthenticator, ExecutableIdentityV1,
    LaunchSecret, PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID,
    ProtectedCredentialEnrollmentLaunchBindingV1, ProtectedCredentialEnrollmentLaunchRequestV3,
    ProtectedCredentialEnrollmentPreludeV2, ProtectedCredentialEnrollmentPrepareV2,
    ProtectedLaunchRequestV1, ProtectedLaunchRequestV2, ProtectedOwnedLaunchV2, ProtectedReadyV1,
    ProtectedRuntimeProfileV1, ProviderActivationBindingV1, StableRuntimeBindingV1,
};

use super::super::{ProtectedActivationChannel, V2TransitionInput, transition_with};

pub(super) fn id(byte: u8) -> [u8; 16] {
    let mut value = [byte; 16];
    value[6] = 0x70 | (byte & 0x0f);
    value[8] = 0x80 | (byte & 0x3f);
    value
}

fn profile() -> ProtectedRuntimeProfileV1 {
    ProtectedRuntimeProfileV1::new(
        PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID,
        1,
        "fixture",
        [1; 32],
        [2; 32],
    )
    .unwrap()
}

pub(super) fn launch(
    runtime_root: &str,
    secret: [u8; 32],
    authority: [u8; 16],
    host: [u8; 16],
    disposition: ActivationDispositionV1,
) -> ProtectedLaunchRequestV1 {
    launch_with(
        runtime_root,
        secret,
        authority,
        host,
        disposition,
        profile(),
        ExecutableIdentityV1::new([4; 32], [5; 32], 1).unwrap(),
    )
}

pub(super) fn launch_with(
    runtime_root: &str,
    secret: [u8; 32],
    authority: [u8; 16],
    host: [u8; 16],
    disposition: ActivationDispositionV1,
    profile: ProtectedRuntimeProfileV1,
    executable: ExecutableIdentityV1,
) -> ProtectedLaunchRequestV1 {
    ProtectedLaunchRequestV1::new(
        authority,
        host,
        LaunchSecret::from_bytes(secret).unwrap(),
        10,
        20,
        "local-owner",
        profile,
        executable,
        runtime_root.into(),
        disposition,
    )
    .unwrap()
}

pub(super) struct Fixture {
    pub(super) original: ProtectedLaunchRequestV2,
    pub(super) owned: ProtectedOwnedLaunchV2,
    prepare: ProtectedCredentialEnrollmentPrepareV2,
    prelude: ProtectedCredentialEnrollmentPreludeV2,
    pub(super) keys: runne_api::ProtectedActivationKeys,
    pub(super) binding: ProtectedCredentialEnrollmentLaunchBindingV1,
    _client: UnixStream,
    pub(super) channel: ProtectedActivationChannel,
}

pub(super) struct TestInput<'a> {
    pub(super) original: &'a ProtectedLaunchRequestV2,
    pub(super) owned: &'a ProtectedOwnedLaunchV2,
    pub(super) keys: &'a runne_api::ProtectedActivationKeys,
    pub(super) last_sequence: u64,
    pub(super) now: u64,
}

impl Fixture {
    pub(super) fn new() -> Self {
        let request = launch(
            "/tmp/runtime",
            [3; 32],
            id(1),
            id(2),
            ActivationDispositionV1::FirstActivation,
        );
        let keys = request.derive_keys();
        let stable =
            StableRuntimeBindingV1::new(id(10), "local-owner", id(11), "fixture", [1; 32], [2; 32])
                .unwrap();
        let ready = ProtectedReadyV1::new(
            id(1),
            id(2),
            request.executable().clone(),
            profile(),
            stable,
            id(12),
            1,
            id(13),
            "https://127.0.0.1",
            [14; 32],
            vec![15],
            vec!["provider.enroll".into()],
        )
        .unwrap();
        let provider = ProviderActivationBindingV1::openai_responses_text_v1();
        let original = ProtectedLaunchRequestV2::new(request.clone(), provider.clone()).unwrap();
        let owned = ProtectedOwnedLaunchV2::new(ready.owned_launch(), provider.clone()).unwrap();
        let mut prepare = ProtectedCredentialEnrollmentPrepareV2::new(
            owned.clone(),
            1,
            [21; 32],
            [7; 32],
            [8; 32],
            [9; 32],
            1,
        )
        .unwrap();
        prepare.sign(&keys);
        let daemon_prelude = runne_api::DaemonEnrollmentLaunchPreludeV1::macos_arm64(
            id(1),
            id(2),
            [22; 32],
            [23; 32],
            [24; 32],
            [6; 32],
            [9; 32],
            1,
            10,
            20,
        )
        .unwrap();
        let mut prelude =
            ProtectedCredentialEnrollmentPreludeV2::new(&prepare, [25; 32], daemon_prelude.clone())
                .unwrap();
        prelude.sign(&keys);
        let commitment = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys)
            .enrollment_launch_commitment(&daemon_prelude);
        let binding = ProtectedCredentialEnrollmentLaunchBindingV1::macos_apple_silicon(
            [6; 32], [7; 32], [8; 32], [9; 32], 1, commitment,
        )
        .unwrap();
        let (client, stream) = UnixStream::pair().unwrap();
        Self {
            original,
            owned,
            prepare,
            prelude,
            keys,
            binding,
            _client: client,
            channel: ProtectedActivationChannel::new(stream).unwrap(),
        }
    }

    pub(super) fn v3(&self, runtime_root: &str) -> ProtectedCredentialEnrollmentLaunchRequestV3 {
        self.v3_with(
            launch(
                runtime_root,
                [3; 32],
                id(1),
                id(2),
                ActivationDispositionV1::Existing(Box::new(
                    self.owned.compatibility_owned_launch().stable().clone(),
                )),
            ),
            ProviderActivationBindingV1::openai_responses_text_v1(),
            self.binding.clone(),
        )
    }

    pub(super) fn v3_with(
        &self,
        request: ProtectedLaunchRequestV1,
        provider: ProviderActivationBindingV1,
        binding: ProtectedCredentialEnrollmentLaunchBindingV1,
    ) -> ProtectedCredentialEnrollmentLaunchRequestV3 {
        ProtectedCredentialEnrollmentLaunchRequestV3::new(request, provider, binding).unwrap()
    }

    pub(super) fn binding(
        &self,
        installation: [u8; 32],
        release: [u8; 32],
        qualification: [u8; 32],
        peer: [u8; 32],
        generation: u64,
    ) -> ProtectedCredentialEnrollmentLaunchBindingV1 {
        let commitment =
            CredentialBrokerTransferAuthenticator::from_protected_activation(&self.keys)
                .enrollment_launch_commitment(self.prelude.prelude());
        ProtectedCredentialEnrollmentLaunchBindingV1::macos_apple_silicon(
            installation,
            release,
            qualification,
            peer,
            generation,
            commitment,
        )
        .unwrap()
    }

    pub(super) fn input(&self) -> TestInput<'_> {
        TestInput {
            original: &self.original,
            owned: &self.owned,
            keys: &self.keys,
            last_sequence: 0,
            now: 10,
        }
    }

    pub(super) fn admits(
        &self,
        request: ProtectedCredentialEnrollmentLaunchRequestV3,
        input: TestInput<'_>,
        native: impl FnOnce(
            &UnixStream,
            &runne_api::VerifiedProtectedCredentialEnrollmentPrepareV2<'_>,
        ) -> bool,
        channel: &ProtectedActivationChannel,
    ) -> bool {
        let input = V2TransitionInput::new(
            &self.prepare,
            &self.prelude,
            input.owned,
            input.original,
            input.last_sequence,
            input.keys,
            input.now,
            input.now,
            [6; 32],
        );
        transition_with(&input, request, native, channel).is_ok()
    }

    pub(super) fn transition(&self, request: ProtectedCredentialEnrollmentLaunchRequestV3) -> bool {
        self.admits(request, self.input(), |_, _| true, &self.channel)
    }
}
