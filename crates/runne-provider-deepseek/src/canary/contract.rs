use super::CanaryEvidence;
use core::fmt;
use sha2::{Digest, Sha256};
/// Digest of the pinned provider profile sidecar.
pub const PROFILE_DIGEST: &str =
    "sha256:b8b218277978e360460e5bc53a46081d3fd244f936d0c772e8bd1651edb1f260";
/// Digest of the single compiled canary candidate.
pub const CANARY_DIGEST: &str =
    "sha256:76147673af425fe03b473f3234a193f8173382f40f0cdb7d442fba41b49250fb";
const RAW_PROFILE_DIGEST: [u8; 32] = [
    0xb8, 0xb2, 0x18, 0x27, 0x79, 0x78, 0xe3, 0x60, 0x46, 0x0e, 0x5b, 0xc5, 0x3a, 0x46, 0x08, 0x1d,
    0x3f, 0xd2, 0x44, 0xf9, 0x36, 0xd0, 0xc7, 0x72, 0xe8, 0xbd, 0x16, 0x51, 0xed, 0xb1, 0xf2, 0x60,
];
const PROFILE_ID: &str = "runne-deepseek-responses-text/1";
const PROFILE_REVISION: u32 = 1;
const PROVIDER: &str = "deepseek";
const ORIGIN: &str = "https://api.deepseek.com";
const METHOD: &str = "POST";
const PATH: &str = "/v1/responses";
const REQUEST_MODEL: &str = "deepseek-chat";
const MODEL_ID: &str = "deepseek-chat";
const MODEL_REVISION: &str = "2026-08-16";
const SERVICE_TIER: &str = "default";
pub(super) const PRICING_REVISION: &str = "deepseek-chat-base-2026-08-16/1";
const PROMPT: &str = "Reply with exactly: OK";
const RESULT: &str = "OK";
/// Closed result of candidate preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateDisposition {
    /// The supplied identity differs from the compiled identity.
    ProfileMismatch,
    /// The supplied request policy differs from the compiled policy.
    OverlayRejected,
    /// The prepared candidate remains inactive.
    NotActivated,
}
macro_rules! identity_assertion {
    ($($name:ident, $index:literal, $expected:expr);+ $(;)?) => {$(
        #[doc = "Sets one compiled identity assertion without retaining its value."]
        #[must_use]
        pub fn $name(mut self, value: &str) -> Self { self.matches[$index] = value == $expected; self }
    )+};
}
/// Identity assertions checked without retaining supplied values.
#[derive(Clone, Copy)]
pub struct CanaryIdentity {
    matches: [bool; 12],
}
impl CanaryIdentity {
    /// Returns the exact compiled identity assertions.
    #[must_use]
    pub const fn canonical() -> Self {
        Self {
            matches: [true; 12],
        }
    }
    identity_assertion!(
        with_profile_id, 0, PROFILE_ID; with_profile_digest, 2, PROFILE_DIGEST;
        with_provider, 3, PROVIDER; with_origin, 4, ORIGIN;
        with_method, 5, METHOD; with_path, 6, PATH;
        with_request_model, 7, REQUEST_MODEL; with_model_id, 8, MODEL_ID;
        with_model_revision, 9, MODEL_REVISION; with_service_tier, 10, SERVICE_TIER;
        with_pricing_revision, 11, PRICING_REVISION;
    );
    /// Sets the compiled profile revision assertion.
    #[must_use]
    pub const fn with_profile_revision(mut self, value: u32) -> Self {
        self.matches[1] = value == PROFILE_REVISION;
        self
    }
    fn is_exact(&self) -> bool {
        self.matches.into_iter().all(core::convert::identity)
    }
}
macro_rules! policy_assertion {
    ($($name:ident, $index:literal, $expected:expr);+ $(;)?) => {$(
        #[doc = "Sets one compiled policy assertion."]
        #[must_use]
        pub const fn $name(mut self, value: bool) -> Self { self.matches[$index] = value == $expected; self }
    )+};
}
/// A policy overlay that retains input only as a match, digest, and byte length.
#[derive(Clone, Copy)]
pub struct CanaryOverlay {
    input_count: u8,
    user: bool,
    exact_prompt_match: bool,
    prompt_digest: [u8; 32],
    prompt_length: u64,
    matches: [bool; 11],
    max_output_tokens: u64,
}
impl CanaryOverlay {
    /// Returns the only approved overlay.
    #[must_use]
    pub fn approved() -> Self {
        Self::user(PROMPT)
    }
    /// Builds a one-user-entry overlay without retaining the text.
    #[must_use]
    pub fn user(text: &str) -> Self {
        Self {
            input_count: 1,
            user: true,
            exact_prompt_match: text == PROMPT,
            prompt_digest: digest(b"runne.canary.prompt/1", &[text.as_bytes()]),
            prompt_length: text.len() as u64,
            matches: [true; 11],
            max_output_tokens: 16,
        }
    }
    /// Returns an overlay without input entries.
    #[must_use]
    pub fn empty() -> Self {
        let mut value = Self::approved();
        value.input_count = 0;
        value
    }
    /// Adds a second user entry marker without retaining its text.
    #[must_use]
    pub const fn with_second_user(mut self, _text: &str) -> Self {
        self.input_count = 2;
        self
    }
    /// Returns a non-user entry marker without retaining its text.
    #[must_use]
    pub fn assistant(_text: &str) -> Self {
        let mut value = Self::approved();
        value.user = false;
        value
    }
    /// Returns a developer entry marker without retaining its text.
    #[must_use]
    pub fn developer(_text: &str) -> Self {
        Self::assistant("")
    }
    policy_assertion!(
        with_store, 0, false; with_background, 1, false; with_tools_empty, 2, true;
        with_tool_choice_none, 3, true; with_stream, 4, true;
        with_reasoning_none, 5, true; with_metadata, 6, true;
        with_previous_response, 7, true; with_retry, 8, false;
        with_redirect, 9, false; with_proxy, 10, false;
    );
    /// Sets the maximum output token assertion.
    #[must_use]
    pub const fn with_max_output_tokens(mut self, value: u64) -> Self {
        self.max_output_tokens = value;
        self
    }
    fn is_exact(&self) -> bool {
        self.input_count == 1
            && self.user
            && self.exact_prompt_match
            && self.prompt_length == PROMPT.len() as u64
            && self.matches.into_iter().all(core::convert::identity)
            && self.max_output_tokens == 16
    }
}
macro_rules! candidate_field {
    ($($name:ident, $value:expr);+ $(;)?) => {$(
        #[doc = "Returns one compiled candidate identity field."]
        #[must_use]
        pub const fn $name(&self) -> &'static str { let _ = self; $value }
    )+};
}
macro_rules! components { ($($component:expr);+ $(;)?) => { [$($component),+] }; }
/// Prepared, inactive candidate with only digest and length data.
pub struct CanaryCandidate {
    evidence: CanaryEvidence,
    disposition: CandidateDisposition,
}
impl CanaryCandidate {
    /// Validates exact assertions and prepares an inactive candidate.
    ///
    /// # Errors
    /// Returns a disposition when the identity or overlay assertion differs.
    pub fn prepare(
        identity: CanaryIdentity,
        overlay: CanaryOverlay,
    ) -> Result<Self, CandidateDisposition> {
        if !identity.is_exact() {
            return Err(CandidateDisposition::ProfileMismatch);
        }
        if !overlay.is_exact() {
            return Err(CandidateDisposition::OverlayRejected);
        }
        let one = 1_u64.to_be_bytes();
        let zero = 0_u64.to_be_bytes();
        let sixteen = 16_u64.to_be_bytes();
        let prompt_length = overlay.prompt_length.to_be_bytes();
        let request_components: [&[u8]; 22] = components!(
            &RAW_PROFILE_DIGEST; METHOD.as_bytes(); ORIGIN.as_bytes(); PATH.as_bytes();
            REQUEST_MODEL.as_bytes(); SERVICE_TIER.as_bytes(); &one; &[1];
            &overlay.prompt_digest; &prompt_length; &[0]; &[0]; &[1]; &[0]; &[0]; &[0];
            &zero; b"none"; b"none"; &sixteen; &[1]; &[1];
        );
        let request_length = 384_u64;
        let request_digest = digest(b"runne.canary.request/1", &request_components);
        let result_digest = digest(b"runne.canary.result/1", &[RESULT.as_bytes()]);
        let request_length_bytes = request_length.to_be_bytes();
        let result_length = RESULT.len() as u64;
        let result_length_bytes = result_length.to_be_bytes();
        let candidate_digest = digest(
            b"runne.canary.candidate/1",
            &components!(
                &RAW_PROFILE_DIGEST; &request_digest; &request_length_bytes;
                &overlay.prompt_digest; &prompt_length; &result_digest; &result_length_bytes;
            ),
        );
        Ok(Self {
            evidence: CanaryEvidence::new(
                components!(
                    candidate_digest; RAW_PROFILE_DIGEST; request_digest; overlay.prompt_digest; result_digest;
                ),
                [request_length, overlay.prompt_length, result_length],
            ),
            disposition: CandidateDisposition::NotActivated,
        })
    }
    candidate_field!(
        profile_id, PROFILE_ID; provider, PROVIDER; origin, ORIGIN; method, METHOD;
        path, PATH; request_model, REQUEST_MODEL; model_id, MODEL_ID;
        model_revision, MODEL_REVISION; service_tier, SERVICE_TIER;
        pricing_revision, PRICING_REVISION;
    );
    /// Returns the compiled profile revision.
    #[must_use]
    pub const fn profile_revision(&self) -> u32 {
        PROFILE_REVISION
    }
    /// Returns the compiled candidate digest.
    #[must_use]
    pub const fn candidate_digest(&self) -> &'static str {
        CANARY_DIGEST
    }
    /// Returns closed digest-and-length evidence without plaintext.
    #[must_use]
    pub const fn evidence(&self) -> CanaryEvidence {
        self.evidence
    }
    /// Returns the closed inactive disposition.
    #[must_use]
    pub const fn disposition(&self) -> CandidateDisposition {
        self.disposition
    }
}
impl fmt::Debug for CanaryCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanaryCandidate")
    }
}
/// Frames `domain` and every component as `u64be(length) || bytes`, then hashes it with SHA-256.
fn digest(domain: &[u8], components: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for component in core::iter::once(domain).chain(components.iter().copied()) {
        hasher.update((component.len() as u64).to_be_bytes());
        hasher.update(component);
    }
    hasher.finalize().into()
}
