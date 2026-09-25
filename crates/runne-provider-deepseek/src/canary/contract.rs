use super::CanaryEvidence;
use core::fmt;
use sha2::{Digest, Sha256};
/// Digest of the pinned provider profile sidecar.
pub const PROFILE_DIGEST: &str =
    "sha256:0112c4b6ce64739810bb79802ebb5ae6fd8ac563d1d1397ac51f07a190538195";
/// Digest of the single compiled canary candidate.
pub const CANARY_DIGEST: &str =
    "sha256:f69bbad907ac7b5ba9e72fc37ae4ea5fe541fae3396bd04f5035dbcfe2b6e410";
const RAW_PROFILE_DIGEST: [u8; 32] = [
    0x01, 0x12, 0xc4, 0xb6, 0xce, 0x64, 0x73, 0x98, 0x10, 0xbb, 0x79, 0x80, 0x2e, 0xbb, 0x5a, 0xe6,
    0xfd, 0x8a, 0xc5, 0x63, 0xd1, 0xd1, 0x39, 0x7a, 0xc5, 0x1f, 0x07, 0xa1, 0x90, 0x53, 0x81, 0x95,
];
const PROFILE_ID: &str = "gocode-deepseek-responses-text/1";
const PROFILE_REVISION: u32 = 2;
const PROVIDER: &str = "deepseek";
const ORIGIN: &str = "https://api.deepseek.com";
const METHOD: &str = "POST";
const PATH: &str = "/responses";
const REQUEST_MODEL: &str = "deepseek-flash";
const MODEL_ID: &str = "deepseek-flash";
const MODEL_REVISION: &str = "2026-09-21";
/// Legacy compiled identity field; the rendered request carries no
/// `service_tier` and the request digest excludes it.
const SERVICE_TIER: &str = "default";
pub(super) const PRICING_REVISION: &str = "deepseek-flash-peak-2026-09-21/1";
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
    matches: [bool; 11],
}
impl CanaryIdentity {
    /// Returns the exact compiled identity assertions.
    #[must_use]
    pub const fn canonical() -> Self {
        Self {
            matches: [true; 11],
        }
    }
    identity_assertion!(
        with_profile_id, 0, PROFILE_ID; with_profile_digest, 2, PROFILE_DIGEST;
        with_provider, 3, PROVIDER; with_origin, 4, ORIGIN;
        with_method, 5, METHOD; with_path, 6, PATH;
        with_request_model, 7, REQUEST_MODEL; with_model_id, 8, MODEL_ID;
        with_model_revision, 9, MODEL_REVISION;
        with_pricing_revision, 10, PRICING_REVISION;
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
    matches: [bool; 9],
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
            prompt_digest: digest(b"gocode.canary.prompt/1", &[text.as_bytes()]),
            prompt_length: text.len() as u64,
            matches: [true; 9],
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
        with_tools_empty, 0, true; with_tool_choice_none, 1, true;
        with_stream, 2, true; with_reasoning_none, 3, true;
        with_metadata, 4, true; with_previous_response, 5, true;
        with_retry, 6, false; with_redirect, 7, false; with_proxy, 8, false;
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
        let request_components: [&[u8]; 21] = components!(
            &RAW_PROFILE_DIGEST; METHOD.as_bytes(); ORIGIN.as_bytes(); PATH.as_bytes();
            REQUEST_MODEL.as_bytes(); &one; &[1];
            &overlay.prompt_digest; &prompt_length; &[0]; &[0]; &[1]; &[0]; &[0]; &[0];
            &zero; b"none"; b"none"; &sixteen; &[1]; &[1];
        );
        let request_length = 218_u64;
        let request_digest = digest(b"gocode.canary.request/1", &request_components);
        let result_digest = digest(b"gocode.canary.result/1", &[RESULT.as_bytes()]);
        let request_length_bytes = request_length.to_be_bytes();
        let result_length = RESULT.len() as u64;
        let result_length_bytes = result_length.to_be_bytes();
        let candidate_digest = digest(
            b"gocode.canary.candidate/1",
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
        profile_id, PROFILE_ID; service_tier, SERVICE_TIER; provider, PROVIDER; origin, ORIGIN; method, METHOD;
        path, PATH; request_model, REQUEST_MODEL; model_id, MODEL_ID;
        model_revision, MODEL_REVISION; pricing_revision, PRICING_REVISION;
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
