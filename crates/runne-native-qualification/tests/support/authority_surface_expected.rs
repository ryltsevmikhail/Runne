pub const SENSITIVE: &[&str] = &[
    "QualificationAdmissionVerifier",
    "VerifiedQualificationRunContext",
    "PendingQualificationAdmission",
    "QualificationRunContextVerifier",
    "PendingQualificationRunContext",
    "QualificationAdmissionRelayTranscript",
    "QualificationRunContextRelayCodecV1",
    "QualificationAdmissionRelayCodecV1",
];

pub fn expected_methods() -> Vec<(&'static str, &'static str)> {
    [
        (
            "QualificationAdmissionVerifier",
            &["from_compiled_policy", "verify_exact_borrowed"][..],
        ),
        (
            "VerifiedQualificationRunContext",
            &["context_id", "nonce", "expires_at", "ticket_sha256"][..],
        ),
        (
            "PendingQualificationAdmission",
            &["from_admitted_bundle", "encode_relay_transcript"],
        ),
        (
            "QualificationRunContextVerifier",
            &["from_compiled_policy", "verify_and_consume"],
        ),
        ("QualificationAdmissionRelayTranscript", &["into_bytes"]),
        (
            "QualificationRunContextRelayCodecV1",
            &["from_protected_activation", "recognizes_frame", "decode"],
        ),
        (
            "QualificationAdmissionRelayCodecV1",
            &["from_protected_activation", "decode_transcript"],
        ),
    ]
    .into_iter()
    .flat_map(|(owner, methods)| methods.iter().map(move |method| (owner, *method)))
    .collect()
}

pub fn expected_signature(owner: &str, method: &str) -> Option<syn::Signature> {
    let source = match (owner, method) {
        (
            "QualificationAdmissionVerifier" | "QualificationRunContextVerifier",
            "from_compiled_policy",
        ) => "pub fn from_compiled_policy() -> Self {}",
        ("QualificationAdmissionVerifier", "verify_exact_borrowed") => {
            "pub fn verify_exact_borrowed(&mut self, admission: &PendingQualificationAdmission, candidate_sha256: [u8; 32], raw_v3_tuple_sha256: [u8; 32], now_unix_seconds: u64) -> Result<(), QualificationAdmissionVerificationError> {}"
        }
        ("VerifiedQualificationRunContext", "context_id") => {
            "pub const fn context_id(&self) -> [u8; 32] {}"
        }
        ("VerifiedQualificationRunContext", "nonce") => "pub const fn nonce(&self) -> [u8; 32] {}",
        ("VerifiedQualificationRunContext", "expires_at") => {
            "pub const fn expires_at(&self) -> u64 {}"
        }
        ("VerifiedQualificationRunContext", "ticket_sha256") => {
            "pub const fn ticket_sha256(&self) -> [u8; 32] {}"
        }
        ("PendingQualificationAdmission", "from_admitted_bundle") => {
            "pub fn from_admitted_bundle(bytes: Vec<u8>) -> Result<Self, QualificationAdmissionError> {}"
        }
        ("PendingQualificationAdmission", "encode_relay_transcript") => {
            "pub fn encode_relay_transcript(self, codec: &QualificationAdmissionRelayCodecV1, context_binding: &runne_api::QualificationRunContextRelayBindingV1, fault_binding: &runne_api::QualificationFaultRelayBindingV1) -> Result<QualificationAdmissionRelayTranscript, QualificationAdmissionRelayError> {}"
        }
        ("QualificationRunContextVerifier", "verify_and_consume") => {
            "pub fn verify_and_consume(&mut self, bytes: &[u8], expected: &QualificationRunContextExpectation, now_unix_seconds: u64) -> Result<VerifiedQualificationRunContext, QualificationRunContextError> {}"
        }
        ("QualificationAdmissionRelayTranscript", "into_bytes") => {
            "pub fn into_bytes(self) -> Vec<u8> {}"
        }
        (
            "QualificationRunContextRelayCodecV1" | "QualificationAdmissionRelayCodecV1",
            "from_protected_activation",
        ) => "pub fn from_protected_activation(keys: &ProtectedActivationKeys) -> Self {}",
        ("QualificationRunContextRelayCodecV1", "recognizes_frame") => {
            "pub fn recognizes_frame(frame: &[u8]) -> bool {}"
        }
        ("QualificationRunContextRelayCodecV1", "decode") => {
            "pub fn decode(&self, frame: &[u8], expected: &QualificationRunContextRelayBindingV1) -> Result<PendingQualificationRunContext, QualificationRunContextRelayError> {}"
        }
        ("QualificationAdmissionRelayCodecV1", "decode_transcript") => {
            "pub fn decode_transcript(&self, bytes: &[u8], context_binding: &QualificationRunContextRelayBindingV1, fault_binding: &QualificationFaultRelayBindingV1) -> Result<PendingQualificationAdmission, QualificationAdmissionRelayError> {}"
        }
        _ => return None,
    };
    syn::parse_str::<syn::ImplItemFn>(source)
        .ok()
        .map(|item| item.sig)
}
