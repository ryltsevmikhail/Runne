pub const SENSITIVE: &[&str] = &[
    "QualificationAdmissionVerifier",
    "VerifiedQualificationFenceFacts",
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
            &[
                "from_compiled_policy",
                "verify_exact_borrowed",
                "verify_exact_for_fence_borrowed",
            ][..],
        ),
        (
            "VerifiedQualificationFenceFacts",
            &[
                "context_id",
                "context_nonce",
                "ticket_id",
                "ticket_nonce",
                "scenario",
                "selector",
                "process_role",
                "candidate_sha256",
                "raw_v3_tuple_sha256",
                "source_revision",
                "workflow_run_id",
                "namespace_sha256",
                "ticket_sha256",
                "context_issued_at",
                "context_expires_at",
                "ticket_issued_at",
                "ticket_expires_at",
            ][..],
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
    if owner == "VerifiedQualificationFenceFacts" {
        return parse_signature(fence_facts_signature(method)?);
    }
    let source = match (owner, method) {
        (
            "QualificationAdmissionVerifier" | "QualificationRunContextVerifier",
            "from_compiled_policy",
        ) => "pub fn from_compiled_policy() -> Self {}",
        ("QualificationAdmissionVerifier", "verify_exact_borrowed") => {
            "pub fn verify_exact_borrowed(&mut self, admission: &PendingQualificationAdmission, candidate_sha256: [u8; 32], raw_v3_tuple_sha256: [u8; 32], now_unix_seconds: u64) -> Result<(), QualificationAdmissionVerificationError> {}"
        }
        ("QualificationAdmissionVerifier", "verify_exact_for_fence_borrowed") => {
            "pub fn verify_exact_for_fence_borrowed(&mut self, admission: &PendingQualificationAdmission, candidate_sha256: [u8; 32], raw_v3_tuple_sha256: [u8; 32], now_unix_seconds: u64) -> Result<crate::VerifiedQualificationFenceFacts, QualificationAdmissionVerificationError> {}"
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
    parse_signature(source)
}

fn parse_signature(source: &str) -> Option<syn::Signature> {
    syn::parse_str::<syn::ImplItemFn>(source)
        .ok()
        .map(|item| item.sig)
}

fn fence_facts_signature(method: &str) -> Option<&'static str> {
    Some(match method {
        "context_id" => "pub const fn context_id(&self) -> [u8; 32] {}",
        "context_nonce" => "pub const fn context_nonce(&self) -> [u8; 32] {}",
        "ticket_id" => "pub const fn ticket_id(&self) -> [u8; 32] {}",
        "ticket_nonce" => "pub const fn ticket_nonce(&self) -> [u8; 32] {}",
        "scenario" => "pub const fn scenario(&self) -> QualificationScenario {}",
        "selector" => "pub const fn selector(&self) -> QualificationFaultSelector {}",
        "process_role" => "pub const fn process_role(&self) -> QualificationProcessRole {}",
        "candidate_sha256" => "pub const fn candidate_sha256(&self) -> [u8; 32] {}",
        "raw_v3_tuple_sha256" => "pub const fn raw_v3_tuple_sha256(&self) -> [u8; 32] {}",
        "source_revision" => "pub const fn source_revision(&self) -> [u8; 20] {}",
        "workflow_run_id" => "pub fn workflow_run_id(&self) -> &str {}",
        "namespace_sha256" => "pub const fn namespace_sha256(&self) -> [u8; 32] {}",
        "ticket_sha256" => "pub const fn ticket_sha256(&self) -> [u8; 32] {}",
        "context_issued_at" => "pub const fn context_issued_at(&self) -> u64 {}",
        "context_expires_at" => "pub const fn context_expires_at(&self) -> u64 {}",
        "ticket_issued_at" => "pub const fn ticket_issued_at(&self) -> u64 {}",
        "ticket_expires_at" => "pub const fn ticket_expires_at(&self) -> u64 {}",
        _ => return None,
    })
}
