//! Phase 5 Codec Tests — malformed-input rejection and golden byte stability.
//!
//! Ensures the store codec rejects: unknown version, unknown tag, trailing bytes,
//! and truncated payloads for Phase 5 TaskRunEvent and CommandOutcome variants.
//! Additionally verifies existing golden tags (0x01..0x14) remain unchanged.

include!("agent_loop_codec/support.rs");
include!("agent_loop_codec/codec_cases.rs");
include!("agent_loop_codec/receipts.rs");
