use gocode_application::commands::CommandOutcome;
use gocode_application::ports::{TextGenerationPhase, TextGenerationReceipt};
use gocode_domain::command::TerminalResult;
use gocode_domain::conversation::{ConversationEvent, GenerationFailureReason};
use gocode_domain::id::*;
use gocode_domain::task_run::TaskRunEvent;
use gocode_store::codec::{
    CommandOutcomeCodec, ConversationEventCodec, StoreCodec, StoreCodecError, TaskRunEventCodec,
    TextGenerationReceiptCodec,
};

const TASK: &str = "018f2e3a-7000-7000-8000-000000000001";
const ATT_ID: &str = "018f2e3a-7000-7000-8000-000000000002";
const CONVERSATION: &str = "018f2e3a-7000-7000-8000-000000000003";
const WORKSPACE: &str = "018f2e3a-7000-7000-8000-000000000004";
const MESSAGE: &str = "018f2e3a-7000-7000-8000-000000000005";

// ═══════════════════════════════════════════════════════════════════════
// TaskRunEvent malformed-input tests
// ═══════════════════════════════════════════════════════════════════════
