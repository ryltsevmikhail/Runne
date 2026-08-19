use runne_application::commands::CommandOutcome;
use runne_application::ports::{TextGenerationPhase, TextGenerationReceipt};
use runne_domain::command::TerminalResult;
use runne_domain::conversation::{ConversationEvent, GenerationFailureReason};
use runne_domain::id::*;
use runne_domain::task_run::TaskRunEvent;
use runne_store::codec::{
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
