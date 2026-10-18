use super::{D2_PENDING_CREATE_RESPONSE, D2_TOOL_PROPOSAL_RESPONSE};

const CREATE_RESPONSE: &str = concat!(
    "event: response.created\ndata: {\"type\":\"response.created\",\"sequence_number\":0,\"response\":{\"id\":\"resp_d2_create\",\"object\":\"response\",\"model\":\"gpt-5.5-2026-04-23\",\"service_tier\":\"default\",\"status\":\"in_progress\",\"output\":[],\"usage\":null,\"background\":false,\"tools\":[]}}\n\n",
    "event: response.in_progress\ndata: {\"type\":\"response.in_progress\",\"sequence_number\":1,\"response\":{\"id\":\"resp_d2_create\",\"object\":\"response\",\"model\":\"gpt-5.5-2026-04-23\",\"service_tier\":\"default\",\"status\":\"in_progress\",\"output\":[],\"usage\":null,\"background\":false,\"tools\":[]}}\n\n",
    "event: response.output_item.added\ndata: {\"type\":\"response.output_item.added\",\"sequence_number\":2,\"output_index\":0,\"item\":{\"id\":\"fc_d2_create\",\"type\":\"function_call\",\"status\":\"in_progress\",\"call_id\":\"call_d2_create\",\"name\":\"workspace_file_create_new\",\"arguments\":\"\"}}\n\n",
    "event: response.function_call_arguments.delta\ndata: {\"type\":\"response.function_call_arguments.delta\",\"sequence_number\":3,\"output_index\":0,\"item_id\":\"fc_d2_create\",\"delta\":\"{\\\"content_base64\\\":\\\"Y3JlYXRlZCB0aHJvdWdoIGFwcHJvdmVkIHRvb2wK\\\",\\\"path\\\":\\\"fixture-created.txt\\\"}\"}\n\n",
    "event: response.function_call_arguments.done\ndata: {\"type\":\"response.function_call_arguments.done\",\"sequence_number\":4,\"output_index\":0,\"item_id\":\"fc_d2_create\",\"arguments\":\"{\\\"content_base64\\\":\\\"Y3JlYXRlZCB0aHJvdWdoIGFwcHJvdmVkIHRvb2wK\\\",\\\"path\\\":\\\"fixture-created.txt\\\"}\"}\n\n",
    "event: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"sequence_number\":5,\"output_index\":0,\"item\":{\"id\":\"fc_d2_create\",\"type\":\"function_call\",\"status\":\"completed\",\"call_id\":\"call_d2_create\",\"name\":\"workspace_file_create_new\",\"arguments\":\"{\\\"content_base64\\\":\\\"Y3JlYXRlZCB0aHJvdWdoIGFwcHJvdmVkIHRvb2wK\\\",\\\"path\\\":\\\"fixture-created.txt\\\"}\"}}\n\n",
    "event: response.completed\ndata: {\"type\":\"response.completed\",\"sequence_number\":6,\"response\":{\"id\":\"resp_d2_create\",\"object\":\"response\",\"model\":\"gpt-5.5-2026-04-23\",\"service_tier\":\"default\",\"status\":\"completed\",\"output\":[{\"id\":\"fc_d2_create\",\"type\":\"function_call\",\"status\":\"completed\",\"call_id\":\"call_d2_create\",\"name\":\"workspace_file_create_new\",\"arguments\":\"{\\\"content_base64\\\":\\\"Y3JlYXRlZCB0aHJvdWdoIGFwcHJvdmVkIHRvb2wK\\\",\\\"path\\\":\\\"fixture-created.txt\\\"}\"}],\"usage\":{\"input_tokens\":18,\"input_tokens_details\":{\"cached_tokens\":0},\"output_tokens\":5,\"output_tokens_details\":{\"reasoning_tokens\":0},\"total_tokens\":23},\"background\":false,\"tools\":[]}}\n\n"
);

const FINAL_RESPONSE: &str = concat!(
    "event: response.created\ndata: {\"type\":\"response.created\",\"sequence_number\":0,\"response\":{\"id\":\"resp_d2_final\",\"object\":\"response\",\"model\":\"gpt-5.5-2026-04-23\",\"service_tier\":\"default\",\"status\":\"in_progress\",\"output\":[],\"usage\":null,\"background\":false,\"tools\":[]}}\n\n",
    "event: response.in_progress\ndata: {\"type\":\"response.in_progress\",\"sequence_number\":1,\"response\":{\"id\":\"resp_d2_final\",\"object\":\"response\",\"model\":\"gpt-5.5-2026-04-23\",\"service_tier\":\"default\",\"status\":\"in_progress\",\"output\":[],\"usage\":null,\"background\":false,\"tools\":[]}}\n\n",
    "event: response.output_item.added\ndata: {\"type\":\"response.output_item.added\",\"sequence_number\":2,\"output_index\":0,\"item\":{\"id\":\"msg_d2_final\",\"type\":\"message\",\"status\":\"in_progress\",\"role\":\"assistant\",\"content\":[]}}\n\n",
    "event: response.content_part.added\ndata: {\"type\":\"response.content_part.added\",\"sequence_number\":3,\"output_index\":0,\"item_id\":\"msg_d2_final\",\"content_index\":0,\"part\":{\"type\":\"output_text\",\"text\":\"\",\"annotations\":[]}}\n\n",
    "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"sequence_number\":4,\"item_id\":\"msg_d2_final\",\"output_index\":0,\"content_index\":0,\"delta\":\"D2 fixture completed after the approved read and create.\"}\n\n",
    "event: response.output_text.done\ndata: {\"type\":\"response.output_text.done\",\"sequence_number\":5,\"item_id\":\"msg_d2_final\",\"output_index\":0,\"content_index\":0,\"text\":\"D2 fixture completed after the approved read and create.\"}\n\n",
    "event: response.content_part.done\ndata: {\"type\":\"response.content_part.done\",\"sequence_number\":6,\"output_index\":0,\"item_id\":\"msg_d2_final\",\"content_index\":0,\"part\":{\"type\":\"output_text\",\"text\":\"D2 fixture completed after the approved read and create.\",\"annotations\":[]}}\n\n",
    "event: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"sequence_number\":7,\"output_index\":0,\"item\":{\"id\":\"msg_d2_final\",\"type\":\"message\",\"status\":\"completed\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"D2 fixture completed after the approved read and create.\",\"annotations\":[]}]}}\n\n",
    "event: response.completed\ndata: {\"type\":\"response.completed\",\"sequence_number\":8,\"response\":{\"id\":\"resp_d2_final\",\"object\":\"response\",\"model\":\"gpt-5.5-2026-04-23\",\"service_tier\":\"default\",\"status\":\"completed\",\"output\":[{\"id\":\"msg_d2_final\",\"type\":\"message\",\"status\":\"completed\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"D2 fixture completed after the approved read and create.\",\"annotations\":[]}]}],\"usage\":{\"input_tokens\":24,\"input_tokens_details\":{\"cached_tokens\":0},\"output_tokens\":10,\"output_tokens_details\":{\"reasoning_tokens\":0},\"total_tokens\":34},\"background\":false,\"tools\":[]}}\n\n"
);

pub(crate) fn response(round: usize) -> Option<&'static str> {
    match round {
        0 => Some(D2_TOOL_PROPOSAL_RESPONSE),
        1 => Some(CREATE_RESPONSE),
        2 => Some(FINAL_RESPONSE),
        _ => None,
    }
}

pub(crate) fn scenario_response(scenario: &str) -> Option<String> {
    let proposal = D2_TOOL_PROPOSAL_RESPONSE;
    match scenario {
        "approved-target-create-race" => Some(D2_PENDING_CREATE_RESPONSE.to_owned()),
        "unknown-tool-proposal" => {
            Some(proposal.replace("workspace_file_read", "workspace_file_unknown"))
        }
        "malformed-tool-arguments" => {
            Some(proposal.replace(r#"{\"path\":\"fixture-read.txt\"}"#, r#"{\"path\":"#))
        }
        "outside-target" => Some(proposal.replace("fixture-read.txt", "../outside-secret.txt")),
        "excluded-target" => Some(proposal.replace("fixture-read.txt", "id_rsa")),
        "early-final-stop" => Some(super::SSE_RESPONSE.to_owned()),
        "incomplete-provider-response" => proposal
            .split("event: response.function_call_arguments.done")
            .next()
            .map(str::to_owned),
        "deny-read"
        | "stale-approval"
        | "approval-expiry"
        | "revoke-before-lease"
        | "target-changed-before-go"
        | "cancel-before-go"
        | "crash-before-go" => Some(CREATE_RESPONSE.to_owned()),
        "cancel-after-create-effect"
        | "cancel-restart-after-create-effect"
        | "crash-after-create-effect" => Some(CREATE_RESPONSE.to_owned()),
        _ => None,
    }
}
