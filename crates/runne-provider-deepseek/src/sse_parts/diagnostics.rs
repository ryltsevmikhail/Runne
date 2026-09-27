fn traced_exact_keys(
    trace: &mut DecodeTrace,
    object: &Map<String, Value>,
    expected: &[&str],
    node: DeepSeekDecodeSchemaNode,
) -> Result<(), DeepSeekStreamError> {
    let expected_set = expected.iter().copied().collect::<BTreeSet<_>>();
    let actual_set = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual_set != expected_set {
        let missing = expected.iter().find(|field| !actual_set.contains(**field));
        let unexpected = object
            .keys()
            .map(String::as_str)
            .find(|field| !expected_set.contains(field));
        let (field, issue) = missing.map_or_else(
            || {
                (
                    unexpected.map_or(DeepSeekDecodeField::Unknown, DeepSeekDecodeField::from_wire),
                    DeepSeekDecodeIssue::UnexpectedField,
                )
            },
            |field| {
                (
                    DeepSeekDecodeField::from_wire(field),
                    DeepSeekDecodeIssue::MissingField,
                )
            },
        );
        trace.record(DeepSeekDecodePhase::EventSchema, node, field, issue);
    }
    require_keys(object, expected)
}

fn traced_subset_keys(
    trace: &mut DecodeTrace,
    object: &Map<String, Value>,
    allowed: &[&str],
    required: &[&str],
    node: DeepSeekDecodeSchemaNode,
) -> Result<(), DeepSeekStreamError> {
    if let Some(field) = required.iter().find(|key| !object.contains_key(**key)) {
        trace.record(
            DeepSeekDecodePhase::EventSchema,
            node,
            DeepSeekDecodeField::from_wire(field),
            DeepSeekDecodeIssue::MissingField,
        );
    } else if !object.keys().all(|key| allowed.contains(&key.as_str())) {
        let field = object
            .keys()
            .map(String::as_str)
            .find(|key| !allowed.contains(key))
            .map_or(DeepSeekDecodeField::Unknown, DeepSeekDecodeField::from_wire);
        trace.record(
            DeepSeekDecodePhase::EventSchema,
            node,
            field,
            DeepSeekDecodeIssue::UnexpectedField,
        );
    }
    require_keys_subset(object, allowed, required)
}

fn traced_message_item_keys(
    trace: &mut DecodeTrace,
    object: &Map<String, Value>,
    node: DeepSeekDecodeSchemaNode,
) -> Result<(), DeepSeekStreamError> {
    traced_subset_keys(
        trace,
        object,
        &["content", "id", "phase", "role", "status", "type"],
        &["content", "id", "role", "status", "type"],
        node,
    )
}

fn traced_output_text_part_keys(
    trace: &mut DecodeTrace,
    object: &Map<String, Value>,
) -> Result<(), DeepSeekStreamError> {
    traced_subset_keys(
        trace,
        object,
        &["annotations", "logprobs", "text", "type"],
        &["annotations", "text", "type"],
        DeepSeekDecodeSchemaNode::OutputTextPart,
    )
}

fn traced_required_string<'a>(
    trace: &mut DecodeTrace,
    object: &'a Map<String, Value>,
    key: &str,
    node: DeepSeekDecodeSchemaNode,
) -> Result<&'a str, DeepSeekStreamError> {
    record_required(trace, object, key, node, ValueKind::String);
    required_string(object, key)
}

fn traced_required_object<'a>(
    trace: &mut DecodeTrace,
    object: &'a Map<String, Value>,
    key: &str,
    node: DeepSeekDecodeSchemaNode,
) -> Result<&'a Map<String, Value>, DeepSeekStreamError> {
    record_required(trace, object, key, node, ValueKind::Object);
    required_object(object, key)
}

fn traced_required_array<'a>(
    trace: &mut DecodeTrace,
    object: &'a Map<String, Value>,
    key: &str,
    node: DeepSeekDecodeSchemaNode,
) -> Result<&'a Vec<Value>, DeepSeekStreamError> {
    record_required(trace, object, key, node, ValueKind::Array);
    object
        .get(key)
        .and_then(Value::as_array)
        .ok_or(DeepSeekStreamError::MalformedEvent)
}

fn traced_array_is_empty(
    trace: &mut DecodeTrace,
    object: &Map<String, Value>,
    key: &str,
    node: DeepSeekDecodeSchemaNode,
) -> bool {
    record_required(trace, object, key, node, ValueKind::Array);
    object
        .get(key)
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
}

fn traced_required_u64(
    trace: &mut DecodeTrace,
    object: &Map<String, Value>,
    key: &str,
    node: DeepSeekDecodeSchemaNode,
) -> Result<u64, DeepSeekStreamError> {
    record_required(trace, object, key, node, ValueKind::Unsigned);
    required_u64(object, key)
}

fn record_required(
    trace: &mut DecodeTrace,
    object: &Map<String, Value>,
    key: &str,
    node: DeepSeekDecodeSchemaNode,
    kind: ValueKind,
) {
    let issue = match object.get(key) {
        None => Some(DeepSeekDecodeIssue::MissingField),
        Some(value) if !kind.matches(value) => Some(DeepSeekDecodeIssue::WrongType),
        Some(_) => None,
    };
    if let Some(issue) = issue {
        trace.record(
            DeepSeekDecodePhase::EventSchema,
            node,
            DeepSeekDecodeField::from_wire(key),
            issue,
        );
    }
}

#[derive(Clone, Copy)]
enum ValueKind {
    String,
    Unsigned,
    Object,
    Array,
}

impl ValueKind {
    fn matches(self, value: &Value) -> bool {
        match self {
            Self::String => value.is_string(),
            Self::Unsigned => value.as_u64().is_some(),
            Self::Object => value.is_object(),
            Self::Array => value.is_array(),
        }
    }
}
