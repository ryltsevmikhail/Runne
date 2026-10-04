use std::sync::OnceLock;

use super::AutomaticTaskRunError;
use runne_application::ports::EventStoreError;
use runne_domain::id::TaskRunId;

const WARNING_FIELDS: &[&str] = &["message", "taskrun_id", "outcome", "error"];
const TARGET: &str = "runne_runtime::taskrun_auto_worker";
static WARNING_CALLSITE: tracing::callsite::DefaultCallsite =
    tracing::callsite::DefaultCallsite::new(&WARNING_METADATA);
static WARNING_METADATA: tracing::Metadata<'static> = tracing::Metadata::new(
    "automatic_taskrun_worker_warning",
    TARGET,
    tracing::Level::WARN,
    Some(file!()),
    Some(line!()),
    Some(TARGET),
    tracing::field::FieldSet::new(
        WARNING_FIELDS,
        tracing::callsite::Identifier(&WARNING_CALLSITE),
    ),
    tracing::metadata::Kind::EVENT,
);
static WARNING_REGISTERED: OnceLock<()> = OnceLock::new();

fn warning_enabled() -> bool {
    WARNING_REGISTERED.get_or_init(|| tracing::callsite::register(&WARNING_CALLSITE));
    if tracing::Level::WARN > tracing::level_filters::STATIC_MAX_LEVEL
        || tracing::Level::WARN > tracing::level_filters::LevelFilter::current()
    {
        return false;
    }
    let interest = WARNING_CALLSITE.interest();
    !interest.is_never()
        && (interest.is_always()
            || tracing::dispatcher::get_default(|dispatch| dispatch.enabled(&WARNING_METADATA)))
}

fn emit_warning(
    message: &'static str,
    taskrun_id: Option<TaskRunId>,
    outcome: Option<String>,
    error: Option<String>,
) {
    let message = tracing::field::display(message);
    let taskrun_id = taskrun_id.map(tracing::field::display);
    let outcome = outcome.map(tracing::field::display);
    let error = error.map(tracing::field::display);
    let values: [Option<&dyn tracing::field::Value>; 4] = [
        Some(&message),
        taskrun_id
            .as_ref()
            .map(|value| value as &dyn tracing::field::Value),
        outcome
            .as_ref()
            .map(|value| value as &dyn tracing::field::Value),
        error
            .as_ref()
            .map(|value| value as &dyn tracing::field::Value),
    ];
    let fields = WARNING_METADATA.fields().value_set_all(&values);
    tracing::Event::dispatch(&WARNING_METADATA, &fields);
}

pub(super) fn warn_execution(taskrun_id: TaskRunId, outcome: AutomaticTaskRunError) {
    if warning_enabled() {
        emit_warning(
            "automatic TaskRun execution did not complete",
            Some(taskrun_id),
            Some(format!("{outcome:?}")),
            None,
        );
    }
}

pub(super) fn warn_worker_panic(taskrun_id: TaskRunId) {
    if warning_enabled() {
        emit_warning(
            "automatic TaskRun worker panicked; the claimed run will not be replayed",
            Some(taskrun_id),
            None,
            None,
        );
    }
}

pub(super) fn warn_scan_failure(error: EventStoreError, cancellations: bool) {
    if warning_enabled() {
        let message = if cancellations {
            "automatic TaskRun cancellation scan failed"
        } else {
            "automatic TaskRun queue scan failed"
        };
        emit_warning(message, None, None, Some(format!("{error:?}")));
    }
}

pub(super) fn warn_shutdown_execution(taskrun_id: TaskRunId, outcome: AutomaticTaskRunError) {
    if warning_enabled() {
        emit_warning(
            "automatic TaskRun execution did not complete during shutdown",
            Some(taskrun_id),
            Some(format!("{outcome:?}")),
            None,
        );
    }
}

pub(super) fn warn_shutdown_panic(taskrun_id: TaskRunId) {
    if warning_enabled() {
        emit_warning(
            "automatic TaskRun worker panicked during shutdown",
            Some(taskrun_id),
            None,
            None,
        );
    }
}
