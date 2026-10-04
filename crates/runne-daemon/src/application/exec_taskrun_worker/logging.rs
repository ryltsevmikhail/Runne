use std::sync::OnceLock;

use runne_domain::id::TaskRunId;
const WARNING_FIELDS: &[&str] = &["message", "taskrun_id"];
const TARGET: &str = "runne_daemon::application::exec_taskrun_worker";
static WARNING_CALLSITE: tracing::callsite::DefaultCallsite =
    tracing::callsite::DefaultCallsite::new(&WARNING_METADATA);
static WARNING_METADATA: tracing::Metadata<'static> = tracing::Metadata::new(
    "taskrun_lease_renewal_warning",
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

pub(super) fn warn_lease_renewal_failure(taskrun_id: TaskRunId) {
    WARNING_REGISTERED.get_or_init(|| tracing::callsite::register(&WARNING_CALLSITE));
    if tracing::Level::WARN > tracing::level_filters::STATIC_MAX_LEVEL
        || tracing::Level::WARN > tracing::level_filters::LevelFilter::current()
    {
        return;
    }
    let interest = WARNING_CALLSITE.interest();
    if interest.is_never()
        || (!interest.is_always()
            && !tracing::dispatcher::get_default(|dispatch| dispatch.enabled(&WARNING_METADATA)))
    {
        return;
    }
    let message = tracing::field::display(
        "TaskRun lease renewal failed; retaining provider execution until authoritative outcome",
    );
    let taskrun_id = tracing::field::display(taskrun_id);
    let values: [Option<&dyn tracing::field::Value>; 2] = [Some(&message), Some(&taskrun_id)];
    let fields = WARNING_METADATA.fields().value_set_all(&values);
    tracing::Event::dispatch(&WARNING_METADATA, &fields);
}
