pub(super) fn run() {
    super::harness::dispatch("real_pair_transcript_persists_across_runned_restart", inner);
}

fn inner(context: &super::support::InnerContext) -> Result<(), &'static str> {
    context.run_positive_transcript(false)
}
