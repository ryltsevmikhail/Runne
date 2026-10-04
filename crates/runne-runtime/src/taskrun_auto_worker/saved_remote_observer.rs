use std::sync::Arc;
use std::time::Duration;

use runne_provider::DispatchAttemptId;
use tokio_util::sync::CancellationToken;

use super::{AutomaticTaskRunError, AutomaticTaskRunService};

pub(super) async fn run(service: Arc<dyn AutomaticTaskRunService>, stop: CancellationToken) {
    const PAGE_SIZE: usize = 4;
    const BETWEEN_PAGES: Duration = Duration::from_millis(100);
    const BETWEEN_SWEEPS: Duration = Duration::from_secs(60);
    const MAX_SWEEP: Duration = Duration::from_secs(30);
    const PAGE_DEADLINE: Duration = Duration::from_secs(20);
    const RETRY_DELAY: Duration = Duration::from_secs(5);
    let mut cursor: Option<DispatchAttemptId> = None;
    let mut sweep_started = tokio::time::Instant::now();
    let mut next_tick = sweep_started;
    let mut resume_slice = false;
    let mut last_warning = None;
    loop {
        tokio::select! {
            biased;
            _ = stop.cancelled() => return,
            _ = tokio::time::sleep_until(next_tick) => {
                let now = tokio::time::Instant::now();
                if resume_slice {
                    sweep_started = now;
                    resume_slice = false;
                }
                let observation = service.observe_saved_remote_page(cursor, PAGE_SIZE);
                let result = tokio::select! {
                    biased;
                    _ = stop.cancelled() => return,
                    result = tokio::time::timeout(PAGE_DEADLINE, observation) => result,
                };
                match result {
                    Ok(Ok(progress)) => {
                        cursor = if progress.reached_end { None } else { progress.next_after };
                        let now = tokio::time::Instant::now();
                        if progress.unavailable_candidates > 0
                            && last_warning.is_none_or(|prior| now.duration_since(prior) >= BETWEEN_SWEEPS)
                        {
                            tracing::warn!(
                                unavailable_candidates = progress.unavailable_candidates,
                                "saved remote observation page had unavailable candidates"
                            );
                            last_warning = Some(now);
                        }
                        if progress.reached_end {
                            sweep_started = now;
                            resume_slice = true;
                            next_tick = now + BETWEEN_SWEEPS;
                        } else if now.duration_since(sweep_started) >= MAX_SWEEP {
                            resume_slice = true;
                            next_tick = now + BETWEEN_SWEEPS;
                        } else {
                            next_tick = now + BETWEEN_PAGES;
                        }
                    }
                    Ok(Err(error)) => {
                        schedule_retry(error, &mut last_warning, &mut next_tick, RETRY_DELAY, BETWEEN_SWEEPS);
                    }
                    Err(_) => {
                        schedule_retry(
                            AutomaticTaskRunError::Unavailable,
                            &mut last_warning,
                            &mut next_tick,
                            RETRY_DELAY,
                            BETWEEN_SWEEPS,
                        );
                    }
                }
            }
        }
    }
}

fn schedule_retry(
    _error: AutomaticTaskRunError,
    last_warning: &mut Option<tokio::time::Instant>,
    next_tick: &mut tokio::time::Instant,
    retry_delay: Duration,
    warning_interval: Duration,
) {
    let now = tokio::time::Instant::now();
    if last_warning.is_none_or(|prior| now.duration_since(prior) >= warning_interval) {
        tracing::warn!("saved remote observation page unavailable; retrying bounded scan");
        *last_warning = Some(now);
    }
    *next_tick = now + retry_delay;
}
