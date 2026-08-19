use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::Duration;

use runne_runtime_client::{ReconnectDecision, ReconnectPolicy, ReconnectRuntime};

struct FakeRuntime {
    now: Duration,
    sleeps: Mutex<Vec<Duration>>,
}

impl ReconnectRuntime for FakeRuntime {
    fn now(&self) -> Duration {
        self.now
    }

    fn sleep(&self, delay: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        self.sleeps.lock().expect("sleep log").push(delay);
        Box::pin(std::future::ready(()))
    }
}

#[test]
fn reconnect_delays_are_bounded_and_live_stability_resets_them() {
    let mut policy = ReconnectPolicy::new();
    let expected = [
        Duration::from_millis(250),
        Duration::from_millis(500),
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
    ];

    for delay in expected {
        assert_eq!(
            policy.record_failure(),
            ReconnectDecision::RetryAfter(delay)
        );
    }
    assert_eq!(policy.record_failure(), ReconnectDecision::Exhausted);

    policy.record_live_delivery(Duration::from_secs(100));
    policy.record_live_delivery(Duration::from_secs(130));
    assert_eq!(
        policy.record_failure(),
        ReconnectDecision::RetryAfter(Duration::from_millis(250))
    );
}

#[test]
fn less_than_thirty_seconds_live_does_not_reset_attempts() {
    let mut policy = ReconnectPolicy::new();
    assert_eq!(
        policy.record_failure(),
        ReconnectDecision::RetryAfter(Duration::from_millis(250))
    );
    policy.record_live_delivery(Duration::from_secs(100));
    policy.record_live_delivery(Duration::from_secs(129));

    assert_eq!(
        policy.record_failure(),
        ReconnectDecision::RetryAfter(Duration::from_millis(500))
    );
}

#[tokio::test]
async fn injectable_runtime_observes_exact_delay_without_wall_clock_waiting() {
    let runtime = FakeRuntime {
        now: Duration::from_secs(100),
        sleeps: Mutex::new(Vec::new()),
    };
    let mut policy = ReconnectPolicy::new();

    assert_eq!(
        policy.wait_after_failure(&runtime).await,
        ReconnectDecision::RetryAfter(Duration::from_millis(250))
    );
    assert_eq!(
        runtime.sleeps.lock().expect("sleep log").as_slice(),
        &[Duration::from_millis(250)]
    );
}
