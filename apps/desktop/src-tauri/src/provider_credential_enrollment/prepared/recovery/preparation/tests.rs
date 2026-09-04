use super::*;
use std::sync::{Arc, Mutex};

struct NativeSteps {
    log: Arc<Mutex<Vec<&'static str>>>,
    fail: Option<&'static str>,
}
impl NativeSteps {
    fn step(&self, name: &'static str) -> Result<(), RecoveryRunError> {
        self.log.lock().unwrap().push(name);
        if self.fail == Some(name) {
            Err(RecoveryRunError::Transport)
        } else {
            Ok(())
        }
    }
}
impl Preparation for NativeSteps {
    type Output = ();
    fn revalidate(&self) -> Result<(), RecoveryRunError> {
        self.step("revalidate")
    }
    async fn renew(&mut self) -> Result<(), RecoveryRunError> {
        self.step("renew")
    }
    async fn confirm(&mut self) -> Result<(), RecoveryRunError> {
        self.step("confirm")
    }
    async fn round(&mut self) -> Result<(), RecoveryRunError> {
        self.step("round")
    }
    async fn transition(&mut self) -> Result<(), RecoveryRunError> {
        self.step("transition")
    }
    async fn register(&mut self) -> Result<(), RecoveryRunError> {
        self.step("register")
    }
    fn finish(self) -> Result<(), RecoveryRunError> {
        self.step("finish")
    }
}

#[tokio::test]
async fn startup_preparation_transitions_without_renewal_and_stops_at_each_failure() {
    let steps = ["revalidate", "confirm", "transition", "register", "finish"];
    for failed in 0..=steps.len() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let result = prepare_first(NativeSteps {
            log: Arc::clone(&log),
            fail: steps.get(failed).copied(),
        })
        .await;
        assert_eq!(result.is_ok(), failed == steps.len());
        assert_eq!(*log.lock().unwrap(), steps[..(failed + 1).min(steps.len())]);
    }
}

#[tokio::test]
async fn recovery_preparation_orders_native_steps_and_stops_after_failure() {
    let steps = [
        "revalidate",
        "renew",
        "confirm",
        "round",
        "register",
        "finish",
    ];
    for failed in 0..=steps.len() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let result = prepare(NativeSteps {
            log: Arc::clone(&log),
            fail: steps.get(failed).copied(),
        })
        .await;
        assert_eq!(result.is_ok(), failed == steps.len());
        assert_eq!(*log.lock().unwrap(), steps[..(failed + 1).min(steps.len())]);
    }
}
