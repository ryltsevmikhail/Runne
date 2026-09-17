use zeroize::Zeroizing;

use super::*;
use crate::qualification_runner::{
    QualificationRunnerReply, QualificationRunnerRequest, QualificationRunnerSession,
};

struct Reject;

struct Slow {
    entered: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

struct PanicOnDrop(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl Drop for PanicOnDrop {
    fn drop(&mut self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        panic!("test drop panic");
    }
}

impl QualificationRunnerSession for PanicOnDrop {
    fn exchange(
        &mut self,
        _: QualificationRunnerRequest,
    ) -> Result<QualificationRunnerReply, QualificationRunnerXpcError> {
        panic!("test handler panic");
    }
}

impl QualificationRunnerSession for Reject {
    fn exchange(
        &mut self,
        _: QualificationRunnerRequest,
    ) -> Result<QualificationRunnerReply, QualificationRunnerXpcError> {
        Err(QualificationRunnerXpcError::Rejected)
    }
}

impl QualificationRunnerSession for Slow {
    fn exchange(
        &mut self,
        request: QualificationRunnerRequest,
    ) -> Result<QualificationRunnerReply, QualificationRunnerXpcError> {
        self.entered.send(()).unwrap();
        self.release.recv().unwrap();
        QualificationRunnerReply::from_zeroizing(request.into_zeroizing())
    }
}

fn request() -> QualificationRunnerRequest {
    QualificationRunnerRequest::from_zeroizing(Zeroizing::new(vec![1])).unwrap()
}

#[test]
fn invalid_frame_or_session_failure_closes_only_its_connection_slot() {
    let lease = || {
        crate::QualificationRunnerSessionLease::new(
            Box::new(Reject),
            Instant::now() + std::time::Duration::from_secs(1),
        )
        .unwrap()
    };
    let first = SessionSlot::new(lease());
    let second = SessionSlot::new(lease());
    assert!(matches!(
        first.exchange(request()),
        Err(QualificationRunnerXpcError::Rejected)
    ));
    assert!(first.is_closed());
    assert!(!second.is_closed());
}

#[test]
fn handler_and_drop_panics_leave_no_session_lease() {
    let drops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let slot = SessionSlot::new(
        crate::QualificationRunnerSessionLease::new(
            Box::new(PanicOnDrop(std::sync::Arc::clone(&drops))),
            Instant::now() + std::time::Duration::from_secs(1),
        )
        .unwrap(),
    );
    assert!(matches!(
        slot.exchange(request()),
        Err(QualificationRunnerXpcError::Unavailable)
    ));
    assert!(slot.is_closed());
    assert!(slot.lock().is_none());
    assert_eq!(drops.load(std::sync::atomic::Ordering::Acquire), 1);
}

#[test]
fn close_is_nonblocking_and_late_success_is_outcome_unknown() {
    let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
    let (release_sender, release_receiver) = std::sync::mpsc::channel();
    let slot = SessionSlot::new(
        crate::QualificationRunnerSessionLease::new(
            Box::new(Slow {
                entered: entered_sender,
                release: release_receiver,
            }),
            Instant::now() + std::time::Duration::from_secs(1),
        )
        .unwrap(),
    );
    let result = std::thread::scope(|scope| {
        let call = scope.spawn(|| slot.exchange(request()));
        entered_receiver.recv().unwrap();
        assert!(!slot.close());
        release_sender.send(()).unwrap();
        call.join().unwrap()
    });
    assert!(matches!(
        result,
        Err(QualificationRunnerXpcError::OutcomeUnknown)
    ));
    assert!(slot.is_closed());
}

#[test]
fn reply_after_deadline_is_terminal_outcome_unknown() {
    let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
    let (release_sender, release_receiver) = std::sync::mpsc::channel();
    let slot = SessionSlot::new(
        crate::QualificationRunnerSessionLease::new(
            Box::new(Slow {
                entered: entered_sender,
                release: release_receiver,
            }),
            Instant::now() + std::time::Duration::from_millis(100),
        )
        .unwrap(),
    );
    let result = std::thread::scope(|scope| {
        let call = scope.spawn(|| slot.exchange(request()));
        entered_receiver.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(110));
        release_sender.send(()).unwrap();
        call.join().unwrap()
    });
    assert!(matches!(
        result,
        Err(QualificationRunnerXpcError::OutcomeUnknown)
    ));
    assert!(slot.is_closed());
}
