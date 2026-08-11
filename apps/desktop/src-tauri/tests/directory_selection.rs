use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use gocode_desktop::{DirectorySelectionManager, VerifiedRootHandle};
use tempfile::tempdir;

fn root() -> (tempfile::TempDir, VerifiedRootHandle) {
    let directory = tempdir().unwrap();
    let root = VerifiedRootHandle::open(directory.path()).unwrap();
    (directory, root)
}

#[test]
fn directory_selection_requires_matching_authoritative_generation_once() {
    let manager = DirectorySelectionManager::new(Duration::from_secs(30)).unwrap();
    let now = Instant::now();
    let (_directory, selected_root) = root();
    let selection = manager
        .issue("main", 0, "request", selected_root, now)
        .unwrap();
    assert!(
        manager
            .consume(&selection, "main", 1, "request", now)
            .is_err()
    );
    assert!(
        manager
            .consume(&selection, "main", 0, "request", now)
            .is_ok()
    );
    assert!(
        manager
            .consume(&selection, "main", 0, "request", now)
            .is_err()
    );
}

#[test]
fn directory_selection_rejects_stale_issue_after_a_reload() {
    let manager = DirectorySelectionManager::new(Duration::from_secs(30)).unwrap();
    let generations = manager.renderer_generations();
    assert_eq!(generations.current("main").unwrap(), 0);
    generations.fence_reload("main").unwrap();
    let (_directory, selected_root) = root();
    assert!(
        manager
            .issue("main", 0, "stale", selected_root, Instant::now())
            .is_err()
    );
}

#[test]
fn directory_selection_fences_reload_before_consume_under_a_barrier() {
    let manager = Arc::new(DirectorySelectionManager::new(Duration::from_secs(30)).unwrap());
    let generations = manager.renderer_generations();
    let now = Instant::now();
    let (_directory, selected_root) = root();
    let selection = manager
        .issue("main", 0, "request", selected_root, now)
        .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let worker_barrier = Arc::clone(&barrier);
    let worker = std::thread::spawn(move || {
        worker_barrier.wait();
        generations.fence_reload("main").unwrap();
    });
    barrier.wait();
    worker.join().unwrap();
    assert!(
        manager
            .consume(&selection, "main", 0, "request", now)
            .is_err()
    );
}

#[test]
fn directory_selection_fences_invalidation_before_consume_under_a_barrier() {
    let manager = Arc::new(DirectorySelectionManager::new(Duration::from_secs(30)).unwrap());
    let now = Instant::now();
    let (_directory, selected_root) = root();
    let selection = manager
        .issue("main", 0, "request", selected_root, now)
        .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let worker_manager = Arc::clone(&manager);
    let worker_barrier = Arc::clone(&barrier);
    let worker = std::thread::spawn(move || {
        worker_barrier.wait();
        worker_manager.invalidate_window("main").unwrap();
    });
    barrier.wait();
    worker.join().unwrap();
    assert!(
        manager
            .consume(&selection, "main", 0, "request", now)
            .is_err()
    );
}

#[test]
fn directory_selection_is_bounded_expiring_and_redacted() {
    assert!(DirectorySelectionManager::new(Duration::from_secs(31)).is_err());
    assert!(DirectorySelectionManager::new(Duration::ZERO).is_err());
    assert!(serde_json::from_str::<gocode_desktop::DirectorySelectionRef>("\"A\"").is_err());
}

#[test]
fn renderer_generation_overflow_is_rejected_without_reuse() {
    let manager = DirectorySelectionManager::new(Duration::from_secs(30)).unwrap();
    let generations = manager.renderer_generations();
    generations
        .set_generation_for_test("main", u64::MAX)
        .unwrap();
    assert!(generations.fence_reload("main").is_err());
    assert_eq!(generations.current("main").unwrap(), u64::MAX);
}
