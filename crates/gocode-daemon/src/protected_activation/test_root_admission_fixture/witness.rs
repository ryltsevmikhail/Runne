use std::io::Write;
use std::path::Path;
use std::time::Duration;

pub(super) fn read_parent_admission_digest(path: &Path) -> [u8; 32] {
    for _ in 0..100 {
        if let Ok(bytes) = std::fs::read(path)
            && let Ok(digest) = bytes.try_into()
        {
            return digest;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("exact parent admission digest was not published")
}

pub(super) fn publish_exact(path: &Path, bytes: &[u8]) {
    let temporary_path = path.with_extension("tmp");
    let mut temporary = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary_path)
        .expect("create temporary witness");
    temporary.write_all(bytes).expect("write temporary witness");
    temporary.sync_all().expect("sync temporary witness");
    drop(temporary);
    std::fs::rename(temporary_path, path).expect("publish witness");
}
