use super::helper_protocol::{check_helper_target, parse_helper_request};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    time::{SystemTime, UNIX_EPOCH},
};
fn request(root: &std::path::Path, name: &str, args: Value, target: &std::path::Path) -> Vec<u8> {
    let r = fs::metadata(root).unwrap();
    let t = fs::metadata(target).unwrap();
    serde_json::to_vec(&json!({"operation":"Coding","tool_name":name,"arguments":args,
 "root":{"device":r.dev(),"inode":r.ino()},
 "expected":{"device":t.dev(),"inode":t.ino(),"size":t.len(),"mtime_sec":t.mtime(),"mtime_nsec":t.mtime_nsec(),"ctime_sec":t.ctime(),"ctime_nsec":t.ctime_nsec()},
 "binding":{"taskrun_id":"11","attempt_id":"22","cycle_id":"33","proposal_index":0,"taskrun_version":1,"assignment_fence":1,"invocation_digest":"44","environment_digest":"55","approval_digest":"66","expires_at_unix_ms":SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64+60000}})).unwrap()
}
#[test]
fn coding_nested_read_is_bound_and_symlink_escape_rejected() {
    let d = tempfile::tempdir().unwrap();
    fs::create_dir(d.path().join("src")).unwrap();
    let file = d.path().join("src/main.rs");
    fs::write(&file, "synthetic").unwrap();
    let bytes = request(
        d.path(),
        "workspace.file.read",
        json!({"path":"src/main.rs"}),
        &file,
    );
    let parsed = parse_helper_request(&bytes).unwrap();
    check_helper_target(&parsed, &fs::File::open(d.path()).unwrap()).unwrap();
    fs::remove_file(&file).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", &file).unwrap();
    assert!(check_helper_target(&parsed, &fs::File::open(d.path()).unwrap()).is_err());
}
#[test]
fn coding_directories_and_strict_arguments() {
    let d = tempfile::tempdir().unwrap();
    for (name, args) in [
        ("workspace.files.list", json!({"path":".","limit":100})),
        (
            "workspace.files.search",
            json!({"path":".","query":"needle","limit":50}),
        ),
        (
            "workspace.command.run",
            json!({"cwd":".","argv":["printf","OK"],"timeout_ms":1000}),
        ),
    ] {
        let bytes = request(d.path(), name, args.clone(), d.path());
        let parsed = parse_helper_request(&bytes).unwrap();
        check_helper_target(&parsed, &fs::File::open(d.path()).unwrap()).unwrap();
        let mut invalid: Value = serde_json::from_slice(&bytes).unwrap();
        invalid["arguments"]["extra"] = json!(true);
        assert!(parse_helper_request(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }
    let b = request(
        d.path(),
        "workspace.command.run",
        json!({"cwd":"../escape","argv":["true"],"timeout_ms":1}),
        d.path(),
    );
    assert!(parse_helper_request(&b).is_err());
}
