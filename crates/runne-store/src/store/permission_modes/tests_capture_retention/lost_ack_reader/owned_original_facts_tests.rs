//! Authored source regressions; compile and tests NOTRUN.
use super::*;
fn facts() -> OriginalFacts<'static> {
    OriginalFacts {
        authority: [42;16],
        lineage: EventLogLineageId::from_bytes([
            1,1,1,1,1,1,0x71,1,0x81,1,1,1,1,1,1,1]),
        intent: ReceiptIntent {command:[1;16],task:[2;16],authority:"authority",
            principal:"principal",key:b"key",fingerprint:[3;32],version:5},
        terminal: terminal::Expected {task:[2;16],attempt:[4;16],binding_digest:[5;32],
            event:[6;16],fence:2,stdout:b"out",stderr:b"err",stdout_observed:99,
            stderr_observed:101,actor:b"actor",causation:Some([7;16]),
            global_position:123,sensitivity:2},
        ownership: Context {invocation:[8;16],area:[9;100],owner:[10;16],
            generation:[11;8],node:[12;16],epoch:3,assignment_lease:500,
            occupation_lease:700,claim_command:[13;16],claim_scope:b"scope",
            claim_key:b"claim",claim_fingerprint:[14;32],claim_version:4,
            admitted:[15;16],started:[16;16],conversation:[17;16],workspace:[18;16],
            command_digest:[19;32],attempt_stdout:b"before-out",attempt_stderr:b"before-err"},
    }
}
#[test]
fn complete_view_equality() {
    let f = facts();
    let owned = OwnedOriginalFacts::try_from_view(&f).unwrap();
    assert!(owned.view() == f);
    let mut f = facts();
    f.terminal.causation = None;
    assert!(OwnedOriginalFacts::try_from_view(&f).unwrap().view() == f);
}
#[test]
fn every_dynamic_backing_can_mutate_and_drop() {
    let owned;
    {
        let mut authority = String::from("authority");
        let mut principal = String::from("principal");
        let mut key = facts().intent.key.to_vec();
        let mut stdout = facts().terminal.stdout.to_vec();
        let mut stderr = facts().terminal.stderr.to_vec();
        let mut actor = facts().terminal.actor.to_vec();
        let mut claim_scope = facts().ownership.claim_scope.to_vec();
        let mut claim_key = facts().ownership.claim_key.to_vec();
        let mut attempt_stdout = facts().ownership.attempt_stdout.to_vec();
        let mut attempt_stderr = facts().ownership.attempt_stderr.to_vec();
        {
            let mut f = facts();
            f.intent.authority = &authority;
            f.intent.principal = &principal;
            f.intent.key = &key;
            f.terminal.stdout = &stdout;
            f.terminal.stderr = &stderr;
            f.terminal.actor = &actor;
            f.ownership.claim_scope = &claim_scope;
            f.ownership.claim_key = &claim_key;
            f.ownership.attempt_stdout = &attempt_stdout;
            f.ownership.attempt_stderr = &attempt_stderr;
            owned = OwnedOriginalFacts::try_from_view(&f).unwrap();
            assert!(owned.view() == f);
        }
        authority.clear(); principal.clear();
        key.fill(0);
        stdout.fill(0);
        stderr.fill(0);
        actor.fill(0);
        claim_scope.fill(0);
        claim_key.fill(0);
        attempt_stdout.fill(0);
        attempt_stderr.fill(0);
        assert!(owned.view() == facts());
    }
    assert!(owned.view() == facts());
}
#[test]
fn exact_limits_accepted_and_each_overlimit_refused() {
    {
        let mut f = facts();
        let at = "a".repeat(65535);
        f.intent.authority = &at;
        let owned = OwnedOriginalFacts::try_from_view(&f).unwrap();
        assert!(owned.view() == f);
        let over = "a".repeat(65535+1);
        f.intent.authority = &over;
        assert!(OwnedOriginalFacts::try_from_view(&f).is_err());
    }
    {
        let mut f = facts();
        let at = "a".repeat(65535);
        f.intent.principal = &at;
        let owned = OwnedOriginalFacts::try_from_view(&f).unwrap();
        assert!(owned.view() == f);
        let over = "a".repeat(65535+1);
        f.intent.principal = &over;
        assert!(OwnedOriginalFacts::try_from_view(&f).is_err());
    }
    {
        let mut f = facts();
        let at = vec![1; 256];
        f.intent.key = &at;
        let owned = OwnedOriginalFacts::try_from_view(&f).unwrap();
        assert!(owned.view() == f);
        let over = vec![1; 256+1];
        f.intent.key = &over;
        assert!(OwnedOriginalFacts::try_from_view(&f).is_err());
    }
    {
        let mut f = facts();
        let at = vec![1; 65536];
        f.terminal.stdout = &at;
        f.terminal.stdout_observed = i64::MAX;
        let owned = OwnedOriginalFacts::try_from_view(&f).unwrap();
        assert!(owned.view() == f);
        let over = vec![1; 65536+1];
        f.terminal.stdout = &over;
        assert!(OwnedOriginalFacts::try_from_view(&f).is_err());
    }
    {
        let mut f = facts();
        let at = vec![1; 65536];
        f.terminal.stderr = &at;
        f.terminal.stderr_observed = i64::MAX;
        let owned = OwnedOriginalFacts::try_from_view(&f).unwrap();
        assert!(owned.view() == f);
        let over = vec![1; 65536+1];
        f.terminal.stderr = &over;
        assert!(OwnedOriginalFacts::try_from_view(&f).is_err());
    }
    {
        let mut f = facts();
        let at = vec![1; 256];
        f.terminal.actor = &at;
        let owned = OwnedOriginalFacts::try_from_view(&f).unwrap();
        assert!(owned.view() == f);
        let over = vec![1; 256+1];
        f.terminal.actor = &over;
        assert!(OwnedOriginalFacts::try_from_view(&f).is_err());
    }
    {
        let mut f = facts();
        let at = vec![1; 1048576];
        f.ownership.claim_scope = &at;
        let owned = OwnedOriginalFacts::try_from_view(&f).unwrap();
        assert!(owned.view() == f);
        let over = vec![1; 1048576+1];
        f.ownership.claim_scope = &over;
        assert!(OwnedOriginalFacts::try_from_view(&f).is_err());
    }
    {
        let mut f = facts();
        let at = vec![1; 256];
        f.ownership.claim_key = &at;
        let owned = OwnedOriginalFacts::try_from_view(&f).unwrap();
        assert!(owned.view() == f);
        let over = vec![1; 256+1];
        f.ownership.claim_key = &over;
        assert!(OwnedOriginalFacts::try_from_view(&f).is_err());
    }
    {
        let mut f = facts();
        let at = vec![1; 65536];
        f.ownership.attempt_stdout = &at;
        let owned = OwnedOriginalFacts::try_from_view(&f).unwrap();
        assert!(owned.view() == f);
        let over = vec![1; 65536+1];
        f.ownership.attempt_stdout = &over;
        assert!(OwnedOriginalFacts::try_from_view(&f).is_err());
    }
    {
        let mut f = facts();
        let at = vec![1; 65536];
        f.ownership.attempt_stderr = &at;
        let owned = OwnedOriginalFacts::try_from_view(&f).unwrap();
        assert!(owned.view() == f);
        let over = vec![1; 65536+1];
        f.ownership.attempt_stderr = &over;
        assert!(OwnedOriginalFacts::try_from_view(&f).is_err());
    }
}

#[test]
fn all_dynamic_maxima_together_preserve_supported_inputs() {
    let text = "é".repeat(32767) + "x"; // 65535 UTF-8 bytes
    let key = vec![255;256];
    let log = vec![128;65536];
    let scope = vec![0;1048576];
    let mut f = facts();
    f.intent.authority = &text; f.intent.principal = &text;
    f.intent.key = &key; f.terminal.actor = &key;
    f.terminal.stdout = &log; f.terminal.stderr = &log;
    f.terminal.stdout_observed = i64::MAX; f.terminal.stderr_observed = i64::MAX;
    f.ownership.claim_scope = &scope; f.ownership.claim_key = &key;
    f.ownership.attempt_stdout = &log; f.ownership.attempt_stderr = &log;
    let owned = OwnedOriginalFacts::try_from_view(&f).unwrap();
    assert!(owned.view() == f);
    f.authority = [90;16]; f.terminal.causation = None;
    f.terminal.global_position = 999; f.ownership.claim_version = 2;
    assert!(owned.view() != f);
    assert_eq!(owned.view().terminal.causation, Some([7;16]));
    assert_eq!(owned.view().terminal.global_position, 123);
    assert_eq!(owned.view().ownership.claim_version, 4);
}
