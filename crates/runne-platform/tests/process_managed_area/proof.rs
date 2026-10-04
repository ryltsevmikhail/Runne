use super::*;

#[test]
fn empty_proof_rejects_replaced_current_name() {
    let Some(root) = root_or_skip() else { return };
    let bind = binding(52);
    let Some(area) = area_or_skip(&root, bind) else {
        return;
    };
    eprintln!("RUN: empty_proof_rejects_replaced_current_name");
    let held = area.take();
    let old = held.identity().clone();
    let proof = held.prove_empty().expect("empty proof");
    root.reopen_area(old.clone(), bind)
        .expect("second handle to exact area")
        .remove_empty()
        .expect("remove old cgroup name while retaining held proof");
    let replacement = root.create_area(bind).expect("recreate deterministic name");
    assert_ne!(replacement.identity().to_bytes(), old.to_bytes());
    assert!(
        proof.revalidate().is_err(),
        "name substitution invalidates proof"
    );
    drop(held);
    replacement.remove_empty().expect("remove replacement area");
}

#[test]
fn empty_proof_is_bound_to_held_area_and_revalidated_after_population() {
    let Some(root) = root_or_skip() else { return };
    let bind = binding(51);
    let Some(area) = area_or_skip(&root, bind) else {
        return;
    };
    eprintln!("RUN: empty_proof_is_bound_to_held_area_and_revalidated_after_population");
    let proof = area.prove_empty().expect("initial empty proof");
    assert_eq!(
        proof.identity_bytes().as_slice(),
        area.identity().to_bytes()
    );

    let mut child = match Command::new("sh")
        .args(["-c", "kill -STOP $$; exec sleep 30"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => TestChild(child),
        Err(_) => {
            eprintln!("SKIP: shell fixture unavailable");
            area.remove_empty();
            return;
        }
    };
    wait_stopped(&child);
    area.attach_gated_process(child.id())
        .expect("attach stopped test child");
    assert!(proof.revalidate().is_err(), "stale empty evidence rejected");
    area.terminate(Duration::from_millis(100))
        .expect("terminate exact child area");
    wait_child(&mut child);
    assert!(
        proof.revalidate().is_ok(),
        "same area may be re-proven empty"
    );
    area.remove_empty();
}
