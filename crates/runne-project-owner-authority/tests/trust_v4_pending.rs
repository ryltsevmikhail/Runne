use runne_project_owner_authority::v4_trust_schema_digests;

#[test]
fn v4_pins_are_active_with_the_exact_finalized_successor_schema_set() {
    let pins = v4_trust_schema_digests().unwrap();
    assert_eq!(pins.len(), 13);
    assert!(
        pins.iter()
            .any(|pin| pin.schema_id == "gocode.project-owner.authority-receipt/5")
    );
    assert!(
        pins.iter()
            .any(|pin| { pin.schema_id == "gocode.release.rc3-publication-authorization/2" })
    );
}
