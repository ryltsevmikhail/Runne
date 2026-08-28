#[test]
fn released_v1_v25_migration_bytes_are_unchanged() {
    let migrations = [
        MIGRATION_V1,
        MIGRATION_V2,
        MIGRATION_V3,
        MIGRATION_V4,
        MIGRATION_V5,
        MIGRATION_V6,
        MIGRATION_V7,
        MIGRATION_V8,
        MIGRATION_V9,
        MIGRATION_V10,
        MIGRATION_V11,
        MIGRATION_V12,
        MIGRATION_V13,
        provider_schema::MIGRATION_V14,
        provider_schema::MIGRATION_V15,
        MIGRATION_V16,
        MIGRATION_V17,
        project_workspace_schema::MIGRATION_V18,
        replay_snapshot_schema::MIGRATION_V19,
        replay_promotion_snapshot_schema::MIGRATION_V20,
        MIGRATION_V21,
        MIGRATION_V22,
        MIGRATION_V23,
        MIGRATION_V24,
        MIGRATION_V25,
    ];
    let actual = migrations.map(|migration| {
        let mut digest = Sha256::new();
        digest.update(migration.as_bytes());
        format!("{:x}", digest.finalize())
    });
    assert_eq!(CURRENT_SCHEMA_VERSION, 30);
    assert_eq!(
        actual,
        [
            "62acaf0d18a059d1159bc0f7aee25c7d7bf30420f7de54da367b00fb59325660",
            "0c4299d7d49e9d8cdec7f2bb7805d0c96b1734424d79d5209dcd0acf9feb328c",
            "08738a5ae6045c9215b1cb5cf3bc023785b68c54276c8996888cfa7d1413b19e",
            "cb82555949a286f71c61f4754ee73e52579d842da5864828d7a4564b382ecf18",
            "a930368c723fe71fc881419c00e2ecb14e494efc5c741f791e72eb1c6bef1bcd",
            "bde47623ea2dffcff6227be9f80ee3abc18eca734b0dc588a330a95ba51f5cae",
            "2ee3cde3a39063adb3231e2b28882f76eb3ca00f764cbfb96f57fcc81c247235",
            "32bcbeed9a79af1322eae66af72457d88a07224aabcf3779e72c081c8231f5f4",
            "c4debc3c84f549a7a985c682c0d1ebca16c6a92fc5f733869f447df817c532c3",
            "3e8ef459abca6c0eb8f87071bd450c5a3254266420ab83b75fd0fd2fbef5ae60",
            "0566938f865ebead8a2f88eebec11a1130f5269313fbdf718af052712a38e2b7",
            "c49c34e28f09999aa9b9fd81ea90631ec7a0408db5743283b642688c723f37e7",
            "8dd7b8693034d4f08d459e25ac8a0c7c47486ef1d0d24da49ec0b4e00e61ced1",
            "c0e1a6c562fa20ef8aeafa373ca15f804fd2cd9414721768559c96bb2e6e49ad",
            "66b33ab03cfd77339810fe0ae411181b1a357f6f733435a7442117efbdf95a44",
            "014e421d417dfe2fd570bed822969b202c036f9c2e657f498a1a47f716984422",
            "1001028c7bf7519d0a13032fe2c61a594b040f6dc29e5875c3a49efbd63dccf3",
            "bc269285ed5dedd0341f847a8ac578710a3a08ac532fe3e4f1328a74d17e38f4",
            "d5b177c746172248a3cf14c6a954bfffc6b87b1aedc2960f727559382ad75cd6",
            "e87ee7c3a9045c02f763b27230170a9e8d734852e7bca122d6c75a4f69b1bce4",
            "cdc282527e6bcc6c76f67975a55ee2ba563f8b56864ed747424c47d4f0b5b400",
            "3f735024c6a874c8fa45b0bf70f5193ddd596b3e96010fd4dba2da70de50dbef",
            "a2d2fcfbfca0aba790816d9415576a48ba8289ec68d0281ef6526a44fc9d8266",
            "6dbb769ba132d11d851d4263d4797a99eec50b7e807e740721df7efc6b39a654",
            "fd6be0f80740697ed47f12e599a34211186f5946b3464843dfbd24fe8004e4d2",
        ]
    );
}

#[test]
fn released_v26_migration_bytes_are_unchanged() {
    assert_eq!(
        format!("{:x}", Sha256::digest(MIGRATION_V26.as_bytes())),
        "d05eba44ea3e9a85f7ee4706cef15487495c2b911d0c302966810ec7c75fe7c7"
    );
}

#[test]
fn released_v27_migration_bytes_are_unchanged() {
    assert_eq!(
        format!("{:x}", Sha256::digest(MIGRATION_V27.as_bytes())),
        "6edf39fadbddbaf89c613dbfabd77a13a2938682b97d859481abbf0717f0a9b8"
    );
}
