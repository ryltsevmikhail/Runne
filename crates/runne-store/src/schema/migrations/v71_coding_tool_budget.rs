const V71_OLD_TARGET: &str = r"target_name TEXT NOT NULL CHECK(length(target_name) BETWEEN 1 AND 255 AND instr(target_name,'/')=0 AND instr(target_name,'\\')=0 AND target_name NOT IN ('.','..'))";
const V71_NEW_TARGET: &str = "target_name TEXT NOT NULL CHECK(length(target_name) BETWEEN 1 AND 255 AND instr(target_name,char(92))=0 AND instr(target_name,char(0))=0 AND ((environment_id!='linux-coding-agent-v1' AND instr(target_name,'/')=0 AND target_name NOT IN ('.','..')) OR (environment_id='linux-coding-agent-v1' AND environment_revision='1' AND tool_name IN ('workspace.file.read','workspace.file.create_new','workspace.file.replace','workspace.files.list','workspace.files.search','workspace.command.run') AND ((target_name='.' AND tool_name IN ('workspace.files.list','workspace.files.search','workspace.command.run')) OR (substr(target_name,1,1)!='/' AND substr(target_name,-1,1)!='/' AND instr(target_name,'//')=0 AND instr('/'||target_name||'/','/./')=0 AND instr('/'||target_name||'/','/../')=0)))))";
// A separate immutable coding policy; historical D2 rows retain exactly 2/2.
const V71_OLD_BUDGET: &str =
    "policy_revision TEXT NOT NULL CHECK(policy_revision='d2-safe-tool-loop-budget-v1'),
 effects_limit INTEGER NOT NULL CHECK(effects_limit=2),
 continuations_limit INTEGER NOT NULL CHECK(continuations_limit=2),
 effects_used INTEGER NOT NULL CHECK(effects_used BETWEEN 0 AND 2),
 continuations_used INTEGER NOT NULL CHECK(continuations_used BETWEEN 0 AND 2),
 updated_at INTEGER NOT NULL CHECK(updated_at>0)";
const V71_NEW_BUDGET: &str = "policy_revision TEXT NOT NULL CHECK(policy_revision IN ('d2-safe-tool-loop-budget-v1','coding-tool-loop-budget-v1')),
 effects_limit INTEGER NOT NULL CHECK(effects_limit IN (2,32)),
 continuations_limit INTEGER NOT NULL CHECK(continuations_limit IN (2,32)),
 effects_used INTEGER NOT NULL CHECK(effects_used BETWEEN 0 AND effects_limit),
 continuations_used INTEGER NOT NULL CHECK(continuations_used BETWEEN 0 AND continuations_limit),
 updated_at INTEGER NOT NULL CHECK(updated_at>0),
 CHECK((policy_revision='d2-safe-tool-loop-budget-v1' AND effects_limit=2 AND continuations_limit=2) OR (policy_revision='coding-tool-loop-budget-v1' AND effects_limit=32 AND continuations_limit=32))";
const V71_TRIGGERS: &[(&str, &str)] = &[
    (
        "taskrun_tool_invocations_policy_round",
        "CREATE TRIGGER taskrun_tool_invocations_policy_round BEFORE INSERT ON taskrun_tool_invocations WHEN NEW.round_index>COALESCE((SELECT continuations_limit FROM taskrun_tool_budgets WHERE taskrun_id=NEW.taskrun_id),-1) BEGIN SELECT RAISE(ABORT,'tool round exceeds bound policy'); END",
    ),
    (
        "taskrun_provider_round_policy_round",
        "CREATE TRIGGER taskrun_provider_round_policy_round BEFORE INSERT ON taskrun_provider_round_bindings WHEN NEW.round_index>COALESCE((SELECT continuations_limit FROM taskrun_tool_budgets WHERE taskrun_id=NEW.taskrun_id),-1) BEGIN SELECT RAISE(ABORT,'provider round exceeds bound policy'); END",
    ),
];

fn v71_schema_ddl() -> String {
    MIGRATION_V64
        .replace(
            "round_index BETWEEN 0 AND 2",
            "round_index BETWEEN 0 AND 32",
        )
        .replace(V71_OLD_BUDGET, V71_NEW_BUDGET)
        .replace(V71_OLD_TARGET, V71_NEW_TARGET)
}

fn apply_v71_migration(connection: &Connection) -> SqliteResult<()> {
    if !v70_matches(connection, 70)? {
        return Err(rusqlite::Error::InvalidQuery);
    }
    connection.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA legacy_alter_table=ON;")?;
    let result = (|| {
        let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
        rebuild_table(&tx, "taskrun_tool_budgets", V71_OLD_BUDGET, V71_NEW_BUDGET)?;
        for table in [
            "taskrun_tool_invocations",
            "taskrun_provider_round_bindings",
        ] {
            rebuild_table(
                &tx,
                table,
                "round_index BETWEEN 0 AND 2",
                "round_index BETWEEN 0 AND 32",
            )?;
        }
        rebuild_table(
            &tx,
            "taskrun_tool_invocations",
            V71_OLD_TARGET,
            V71_NEW_TARGET,
        )?;
        for (_, sql) in V71_TRIGGERS {
            tx.execute_batch(sql)?;
        }
        tx.execute("INSERT INTO schema_version(version) VALUES(71)", [])?;
        if !v71_matches(&tx, 71)? {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let violated: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
            [],
            |row| row.get(0),
        )?;
        if violated {
            return Err(rusqlite::Error::InvalidQuery);
        }
        tx.commit()
    })();
    let restore =
        connection.execute_batch("PRAGMA legacy_alter_table=OFF; PRAGMA foreign_keys=ON;");
    result.and(restore)
}

fn v71_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 71 || !v70_matches(connection, version)? {
        return Ok(false);
    }
    for (name, sql) in V71_TRIGGERS {
        if !schema_trigger_matches(connection, name, sql)? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod coding_budget_schema_tests {
    use super::*;
    #[test]
    fn coding_target_constraint_preserves_legacy_flat_names() {
        let connection = Connection::open_in_memory().unwrap();
        let sql = format!(
            "CREATE TABLE targets(environment_id TEXT, environment_revision TEXT, tool_name TEXT, {V71_NEW_TARGET})"
        );
        connection.execute_batch(&sql).unwrap();
        for (environment, revision, tool, target, accepted) in [
            (
                "linux-coding-agent-v1",
                "1",
                "workspace.files.list",
                ".",
                true,
            ),
            (
                "linux-coding-agent-v1",
                "1",
                "workspace.file.read",
                "src/main.rs",
                true,
            ),
            ("legacy", "1", "workspace.files.list", ".", false),
            ("legacy", "1", "workspace.file.read", "src/main.rs", false),
            ("legacy", "1", "workspace.file.read", "notes.txt", true),
            (
                "linux-coding-agent-v1",
                "2",
                "workspace.files.list",
                ".",
                false,
            ),
            (
                "linux-coding-agent-v1",
                "1",
                "workspace.file.read",
                ".",
                false,
            ),
            (
                "linux-coding-agent-v1",
                "1",
                "workspace.files.list",
                "../secret",
                false,
            ),
            (
                "linux-coding-agent-v1",
                "1",
                "workspace.files.list",
                "src/../secret",
                false,
            ),
            (
                "linux-coding-agent-v1",
                "1",
                "workspace.files.list",
                "src/./file",
                false,
            ),
            (
                "linux-coding-agent-v1",
                "1",
                "workspace.files.list",
                "/absolute",
                false,
            ),
            (
                "linux-coding-agent-v1",
                "1",
                "workspace.files.list",
                "src//file",
                false,
            ),
            (
                "linux-coding-agent-v1",
                "1",
                "workspace.files.list",
                "src/",
                false,
            ),
        ] {
            assert_eq!(
                connection
                    .execute(
                        "INSERT INTO targets VALUES(?1,?2,?3,?4)",
                        rusqlite::params![environment, revision, tool, target]
                    )
                    .is_ok(),
                accepted,
                "{environment}/{target}"
            );
        }
    }
    #[test]
    fn preserves_legacy_budgets_and_rejects_cross_policy_limits() {
        let connection = Connection::open_in_memory().unwrap();
        apply_migrations_internal(&connection, 69).unwrap();
        connection.execute("INSERT INTO taskrun_tool_budgets VALUES(?1,?2,1,'node',1,?3,?4,'d2-safe-tool-loop-budget-v1',2,2,1,1,1)",rusqlite::params![[1u8;16].as_slice(),[2u8;16].as_slice(),[3u8;16].as_slice(),[4u8;32].as_slice()]).unwrap();
        apply_v70_migration(&connection).unwrap();
        connection.execute_batch("INSERT INTO workspaces VALUES(zeroblob(16),zeroblob(16),'owner','root',1,1,1); INSERT INTO workspace_root_identities VALUES('authority','owner',zeroblob(16),zeroblob(32),1);").unwrap();
        apply_v71_migration(&connection).unwrap();
        assert!(v71_matches(&connection, 71).unwrap());
        assert_eq!(connection.query_row("SELECT root_version FROM workspace_root_identities WHERE runtime_authority_id='authority' AND principal_id='owner' AND workspace_id=zeroblob(16) AND filesystem_identity_digest=zeroblob(32)", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
        assert_eq!(
            connection
                .query_row(
                    "SELECT effects_limit,effects_used FROM taskrun_tool_budgets",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
                )
                .unwrap(),
            (2, 1)
        );
        assert!(
            connection
                .execute("UPDATE taskrun_tool_budgets SET effects_limit=32", [])
                .is_err()
        );
        assert!(connection.execute("INSERT INTO taskrun_tool_budgets VALUES(?1,?2,1,'node',1,?3,?4,'d2-safe-tool-loop-budget-v1',32,32,0,0,1)",rusqlite::params![[5u8;16].as_slice(),[6u8;16].as_slice(),[7u8;16].as_slice(),[8u8;32].as_slice()]).is_err());
        connection.execute("INSERT INTO taskrun_tool_budgets VALUES(?1,?2,1,'node',1,?3,?4,'coding-tool-loop-budget-v1',32,32,32,32,1)",rusqlite::params![[5u8;16].as_slice(),[6u8;16].as_slice(),[7u8;16].as_slice(),[8u8;32].as_slice()]).unwrap();
        connection
            .execute_batch("DROP TRIGGER taskrun_tool_invocations_policy_round")
            .unwrap();
        assert!(!v71_matches(&connection, 71).unwrap());
    }
}
