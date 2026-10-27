//! Complete current fixture rows, including retained context; SELECT only.
use runne_domain::id::{InvocationId, TaskRunId};
use rusqlite::{Connection, types::Value};
const TABLES: &[&str] = &[
    "taskrun_local_command_attempts",
    "taskrun_local_permission_routes",
    "taskrun_assignments",
    "taskrun_claim_receipts",
    "taskrun_assignment_occupations",
    "taskrun_terminal_settlement_receipts",
    "taskrun_local_command_stop_receipts",
    "taskrun_no_effect_release_receipts",
    "taskrun_provider_bindings",
    "provider_execution_admissions",
    "taskrun_dispatch_intents",
    "x2_permission_bindings",
    "x2_permission_human",
    "x2_permission_admission",
    "x2_permission_spent",
    "x2_permission_stop",
    "x2_permission_terminal",
];
#[derive(Debug, PartialEq)]
pub(super) struct Rows(Vec<(String, Vec<Vec<Value>>)>);
impl Rows {
    pub fn read(c: &Connection, task: TaskRunId) -> Self {
        let mut all = Vec::new();
        for table in TABLES {
            let sql = format!("SELECT * FROM {table} WHERE taskrun_id=?1 ORDER BY 1,2");
            let mut statement = c.prepare(&sql).unwrap();
            let columns = statement.column_count();
            let rows = statement
                .query_map([task.as_bytes()], |r| {
                    (0..columns)
                        .map(|i| r.get::<_, Value>(i))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            all.push(((*table).into(), rows));
        }
        Self(all)
    }
    pub fn count(&self, table: &str, expected: usize) {
        let row = self.0.iter().find(|(t, _)| t == table).unwrap();
        assert_eq!(row.1.len(), expected, "{table}");
    }
    pub fn assert_same_table(&self, other: &Self, table: &str) {
        let a = self.0.iter().find(|(t, _)| t == table).unwrap();
        let b = other.0.iter().find(|(t, _)| t == table).unwrap();
        assert_eq!(a, b, "{table}");
    }
    pub fn no_effect_evidence(&self) {
        for table in [
            "x2_permission_human",
            "x2_permission_admission",
            "x2_permission_spent",
            "x2_permission_stop",
            "x2_permission_terminal",
            "taskrun_dispatch_intents",
            "taskrun_provider_bindings",
            "provider_execution_admissions",
            "taskrun_local_command_stop_receipts",
            "taskrun_terminal_settlement_receipts",
        ] {
            self.count(table, 0);
        }
    }
}
pub(super) fn fresh_absent(c: &Connection, invocation: InvocationId) {
    for table in ["x2_permission_bindings", "x2_permission_spent"] {
        let sql = format!("SELECT count(*) FROM {table} WHERE invocation_id=?1");
        let count: i64 = c
            .query_row(&sql, [invocation.as_bytes()], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "fresh InvocationId must be absent from {table}");
    }
}
