trait Query {
    fn query_row<T, F>(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
        f: F,
    ) -> rusqlite::Result<T>
    where
        F: FnOnce(&rusqlite::Row<'_>) -> rusqlite::Result<T>;
}
impl Query for Connection {
    fn query_row<T, F>(&self, sql: &str, params: impl rusqlite::Params, f: F) -> rusqlite::Result<T>
    where
        F: FnOnce(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    {
        Connection::query_row(self, sql, params, f)
    }
}
impl Query for Transaction<'_> {
    fn query_row<T, F>(&self, sql: &str, params: impl rusqlite::Params, f: F) -> rusqlite::Result<T>
    where
        F: FnOnce(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    {
        Connection::query_row(self, sql, params, f)
    }
}
