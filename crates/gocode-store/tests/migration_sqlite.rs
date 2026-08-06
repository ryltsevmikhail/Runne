#[path = "support/validated_reopen.rs"]
mod validated_reopen;

include!("migration_sqlite_split_parts/part_01.rs");
include!("migration_sqlite_split_parts/part_02.rs");
include!("migration_sqlite_split_parts/part_03.rs");
include!("migration_sqlite_split_parts/part_04.rs");
include!("migration_sqlite_split_parts/part_05.rs");
