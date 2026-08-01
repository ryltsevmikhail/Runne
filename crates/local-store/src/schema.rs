const REPLAY_TABLES_V4_SQL: &str = "
    DROP TABLE projections;
    DROP TABLE event_journal;
    DROP TABLE replay_cursors;

    CREATE TABLE projections (
        runtime_authority TEXT NOT NULL CHECK (length(runtime_authority) > 0),
        principal TEXT NOT NULL CHECK (length(principal) > 0),
        lineage TEXT NOT NULL CHECK (length(lineage) > 0),
        scope TEXT NOT NULL CHECK (length(scope) > 0),
        binding_digest TEXT NOT NULL CHECK (
            length(binding_digest) = 64
            AND binding_digest NOT GLOB '*[^0-9a-f]*'
        ),
        projection_revision INTEGER NOT NULL CHECK (projection_revision >= 0),
        projection_digest TEXT NOT NULL CHECK (
            length(projection_digest) = 64
            AND projection_digest NOT GLOB '*[^0-9a-f]*'
        ),
        event_sequence INTEGER NOT NULL CHECK (event_sequence >= 1),
        payload BLOB NOT NULL CHECK (json_valid(payload) = 1),
        PRIMARY KEY (runtime_authority, principal, lineage, scope)
    ) STRICT;

    CREATE TABLE event_journal (
        runtime_authority TEXT NOT NULL CHECK (length(runtime_authority) > 0),
        principal TEXT NOT NULL CHECK (length(principal) > 0),
        lineage TEXT NOT NULL CHECK (length(lineage) > 0),
        scope TEXT NOT NULL CHECK (length(scope) > 0),
        binding_digest TEXT NOT NULL CHECK (
            length(binding_digest) = 64
            AND binding_digest NOT GLOB '*[^0-9a-f]*'
        ),
        event_id TEXT NOT NULL CHECK (length(event_id) > 0),
        cursor TEXT NOT NULL CHECK (length(cursor) > 0),
        generation INTEGER NOT NULL CHECK (generation >= 0),
        event_sequence INTEGER NOT NULL CHECK (event_sequence >= 1),
        validated_event BLOB NOT NULL,
        event_digest TEXT NOT NULL CHECK (
            length(event_digest) = 64
            AND event_digest NOT GLOB '*[^0-9a-f]*'
        ),
        projection_revision INTEGER NOT NULL CHECK (projection_revision >= 0),
        projection_digest TEXT NOT NULL CHECK (
            length(projection_digest) = 64
            AND projection_digest NOT GLOB '*[^0-9a-f]*'
        ),
        projected_payload BLOB NOT NULL CHECK (json_valid(projected_payload) = 1),
        PRIMARY KEY (
            runtime_authority,
            principal,
            lineage,
            scope,
            event_id
        ),
        UNIQUE (
            runtime_authority,
            principal,
            lineage,
            scope,
            event_sequence
        ),
        UNIQUE (
            runtime_authority,
            principal,
            lineage,
            scope,
            cursor
        )
    ) STRICT;

    CREATE TABLE replay_cursors (
        runtime_authority TEXT NOT NULL CHECK (length(runtime_authority) > 0),
        principal TEXT NOT NULL CHECK (length(principal) > 0),
        lineage TEXT NOT NULL CHECK (length(lineage) > 0),
        scope TEXT NOT NULL CHECK (length(scope) > 0),
        binding_digest TEXT NOT NULL CHECK (
            length(binding_digest) = 64
            AND binding_digest NOT GLOB '*[^0-9a-f]*'
        ),
        generation INTEGER NOT NULL CHECK (generation >= 0),
        applied_cursor TEXT NOT NULL CHECK (length(applied_cursor) > 0),
        event_sequence INTEGER NOT NULL CHECK (event_sequence >= 1),
        projection_revision INTEGER NOT NULL CHECK (projection_revision >= 0),
        projection_digest TEXT NOT NULL CHECK (
            length(projection_digest) = 64
            AND projection_digest NOT GLOB '*[^0-9a-f]*'
        ),
        PRIMARY KEY (runtime_authority, principal, lineage, scope)
    ) STRICT;
";
