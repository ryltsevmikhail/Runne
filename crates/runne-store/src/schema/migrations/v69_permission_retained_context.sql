ALTER TABLE x2_permission_bindings ADD COLUMN retained_context BLOB
 CHECK(retained_context IS NULL OR (typeof(retained_context)='blob' AND length(retained_context) BETWEEN 1 AND 1048576));
ALTER TABLE x2_permission_bindings ADD COLUMN retained_context_digest BLOB
 CHECK(retained_context_digest IS NULL OR (typeof(retained_context_digest)='blob' AND length(retained_context_digest)=32));
CREATE TRIGGER x2_permission_bindings_context_pair_guard
 BEFORE INSERT ON x2_permission_bindings
 WHEN (NEW.retained_context IS NULL) != (NEW.retained_context_digest IS NULL)
 BEGIN SELECT RAISE(ABORT,'X2 retained context requires exact pair'); END;
