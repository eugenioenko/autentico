# Federation claim admission

Issue #579 stores an ordered rule array on the owning provider as checked JSON TEXT, reusing `federation_providers`. Rules are configuration read with a provider, not separately identified or queried records; a values table adds joins and lifecycle management without a current need.

Each typed `{claim, match, value}` row uses `equals`, `not_equals`, `regex` or `not_regex`. Values are strings or booleans; regex requires a string. Every row must pass. Literal top-level claim names and strict types avoid traversal, scripts and coercion. Missing/null/wrong-type claims fail even negative comparisons. Go regexp gives bounded matching without backtracking; patterns are compiled for validation and evaluation. Search semantics and valid empty patterns match Go; anchors request whole-value matching.

The callback preserves normal signature/issuer/audience/expiry/nonce verification, reloads provider configuration after network I/O, then checks admission before resolveUser and local login effects. Invalid stored rules deny authentication but remain visible as an admin error so a deliberate replacement or empty-array clear can repair them. Omitted updates never silently repair a broken policy. Other login methods and existing sessions are not retrospectively restricted.

The read-only admin tester accepts draft rules and a sample object, shares the matcher, and reports safe row categories without values. It does not verify JWTs, contact issuers, persist samples, create users or issue credentials. Request and rule limits bound work. Admin UI validation also uses Go, avoiding JavaScript regex differences. Positive/negative matcher, callback, migration, real-process HTTP and real TLS proxy browser tests cover the contract.
