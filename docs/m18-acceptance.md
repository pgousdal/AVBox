# M1.8 Acceptance

Acceptance requires full tests and packaging gates, Debian 13 deployment
convergence twice, healthy loopback-only service, a clean locally committed
worktree, and no push.

Automated gates cover exact/no-match, child attachment, multiple occurrences and
provenance, rights/physical-original distinction, ssdeep semantics, verdict
independence, unavailable/auth/timeout/malformed/oversized behavior, identity
conflict, inert hostile metadata, no-bytes request shape, no returned-URL fetch,
recursive budgets, Protocol v1 mapping, and capability truth. Production RAB and
TLSH are not gates but their status must remain truthful.

Final evidence and blockers are recorded in `m18-qualification-report.md`.

Status: **PASS**. The final Debian qualification, quality gates, deployment,
idempotence and service-health evidence are recorded in the qualification report.
