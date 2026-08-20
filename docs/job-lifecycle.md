# Job lifecycle

Normal flow is `CREATED -> STAGED -> QUEUED -> RUNNING -> COMPLETE`. Failures may arise from any active state; staging/running/complete may lead to `QUARANTINED`. `FAILED` and `QUARANTINED` are terminal. Invalid transitions raise immediately.

A job retains requested/applicable scanners, why each result was selected, definition/rule state, native and normalized results, raw-output references, errors and timestamps. M1 removes clean transient staging immediately. MALICIOUS, SUSPICIOUS, and PUA objects enter immutable SHA-256 content-addressed quarantine when enabled; the external source is never moved.

Aggregate precedence is MALICIOUS, PUA, SUSPICIOUS, then CLEAN. An operational error plus otherwise-clean results is UNKNOWN; errors alone are ERROR. Unsupported/unavailable detectors never become CLEAN. System-detector warnings remain ambiguous SUSPICIOUS findings and do not participate in ordinary file jobs.

RAB submissions reuse this state machine asynchronously. Accepted uploads reach QUEUED before response; bounded workers transition RUNNING to COMPLETE/QUARANTINED/FAILED. Startup reconciles stale STAGED, QUEUED, or RUNNING RAB jobs to FAILED/interrupted so an unclean restart never leaves phantom work or silently executes twice.
