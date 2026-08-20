# Job lifecycle

Normal flow is `CREATED -> STAGED -> QUEUED -> RUNNING -> COMPLETE`. Failures may arise from any active state; staging/running/complete may lead to `QUARANTINED`. `FAILED` and `QUARANTINED` are terminal. Invalid transitions raise immediately.

A job retains requested/applicable scanners, platform hints, media type, results, normalized verdict, raw-output references, preservation decision, errors and timestamps. Clean-byte cleanup is deferred to later orchestration; policy defaults to zero-hour clean-byte retention.

