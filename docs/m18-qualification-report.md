# M1.8 Qualification Report

Target: `avbox-m1-qualification`, Debian 13, x86-64.

The harmless deterministic dataset contains A, exact copy A2, slightly modified
B, and unrelated C. The reference provider knows A, two containing parents,
multiple provenance sources, independent rights/physical-original state, and B
as an ssdeep candidate. Real loopback tests cover authentication, exact parsing,
timeout, malformed JSON, response bounds and identity conflict. Instrumentation
asserts exact requests contain hashes/size but no bytes or caller URL.

Production RAB is not configured (`NOT_AVAILABLE`). Debian 13 now has packaged
TLSH, but integration remains `DEFERRED`; no production integration is claimed.
Final commands, deployment recaps, retro and
document/executable chain evidence, Git state, and acceptance outcome are added
after VM qualification.

## Final evidence

Qualification ran on `avbox-m1-qualification`: Debian 13.6, x86-64, 2 vCPU,
3921 MiB RAM. The final full VM suite passed 139 tests. The real loopback
provider tests passed authenticated exact lookup, missing/bad auth, timeout,
malformed response, oversized response and identity conflict. Typed tests passed
exact A, unrelated C no-match, two RAB occurrences, two provenance records,
unknown redistribution rights with physical ownership true, ssdeep candidate
without verdict change, budget exhaustion, and unavailable ordinary-job success.

A real ADF -> LHA `-lh0-` -> known child retained depth-two AVBox ancestry and
separate RAB occurrence authority. A real OOXML -> embedded MZ child retained its
document edge and executable analyzer result alongside exact RAB context. The
request recorder and loopback request body contained hashes, size and optional
fingerprint, with neither object bytes nor a URL. A returned loopback URL remained
inert metadata.

An authenticated RAB -> AVBox Protocol v1 `correlation-default@1` job returned
`COMPLETE` analysis with qualified ssdeep and typed `RAB_UNAVAILABLE` correlation;
the unavailable provider did not fail the job or alter a verdict. Production RAB
was not configured or claimed.

Local gates passed: pytest (139 collected; five loopback tests skipped only in
the socket-restricted workspace and passed on the VM), Ruff, strict mypy, Python
compilation, offline sdist/wheel build, registry validation, doctor, Ansible
syntax, systemd unit verification and `git diff --check`. The isolated build was
also attempted; it could not download an already-installed build backend because
the workspace has no network, so the successful build used `--no-isolation`.

The final deployment changed three tasks (source, editable install and restart).
The immediately following identical Ansible run reported `ok=20 changed=0
failed=0 skipped=1`. The service was active/enabled, `/health` reported M1.8,
and `ss` showed only `127.0.0.1:8080` for AVBox. Doctor and registry validation
passed on the VM.

Qualification defects fixed during execution: an asynchronous acceptance-state
race, recursive child `ObjectIdentity` correlation omission, tmpfs exhaustion in
the harness, an omitted transfer-only example fixture, and an undersized valid
loopback fixture limit. Test data was moved to `/var/tmp`; no preservation or
quarantine data was removed.

M1.8 acceptance result: PASS.
