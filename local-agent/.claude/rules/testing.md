# Testing Rules

## What a change must prove

Every change touching authority — the state machine, a schema, a gate, the
retry budget, the registry — lands with tests that demonstrate the invariant
still holds. New authority or a new side effect gets its tests *first*.

## The two-part assertion

A rejection test asserts two things, always:

1. the correct rejection outcome occurred, and
2. the executor was never invoked.

The second half is what makes it a security test. `harness.executor.call_count`
is the spy; use it. A test that only checks the error code would still pass if
the controller executed the call and then reported an error.

For the filesystem capability there is a **third** part, because the executor
being dispatched is not the same question as bytes being read: assert with the
`fs_spy` fixture that no physical read of an unauthorized location occurred.
An executor that opened a file and *then* errored would satisfy both of the
first two assertions while having already read the data.

`test_the_filesystem_spy_records_real_reads` is the positive control for that
fixture. Without it, a monkeypatch that silently stopped taking effect would
make every "no read occurred" assertion pass vacuously. Never delete it.

## Suite layout

| File | Proves |
|---|---|
| `test_contracts.py` | schemas accept the legal and reject the illegal, at the boundaries |
| `test_state_machine.py` | every one of the 169 state pairs is legal or raises, per the table |
| `test_adversarial.py` | the 20 required hostile-input cases |
| `test_authority.py` | the architecture invariants (model cannot execute, authorize, retry more, …) |
| `test_filesystem.py` | the read-only capability: traversal, symlinks, containment, ceilings, sanitization |
| `test_model_adapter.py` | the model boundary: transport failures, injection, request security, config |
| `test_http_transport.py` | the network-granted module, against a loopback stdlib server |
| `test_live_boundary.py` | the gate itself: skip without it, fail with it and no service |
| `test_live_localai.py` | opt-in live scenarios; skipped unless `LOCAL_AGENT_LIVE_MODEL` is set |
| `test_persistence.py` | the durable boundary: round trip, identity derivation, fsync ordering, locking, ceilings, and the corruption matrix |
| `test_recovery.py` | crash windows A–F with measured execution counts, the recovery matrix, adversarial journal mutations, and that replay executes nothing |
| `test_operator.py` | the control plane: plan identity, approval binding, staleness, the adversarial operator matrix, terminality, inspection, ceilings |
| `test_operator_recovery.py` | recovery end to end: 13 crash windows, safe resume, revalidation, abort semantics, concurrency, model-context security, transparency |
| `test_capability.py` | the capability contract: the admission matrix, immutability including nested, capability identity, the side-effect/retry/idempotency matrix (cases A–H), executor isolation, the result boundary, authority-named model fields, and the runtime secret sentinels |
| `test_workspace_write.py` | the constrained artifact writer: containment under a write, the file-type policy, size limits and their journal coupling, authorization, bounded idempotency, retry counts, crash windows, operator recovery, and the result and model boundaries |
| `test_workspace_append.py` | the first non-re-executable mutation: the fourth corner of the contract, the R(R(S)) != R(S) criterion with an `IDEMPOTENT` control, the retry proof by physical count, recovery cases A-H, the operator terminal path, hostile results, and the M9 decision surface over 52 repetitions |
| `test_determinism.py` | 200 repetitions per in-memory scenario, 100 per filesystem, model, recovery, and operator scenario |
| `test_controller_flow.py` | gate ordering, audit events, budget arithmetic |
| `test_architecture.py` | the capability boundary, enforced against the package AST |

## Rules

1. **No special-casing.** A test may not be made to pass by adding a branch
   that recognises its input. If a test fails, the contract is wrong or the
   implementation is — fix the general case.
2. **Determinism is a property under test, not an assumption.** Anything that
   introduces wall-clock time, randomness, iteration-order dependence, or
   ambient state into a run breaks `test_determinism.py`, which is the point.
3. **Programmer errors stay visible.** Never widen an `except` clause to make a
   test green. `test_case_18d` asserts that an unexpected executor exception
   propagates; a blanket `except Exception` would hide real defects behind a
   normalized error code.
4. **Exhaustive beats illustrative** where the space is small enough to walk —
   the transition table is checked as a full product, not by example.
5. **Filesystem tests own their tree.** Build fixtures under pytest's
   `tmp_path` and nowhere else. Never read the developer's home directory, the
   repository, `/`, or any host location — a suite whose result depends on the
   machine it runs on proves nothing about the code.
6. **Assert positive and negative.** An inside-root symlink must work *and* an
   outside-root one must fail; an authorized root must work *and* an
   unauthorized one must fail. A test suite that only proves things are refused
   cannot tell a working capability from a broken one.
7. **The live gate decides skip versus fail, and both directions are tested.**
   Gate absent → SKIP. Gate present but misconfigured or unreachable → FAIL.
   Turning an explicitly requested live run into a silent skip is the failure
   mode `test_live_boundary.py` exists to catch; never "simplify" it away.
8. **Never weaken TLS to make a test pass.** The scan in
   `test_architecture.py` covers tests as well as `src/` precisely because
   that is where a bypass would be hidden.
9. **The deterministic suite never needs a server.** No test may require a
   running LocalAI, network access beyond loopback, credentials, a GPU, or a
   model download. A live smoke test is allowed only behind an environment
   variable, and must never gate CI.
10. **Say "deterministic controller behavior under controlled model responses",
   not "deterministic".** A real model is probabilistic. The determinism under
   test belongs to the control plane, not to generation.
11. **Crashes are simulated, never slept for.** A crash is a
   `SimulatedCrash(BaseException)` raised at a chosen record boundary by
   `CrashingJournal` or `CrashingExecutor`. `sleep()` would make the suite slow
   and, worse, timing-dependent — the thing `test_determinism.py` exists to
   forbid. It also derives from `BaseException` deliberately, so a stray
   `except Exception` cannot swallow it and turn a crash test green.
12. **An adversarial journal test recomputes the checksum.** Mutating a record
   and leaving the old checksum only proves the checksum works. The interesting
   attacker knows how to recompute it, so the test must too — that is what
   forces the assertion onto re-derivation and re-validation, where the real
   defence lives.
13. **A crash-window test asserts the physical execution count.** Not just the
   disposition: the question "did the side effect happen" is answered by
   counting executor invocations, and a test that only checks the returned plan
   would pass even if recovery had re-run a non-repeatable tool.
14. **An operator test asserts the refusal *and* the two counters.** Not just
   that the decision was rejected: `executor.call_count == 0` and
   `adapter.call_count == 0`. A rejection returned after a side effect, or
   after a model call, is not a rejection.
15. **A model-leak test uses sentinels, not eyeballs.** Put a unique value in
   the plan id, the execution id and the reason code, then assert it is absent
   from everything the adapter was sent. Reading the payload and deciding it
   looks fine proves nothing about the next change.
16. **A boundary scan needs a positive control.** Every AST check that asserts
   an absence has a sibling that poisons a copy and proves the same predicate
   fires. Without it a scanner that silently stopped working would make every
   assertion pass vacuously — `test_the_operator_boundary_check_actually_catches_a_violation`
   is the pattern.
17. **A security property is proven by mutation, not by assertion.** Break the
   real implementation, confirm a named test fails, restore it byte-for-byte,
   confirm the suite is green again. Milestone 7 did this for eleven mutations
   — the admission gate, the registry proxy, the attribute guard, the retry
   gate, both derived properties, the digest check, the coherence rule, name
   validation, the executor-protocol check, and a deliberate metadata leak into
   the model surface. Milestone 8 added fifteen more against a real side
   effect — path containment in both its mechanisms, the file-type checks, the
   write ceiling and its journal coupling, the classification, retry
   suppression, digest verification, result validation, registry admission,
   recovery's resume gate, and both read-only builders. A test nobody has
   watched fail is a test nobody has verified.
18. **Watch for a mutation "caught" by a broken selector.** A `-k` expression
   that matches nothing exits non-zero and looks like a detection. Treat "no
   tests ran" as an audit failure, not a pass — this happened once and was
   caught only because the output was read rather than the exit code.
19. **A refusal test names the reason.** Every admission failure asserts a
   stable slug rather than a message, so the matrix is testable by outcome and
   a reworded error does not silently pass the wrong check.
20. **Assert the limitation too.** `test_the_schema_classes_a_spec_points_at_remain_mutable`
   exists to keep a real weakness visible. Deleting a test because it documents
   something uncomfortable is how a known limitation becomes a forgotten one.
21. **A side-effecting capability needs a third counter.** `call_count` says
   the executor was dispatched; `write_count` says bytes reached a disk. They
   are different facts and only the second is irreversible, so every refusal
   in `test_workspace_write.py` asserts the run was refused, `write_count` is
   zero, *and* — where an escape was attempted — that the sentinel file
   outside the root is byte-identical. Without the third, a containment bug
   would produce a passing test rather than a failing one.
22. **A hang is not a failure, so test the ordering.** An outcome assertion
   cannot catch a removed check whose absence causes a block: the test never
   finishes. Where a check exists to prevent blocking — the
   non-regular-destination check, because `os.open` on a FIFO waits for a
   reader and no timeout is enforced anywhere — assert that the dangerous call
   is never reached, using a spy with its own positive control. That turns a
   five-minute stall into a named failure in milliseconds.
23. **Derive payloads from a ceiling and you stop testing the ceiling.** Every
   size test here computes its payload from `max_file_write_bytes`, so raising
   that constant moves the goalposts and they all still pass. A constant whose
   *value* matters needs a test that names the invariant —
   `test_the_write_ceiling_stays_below_the_journal_argument_ceiling` — not
   just one that exercises the mechanism.
24. **Audit the audit.** A mutation harness is production code for the purpose
   of trusting its output. Pass `-k` expressions as argument lists, never a
   string that gets `.split()` (spaces become path arguments, and pytest then
   selects nothing or the wrong subset — this produced both a false catch in
   M7 and two false misses in M8). Treat a subprocess timeout as an audit
   failure. And re-examine every "a second mechanism holds" claim: it is a
   statement about a *specific* failure mode, and asking a containment
   mechanism to cover an availability failure is a category error that only
   measurement catches.
25. **A retry test for a `MUTATING` capability needs its opposite.** "One
   physical effect" proves the capability gate only if an otherwise identical
   `IDEMPOTENT` harness still produces three. Without that control the test
   would pass just as well if retry were broken outright —
   `test_the_idempotent_writer_is_still_retried_three_times` is the control,
   and it must keep failing if retry stops working generally.
26. **Assert the physical count, not the boolean.** `re_executable is False`
   is a fact about a dataclass. The milestone's claim is about the world, so
   the assertion is the number of appends that reached a disk *and* the file's
   contents. A spy count alone would pass if the bytes went elsewhere.
27. **A crash is not a failure, and the suite must keep them apart.** A clean
   executor failure records `ExecutionCompleted(status="failed")` and closes
   the ambiguity window; only a `SimulatedCrash` leaves it open. Tests that
   want `execution_unknown` must crash, and there is a sibling test asserting
   the failure path lands on `execution_completed` instead — collapsing them
   is the "unknown means failed" error the architecture forbids.
28. All gates (`uv lock --check`, `pytest`, `ruff check`, `ruff format --check`,
   `mypy`) pass before a change is done. CI runs the same ones in the same
   order.
