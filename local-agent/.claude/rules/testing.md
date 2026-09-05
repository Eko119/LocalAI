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
| `test_determinism.py` | 200 repetitions per in-memory scenario, 100 per filesystem, model, and recovery scenario |
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
14. All gates (`uv lock --check`, `pytest`, `ruff check`, `ruff format --check`,
   `mypy`) pass before a change is done. CI runs the same ones in the same
   order.
