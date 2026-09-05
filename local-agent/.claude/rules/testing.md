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

## Suite layout

| File | Proves |
|---|---|
| `test_contracts.py` | schemas accept the legal and reject the illegal, at the boundaries |
| `test_state_machine.py` | every one of the 169 state pairs is legal or raises, per the table |
| `test_adversarial.py` | the 20 required hostile-input cases |
| `test_authority.py` | the architecture invariants (model cannot execute, authorize, retry more, …) |
| `test_determinism.py` | 200 repetitions per scenario produce an identical trace |
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
5. All four gates (`pytest`, `ruff check`, `ruff format --check`, `mypy`) pass
   before a change is done.
