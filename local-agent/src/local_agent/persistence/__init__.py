"""Durable controller state (Milestone 5).

`records.py` defines the typed, versioned record contracts and is pure: it
performs no I/O. `journal.py` is the only module that touches a durable
store, and holds the corresponding capability grant.

The journal is **not** a second authority. It is a durable representation of
controller-owned state, and every record read back is re-validated against
executable invariants before it is believed. See `recovery.py`.
"""
