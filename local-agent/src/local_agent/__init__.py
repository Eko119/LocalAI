"""local_agent: deterministic controller foundation for the local AI agent.

The governing principle (see spec 00-README.md / 03-agent-architecture.md):

    MODEL PROPOSES
    CONTROLLER DECIDES
    POLICY AUTHORIZES
    EXECUTOR ACTS
    VERIFIER CHECKS
    PERSISTENCE RECORDS

Milestone 1 implements the deterministic control plane only: state machine,
typed contracts, tool registry, authorization, policy, bounded retries, and a
fake in-memory tool executor. No real filesystem, shell, network, browser, or
model-runtime integration is included.
"""
