# Local AI Agent Reference — Canonical Specification
Version: 2026-09-05
Hardware: ASUS ROG Strix G15CS, i7-9700F, RTX 2070 SUPER 8 GB, 16 GB DDR4

## Purpose
This repository is the source-of-truth engineering specification for a local AI agent. The design treats the LLM as an untrusted probabilistic component and places all operational authority in a deterministic controller.

## Core guarantee
The system cannot make the neural model deterministic. It can make the **control plane deterministic**:

`MODEL OUTPUT -> PARSE -> SCHEMA -> AUTHORIZATION -> POLICY -> BUDGET -> EXECUTE -> VERIFY`

Malformed, hallucinated, unauthorized, or ambiguous tool calls must never directly execute.

## Practical capacity model
Do not confuse active parameters with resident memory.

- Dense models: all parameters are resident and active.
- MoE models: active parameters reduce compute, but the complete resident weight set still requires memory.
- Host offload can introduce PCIe and DDR4 bandwidth bottlenecks.
- 8 GB VRAM and 16 GB RAM are hard physical constraints.
- Quantized model file size is not the same as total runtime memory: KV cache, CUDA buffers, graph/workspace allocations, tokenizer/runtime overhead, OS/display use, and fragmentation also consume memory.

Gemma 4 12B is the primary candidate only after measurement. Gemma 4 26B A4B is a heavy candidate only after measurement. No model is promoted because of parameter-count theory.

## Determinism boundaries
Deterministic:
- finite-state controller
- schemas
- tool registry
- authorization
- policy
- retry budgets
- timeouts
- idempotency
- execution routing
- verification rules
- benchmark harness
- pinned dependencies

Probabilistic:
- LLM generation
- semantic interpretation
- generated plans
- natural-language responses

## First implementation milestone
1. Deterministic in-memory FakeFileSearch executor.
2. Controller state machine.
3. Typed ToolFeedback / ControllerError protocol.
4. Pydantic validation.
5. Policy enforcement.
6. Bounded retries.
7. Adversarial tests.
8. Only then real filesystem search.
9. Only after that Playwright.

## Non-negotiable invariant
The model may propose. The controller decides. The executor executes only controller-approved requests.
