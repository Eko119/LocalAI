# 08 — Final Corrections and Design Decisions

This document records corrections to earlier drafts.

## Correction 1 — MoE memory
Incorrect:
> 26B A4B behaves like a 4B model.

Correct:
> Only a subset of parameters is active per token, but the resident model weights still require storage. Host offload can create PCIe/DDR4 bottlenecks.

## Correction 2 — 12B VRAM
Incorrect:
> A ~7 GB Q4 model automatically fits in 8 GB VRAM with useful context.

Correct:
> Model file size does not equal runtime memory. KV cache and runtime allocations must be measured. The maximum usable context is hardware/configuration dependent.

## Correction 3 — Benchmark thresholds
Incorrect:
> Universal thresholds such as 15 t/s for 12B and 2 t/s for 26B.

Correct:
> Establish thresholds after baseline measurements. Thresholds are project acceptance criteria, not facts about the hardware.

## Correction 4 — Thinking tokens
Incorrect:
> Strip thinking and then parse arbitrary remaining text.

Correct:
> Define an explicit eligible generation channel. Reasoning content is never executable. Only a schema-valid candidate from the approved channel can reach policy evaluation.

## Correction 5 — Determinism
Incorrect:
> The local LLM is deterministic.

Correct:
> The LLM remains probabilistic. The controller, tool boundary, state machine, policies, retries, and execution routing are deterministic.

## Correction 6 — Retry protocol
The model may receive sanitized feedback and propose a correction. It cannot:
- increase retry budget
- alter policy
- alter schemas
- create controller states
- execute tools
- convert a denial into permission

Default maximum attempts: 3, configurable only by trusted application configuration.

## Correction 7 — First tool
Build:
1. fake in-memory file search
2. real read-only file search
3. Playwright

This order minimizes external nondeterminism while maximizing coverage of the control plane.
