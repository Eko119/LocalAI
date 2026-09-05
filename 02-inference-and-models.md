# 02 — Inference, Models, and Benchmarking

## 1. Model-selection rule
Choose models empirically on the target machine. Model cards and parameter counts establish capability and expected memory, not guaranteed speed.

## 2. Candidate tiers

### Tier A — Small/Fast
Use a smaller GGUF when latency and long context matter more than peak reasoning quality.

### Tier B — Primary: Gemma 4 12B
Candidate uses:
- everyday conversation
- coding assistance
- structured tool proposals
- multimodal workloads supported by the exact model/runtime combination

Target: GPU-first operation.

Important: a Q4 file near the 8 GB VRAM ceiling does **not** mean the whole runtime fits. Measure weights + KV cache + runtime allocations + display/OS use.

### Tier C — Heavy: Gemma 4 26B A4B
Candidate uses:
- difficult coding
- difficult reasoning
- selected offline tasks

It has a large resident parameter set despite a much smaller active parameter count. If weights spill to host RAM, PCIe/DDR4 transfer behavior can dominate latency. Treat this as an experimental hybrid configuration.

## 3. Quantization
Compare multiple compatible GGUF quantizations if needed. Record:
- exact filename
- file size
- quantization type
- context
- GPU layers
- batch/ubatch
- flash-attention setting if supported
- prompt processing speed
- generation speed
- peak VRAM
- peak RAM
- failures

## 4. Benchmark protocol
Every production candidate must pass repeatable tests at 4K, 8K, and 16K where supported.

Measure:
- TTFT
- prompt tokens/sec
- generation tokens/sec
- peak VRAM
- peak RAM
- wall-clock completion
- context failure threshold
- tool-call schema success
- tool-call selection accuracy
- invalid-call rejection
- retry convergence

Run at least 3 repeated trials per configuration and retain raw results.

## 5. Tool reliability benchmark
Minimum suite:
1. valid file-search request
2. missing argument
3. wrong type
4. out-of-range value
5. unknown tool
6. arbitrary path
7. shell injection text
8. tool call embedded in thinking
9. duplicate invalid proposal
10. executor timeout
11. corrupt tool result
12. unauthorized root
13. malformed JSON
14. multiple competing tool calls

Report separate:
- schema accuracy
- policy accuracy
- execution correctness
- recovery correctness

Do not collapse all metrics into one unsupported score.

## 6. Promotion rule
A model is promoted only if it:
- fits the configured memory envelope
- meets the project's measured latency floor
- passes tool protocol tests
- passes adversarial controller tests
- has reproducible benchmark results
- has an exact runtime/model identity recorded
