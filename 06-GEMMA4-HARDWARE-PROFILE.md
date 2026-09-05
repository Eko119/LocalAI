# 06 — Gemma 4 Hardware Profile

Target:
- ASUS ROG Strix G15CS
- RTX 2070 SUPER 8 GB GDDR6
- i7-9700F
- 16 GB DDR4

## 1. Memory accounting
Treat these as separate quantities:

`model weights + KV cache + runtime buffers + CUDA workspace + OS/display + application memory`

A quantized GGUF file size is only one component.

For MoE:

`resident weights != active parameters`

Active parameters describe computation per token; resident weights determine storage pressure.

## 2. Benchmark matrix

| Candidate | Quantization | Strategy | Contexts | Required evidence |
|---|---|---|---|---|
| Gemma 4 12B | exact tested GGUF Q4 variant | GPU-first, tuned -ngl | 4K/8K/16K | VRAM, RAM, TTFT, t/s, failures |
| Gemma 4 26B A4B | exact tested GGUF Q4 variant | hybrid experiment | 4K/8K/16K where viable | VRAM, RAM, TTFT, t/s, failures |

Do not hard-code unsupported thresholds such as `15 t/s` or `2 t/s` as universal truth. Establish project thresholds after baseline measurement.

## 3. llama.cpp parameters
Tune and record:
- `-ngl` / `--n-gpu-layers`
- `-c` / `--ctx-size`
- batch and microbatch settings
- flash attention if supported by the exact build/model
- threads
- split/offload options if used

Do not copy a flag set from another GPU and assume equivalence.

## 4. Promotion gates
A configuration is acceptable only if:
- no OOM at target context
- no unacceptable system thrashing
- stable repeated runs
- tool protocol tests pass
- latency meets the project's measured requirement
- exact configuration is reproducible

## 5. Failure thresholds
Record:
- first OOM context
- first severe slowdown
- first host-memory pressure event
- first correctness regression
- maximum stable context
- maximum stable generation duration

## 6. Benchmark record
Each result must include:
- date
- git commit
- llama.cpp commit/build
- model repository and filename
- quantization
- GPU driver
- CUDA/toolchain information
- OS
- context
- offload layers
- batch/ubatch
- prompt
- output length
- TTFT
- prompt t/s
- generation t/s
- peak VRAM
- peak RAM
- exit/error status
