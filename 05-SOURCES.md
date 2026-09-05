# 05 — Sources and Evidence Register

Use this file as the evidence ledger for implementation decisions. Verify current upstream documentation before pinning a production build.

## Official / primary references

### Google Gemma
Model and technical documentation:
- https://ai.google.dev/gemma
- https://ai.google.dev/gemma/docs
- https://huggingface.co/google

Verify the exact Gemma 4 model card, license, supported modalities, context behavior, thinking configuration, and recommended inference runtimes for the exact model selected.

### llama.cpp
- https://github.com/ggml-org/llama.cpp
- https://github.com/ggml-org/llama.cpp/tree/master/docs

Verify current CUDA build instructions, GGUF support, context settings, GPU offload behavior, memory reporting, and model-specific compatibility.

### Model Context Protocol
- https://modelcontextprotocol.io/
- https://spec.modelcontextprotocol.io/

Verify the current specification and SDK documentation before implementing MCP. Do not assume an older revision's capability semantics remain unchanged.

### Pydantic
- https://docs.pydantic.dev/

Use Pydantic as the boundary for typed tool arguments and structured internal contracts.

### Python
- https://docs.python.org/3/

### uv
- https://docs.astral.sh/uv/

### Docker
- https://docs.docker.com/

Use official documentation for resource controls, isolation, networking, volumes, and rootless/daemon security.

### Playwright
- https://playwright.dev/docs/intro
- https://playwright.dev/python/

Use the official documentation for browser lifecycle, contexts, navigation, downloads, timeouts, and isolation.

### Qdrant
- https://qdrant.tech/documentation/

Use local deployment documentation for vector storage and retrieval.

## Evidence rules
- Primary documentation outranks blog posts.
- Exact model/runtime versions must be recorded.
- Benchmark claims must come from the target hardware.
- Never infer tokens/sec from parameter counts.
- Never infer memory fit from model-file size alone.
- Re-run compatibility checks after runtime/model upgrades.
