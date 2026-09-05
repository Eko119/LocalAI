# 01 — Platform and Installation

## Target
ASUS ROG Strix G15CS:
- Intel Core i7-9700F
- NVIDIA RTX 2070 SUPER 8 GB GDDR6
- 16 GB DDR4
- 512 GB PCIe SSD
- 1 TB HDD

## Recommended baseline
- Windows 11 host if already installed.
- WSL2 Ubuntu for Linux-native development where appropriate.
- NVIDIA driver compatible with the chosen CUDA/llama.cpp build.
- Python 3.12+ only if supported by the pinned dependency set.
- `uv` for Python environment and lockfile management.
- Git for source control.
- Docker Desktop/Engine for isolated code execution, with explicit resource limits.
- llama.cpp for local GGUF inference and CUDA offload.

## Reproducibility
Pin:
- OS assumptions
- NVIDIA driver version
- CUDA/toolchain version
- llama.cpp commit
- model repository + exact model file
- quantization
- Python version
- Python package lock
- Docker image digest
- benchmark configuration

Never use an unpinned `latest` runtime in production.

## Storage layout
Recommended:
- SSD: OS, source, environments, active model, indexes.
- HDD: cold model archive, benchmark artifacts, backups.

## Security baseline
- Secrets never enter prompts or model-visible tool results.
- `.env` files excluded from Git.
- No unrestricted host filesystem mount for code execution.
- Network disabled by default for code execution.
- Tool registry is static and controller-owned.
