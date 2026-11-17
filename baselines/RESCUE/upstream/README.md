<div align="center">
    <h1>[ICLR 2026] RESCUE: Retrieval-Augmented Secure Code Generation</h1>
</div>
  
[![Paper](https://img.shields.io/badge/Paper-ICLR_2026-blue)](https://openreview.net/forum?id=gbxhesw4UH) 
[![arXiv](https://img.shields.io/badge/arXiv-2510.18204-b31b1b)](https://arxiv.org/abs/2510.18204)


## Overview

Large Language Models (LLMs) for code generation have shown remarkable progress, yet they still produce code containing security vulnerabilities. **RESCUE** (**RE**trieval-augmented **S**e**CU**re cod**E** generation) addresses this challenge through incorporating a hybrid security knowledge base.

![Overview of the RESCUE framework](asset/overview.png)

---

## Environment Setup

### Prerequisites

- Python 3.11 (recommended)
- [Docker](https://docs.docker.com/get-docker/) (required for HumanEval+, BigCodeBench, and CWEval evaluation)

### Installation

Set up the environment and install dependencies:

```bash
uv venv --python=3.11
source .venv/bin/activate
uv pip install -r requirements.txt
```

---

## Benchmark Preparation

We evaluate RESCUE on five benchmarks covering both functional correctness and security. Follow the instructions below to set up each benchmark.

| Abbreviation | Benchmark | Focus | Languages |
|:---:|:---|:---|:---|
| `cgp` | CodeGuard+ | Security (CodeQL + unittest) | Python, C, C++ |
| `cwe` | CWEval | Security (functional + secure tests) | Python, C, C++ |
| `hep` | HumanEval+ | Functional correctness | Python |
| `bcb` | BigCodeBench | Functional correctness | Python |
| `lcb` | LiveCodeBench | Functional correctness | Python |

### CodeGuard+

1. **Install CodeQL**

```bash
wget https://github.com/github/codeql-cli-binaries/releases/download/v2.17.5/codeql-linux64.zip
unzip codeql-linux64.zip -d ~
git clone --depth=1 --branch codeql-cli-2.17.5 https://github.com/github/codeql.git ~/codeql/codeql-repo
~/codeql/codeql pack download codeql-cpp@0.7.1 codeql-python@0.6.2 codeql/ssa@0.0.16 codeql/tutorial@0.0.9 codeql/regex@0.0.12 codeql/util@0.0.9
```

2. **Install Python Dependencies**

```bash
uv pip install -r repos-archive/CodeGuardPlus/requirements.txt
```

---

### HumanEval+ & BigCodeBench

These benchmarks rely on Docker for sandboxed evaluation. Please ensure Docker is installed and running before proceeding.

**Note:** There is a known issue in BigCodeBench at line 223 of `.venv/lib/python3.11/site-packages/bigcodebench/sanitize.py`:
```python
# buggy line
msg += " -> " + dbg_identifier.replace(samples, target_path)
```

This line references a non-existent path, causing the evaluation to fail. Please temporarily comment out or remove this line.

---

### LiveCodeBench

Clone and set up LiveCodeBench:

```bash
cd repos-archive
git clone --depth 1 https://github.com/LiveCodeBench/LiveCodeBench.git LiveCodeBench
cd LiveCodeBench
uv pip install -e .
```

---

### CWEval

CWEval is vendored under `repos-archive/CWEval` and already contains the benchmark assets. We evaluate on the **C, C++, and Python** subsets.

1. The required Python packages for CWEval are already included in `requirements.txt`.
2. Evaluation runs inside a Docker container (`co1lin/cweval`) — make sure Docker is available. Pull the image in advance: `docker pull co1lin/cweval`

The evaluation pipeline parses generated code, compiles C/C++ sources, runs functional and security tests inside Docker, and reports **pass@k** metrics for `func` (functional correctness) and `func-sec` (both functional and secure).

> **Modifications to CWEval source:** We modified `cweval/evaluate.py` in two places:
> 1. `pipeline()`: moved `compile_parsed()` out of the Docker path, so it only runs locally when `docker=False`.
> 2. `run_tests_in_docker()`: added a `compile_parsed` step to the Docker command, before `run_tests`.
>
> **Reason:** The original code compiled C/C++ locally before copying into Docker, which requires installing all system-level libraries (OpenSSL, libarchive, libjwt, etc.) on the host. Now compilation happens inside the `co1lin/cweval` container where these libraries are pre-installed. This change does not affect the evaluation behavior or correctness of the results.

---

## Running Experiments

### Step 1: LLM Deployment

**For local models** (e.g., Qwen2.5-Coder-7B-Instruct, DeepSeek-Coder-V2-Lite-Instruct):

```bash
bash scripts/vllm_deploy.sh <MODEL_PATH> <SERVED_MODEL_NAME> <PORT>
```

This starts a vLLM-based OpenAI-compatible API server.

**For API-based models** (e.g., GPT-4o-mini, DeepSeek-V3): skip this step.

### Step 2: Configuration

Copy the template configuration files and fill in your parameters:

```bash
cp conf/model_deploy.yaml.template conf/model_deploy.yaml
cp conf/secret.yaml.template conf/secret.yaml
```

- `model_deploy.yaml` — define API endpoints and ports for each model
- `secret.yaml` — store API keys

### Step 3: Code Generation

```bash
bash scripts/generate.sh <MODEL_NAME> <METHOD> <BENCHMARK>
```

- `<METHOD>`: `zero_shot` (baseline) or `rescue` (our method)
- `<BENCHMARK>`: `cgp`, `cwe`, `hep`, `bcb`, or `lcb`

### Step 4: Evaluation

```bash
bash scripts/evaluate.sh <MODEL_NAME> <METHOD> <BENCHMARK>
```

### Examples

```bash
# Zero-Shot baseline on CodeGuard+
bash scripts/generate.sh gpt-4o-mini zero_shot cgp
bash scripts/evaluate.sh gpt-4o-mini zero_shot cgp

# RESCUE on CodeGuard+
bash scripts/generate.sh gpt-4o-mini rescue cgp
bash scripts/evaluate.sh gpt-4o-mini rescue cgp

# RESCUE on CWEval
bash scripts/generate.sh gpt-4o-mini rescue cwe
bash scripts/evaluate.sh gpt-4o-mini rescue cwe
```

Results are saved to `experiments/<BENCHMARK>/<MODEL>/<METHOD>/`.

---

## Project Structure

```
.
├── conf/                       # Configuration files for LLM endpoints and API keys
│   ├── model_deploy.yaml.template
│   └── secret.yaml.template
├── data/
│   ├── knowledge/              # Pre-built security knowledge base
│   │   ├── code_level_knowledge.json
│   │   └── cwe_level_knowledge.json
│   └── ql_check_completion_prompt.json   # CodeGuard+ benchmark data
├── repos-archive/              # Vendored benchmark repositories
│   ├── CodeGuardPlus/
│   └── CWEval/
├── scripts/
│   ├── generate.sh             # Code generation entry script
│   ├── evaluate.sh             # Evaluation entry script
│   └── vllm_deploy.sh          # vLLM model deployment script
├── src/
│   ├── baselines/
│   │   └── zero_shot.py        # Zero-shot baseline (LLM alone)
│   ├── benchmarks/             # Benchmark runners
│   │   ├── benchmark.py        # Abstract base class
│   │   ├── bcb/                # BigCodeBench
│   │   ├── cgp/                # CodeGuard+
│   │   ├── cweval/             # CWEval
│   │   ├── hep/                # HumanEval+
│   │   └── lcb/                # LiveCodeBench
│   ├── common/
│   │   ├── const.py            # Constants and paths
│   │   ├── model.py            # LLM invocation (chat / completion)
│   │   ├── zero_shot_prompt.py # Zero-shot prompt templates
│   │   └── utils.py            # Utility functions
│   └── rescue/                 # RESCUE method implementation
│       ├── augmented_code_generation.py  # Online stage entry point
│       ├── augmented_prompt.py           # Augmented prompt construction
│       ├── construction/                 # Offline stage: knowledge base construction
│       │   ├── api_extraction.py         # API call extraction
│       │   └── program_slicing.py        # Program slicing
│       └── retrieval/
│           └── hmr.py                    # Hierarchical Multi-faceted Retrieval (HMR)
├── experiments/                # Output directory (generated code & evaluation results)
├── requirements.txt
└── README.md
```

---

## Citation

If you find this work useful, please cite our paper:

```bibtex
@inproceedings{
shi2026rescue,
title={Rescue: Retrieval Augmented Secure Code Generation},
author={Jiahao Shi and Tianyi Zhang},
booktitle={The Fourteenth International Conference on Learning Representations},
year={2026},
url={https://openreview.net/forum?id=gbxhesw4UH}
}
```