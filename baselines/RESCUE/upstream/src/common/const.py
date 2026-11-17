# config directory
CONF_DIR = "conf"
CONF_MODEL_DEPLOY_PATH = "conf/model_deploy.yaml"
CONF_SECRET_PATH = "conf/secret.yaml"

# Code Guard Plus
CODEGUARDPLUS_DATASET_PATH = "data/ql_check_completion_prompt.json"

# C and CPP
C_MAKEFILE_PATH = "repos-archive/CodeGuardPlus/inference/makefiles/c/Makefile"
CPP_MAKEFILE_PATH = "repos-archive/CodeGuardPlus/inference/makefiles/cpp/Makefile"

# experiments
RESULT_DIR = "experiments/cgp/"
RESULT_GENERATION_DIR = "experiments/cgp/generation"
RESULT_EVALUATION_DIR = "experiments/cgp/evaluation"
RESULT_METRIC_DIR = "experiments/cgp/metric"
CODEGUARD_CWD_DIR = "repos-archive/CodeGuardPlus"
CODEGUARDPLUS_SAMPLING_NUM = 1


# retrieval cache
RETRIEVAL_CACHE_DIR = "data/retrieval_cache"
RETRIEVAL_CACHE_ANALYZE_DIR = "data/retrieval_cache/analysis"
RETRIEVAL_CACHE_INDICES_DIR = "data/retrieval_cache/indices"
RETRIEVAL_CACHE_RESULTS_DIR = "data/retrieval_cache/results"

# knowledge base
CODE_LEVEL_KNOWLEDGE_PATH = "data/knowledge/code_level_knowledge.json"
CWE_LEVEL_SUMMARY_PATH = "data/knowledge/cwe_level_knowledge.json"

# semgrep
SEMGREP_TEMP_DIR = "tmp/"

# HumanEvalPlus
HUMAN_EVAL_PLUS_RESULT_DIR = "experiments/hep"
HUMAN_EVAL_PLUS_SAMPLE = 100

# BigCodeBench
BIGCODEBENCH_RESULT_DIR = "experiments/bcb"
BIGCODEBENCH_SAMPLE = 10

# LiveCodeBench
LIVECODEBENCH_RESULT_DIR = "experiments/lcb"
LIVECODEBENCH_SAMPLE = 10
LIVECODEBENCH_FUNC = "repos-archive/LiveCodeBench/lcb_runner/prompts/few_shot_examples/generation/func.json"
LIVECODEBENCH_STDIN = "repos-archive/LiveCodeBench/lcb_runner/prompts/few_shot_examples/generation/stdin.json"

# CWEval
CWEVAL_REPO_DIR = "repos-archive/CWEval"
CWEVAL_BENCHMARK_DIR = "repos-archive/CWEval/benchmark"
CWEVAL_RESULT_DIR = "experiments/cweval"
CWEVAL_SAMPLE = 10
CWEVAL_SUPPORTED_LANGS = ["py", "c", "cpp"]
# CWEVAL_SUPPORTED_LANGS = ["go", "js"]

# SecCodePLT (evaluated through the sibling SeCode-Eval checkout)
SECCODEPLT_DATASET = "anonymous/SecCodePLT"
SECCODEPLT_RESULT_DIR = "experiments/seccodeplt"
SECCODEPLT_SAMPLE = 1

# BaxBench
BAXBENCH_REPO_DIR = "repos-archive/BaxBench"
BAXBENCH_RESULT_DIR = "experiments/baxbench"
BAXBENCH_SAMPLE = 1
BAXBENCH_TEST_WORKERS = 16
BAXBENCH_LANGUAGE_MAP = {
    "python": "py", "javascript": "js", "typescript": "js",
    "golang": "go", "go": "go", "ruby": "rb", "rust": "rust",
    "php": "php",
}

# Model classification
# Models that use chat_complete() API. All others use completion().
CHAT_MODELS = {"gpt-4o-mini", "Deepseek-V3", "Qwen3-8B", "Qwen3-8B-base"}
