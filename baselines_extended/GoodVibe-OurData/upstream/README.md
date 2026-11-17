# GoodVibe

**GoodVibe** is a neuron‑level framework and research codebase for improving the security of code language models via targeted neuron discovery and selective fine‑tuning. It identifies security‑relevant neurons using gradient‑based attribution, applies neuron‑selective updates (with optional clustering), and evaluates generated code with a learned safety judge. In experiments, GoodVibe improves secure code generation while preserving utility, reaching 87.4% secure outputs ($2.49\times$ over the base model) with substantially fewer trainable parameters and lower compute.

## Contents
- [Highlights](#highlights)
- [Repository layout](#repository-layout)
- [Quickstart](#quickstart)
- [Core scripts](#core-scripts)
- [Flags and configuration](#flags-and-configuration)
- [Pipeline](#pipeline)
- [Citation](#citation)
- [Outputs](#outputs)

## Highlights
- End‑to‑end workflow: neuron discovery → fine‑tuning → inference → evaluation.
- Supports masked, clustered, full‑model, and LoRA fine‑tuning.
- Configurable experiment pipeline with YAML/JSON experiment files.

## Repository layout
1. **Data & utilities** — dataset loaders, prompt builders, GPU selection: `util.py`, `util_model.py`, `models.py`.
2. **Safety neuron discovery** — activation/gradient extraction and neuron selection: `main_safety_weights.py`, `safety_neuron_identifier.py`, `probe.py`.
3. **Fine‑tuning pipelines** — masked, clustered, full, and LoRA training scripts; orchestrated via `pipeline.py`.
4. **Inference & evaluation** — generate secure code and judge outputs: `main_inference.py`, `model_response_evaluator.py`, `evaluation_framework.py`.

## Quickstart
### 1) Install dependencies
```bash
conda env create -f neuro.yml
conda activate neuro
```
Notes:
- Hugging Face access is required for `CyberNative/Code_Vulnerability_Security_DPO` and the selected base models.
- GPUs are expected. Scripts default to `CUDA_VISIBLE_DEVICES=0,1,2,3` only when the variable is not already set.

### 2) Discover safety neurons
```bash
python safety_neuron_identifier.py --model_id <id> --language <lang> --top_k 50
```

### 3) Fine‑tune (choose one)
```bash
python fine_tune_without_clustering.py --model_id <id> --language <lang> --use_gradient_safety_neurons
python fine_tune_clustering.py --model_id <id> --language <lang> --use_random_neurons
python fine_tune_full_model.py --model_id <id> --language <lang>
python fine_tune_model_with_lora.py --model_id <id> --language <lang>
```

### 4) Generate secure code
```bash
python main_inference.py --model_id <id> --language <lang> --fine_tune_type <mode>
```

### 5) Evaluate safety with the judge
```bash
python model_response_evaluator.py --model_id <id> --language <lang> --fine_tune_type <mode> --judge_model <path-or-hf-id>
```


## Core scripts
| Component | Description | Example use |
| --- | --- | --- |
| `models.py` | Central list of HF model checkpoints | import |
| `util.py` | Dataset loading, comment stripping, GPU picker, helpers | import |
| `util_model.py` | Model/PEFT loaders, prompt builders, generation utilities | import |
| `pipeline.py` | End‑to‑end experiment: neuron finding → tuning → inference → eval | `python pipeline.py --config goodvibe_example.yaml` |
| `main_safety_weights.py` | Record activations, compute safety neuron weights, save artifacts | `python main_safety_weights.py --model_id 0 --language java` |
| `safety_neuron_identifier.py` | Gradient‑based safety neuron discovery (top‑k) | `python safety_neuron_identifier.py --model_id 5 --language c++ --top_k 50` |
| `fine_tune_without_clustering.py` | Masked fine‑tuning on safety neurons | `python fine_tune_without_clustering.py --model_id 2 --language c++ --use_gradient_safety_neurons` |
| `fine_tune_clustering.py` | Clustered safety‑neuron tuning (optionally random neurons) | `python fine_tune_clustering.py --model_id 0 --language c++ --use_random_neurons --random_fraction 0.1 --num_epochs 2` |
| `fine_tune_full_model.py` | Full secure‑guidance fine‑tune on DPO data | `python fine_tune_full_model.py --model_id 1 --language java --half first` |
| `fine_tune_model_with_lora.py` | LoRA fine‑tuning of secure code samples | `python fine_tune_model_with_lora.py --model_id 3 --language java --num_epochs 2 --lora_rank 2` |
| `main_inference.py` | Generate secure code or safety labels; saves `.npy` under `responses/` | `python main_inference.py --model_id 1 --language java --fine_tune_type fine_tune_cluster` |
| `model_response_evaluator.py` | Score generated code for safety with classifier | `python model_response_evaluator.py --model_id 0 --language python --fine_tune_type fine_tune_cluster --judge_model fine_tuned_models/qwen3-0.6b-judge` |
| `evaluation_framework.py` | Evaluate judge models on vulnerable/mixed sets; CSV/metrics output | `python evaluation_framework.py` |
| `probe.py` | Logistic regression probe used by safety‑neuron scripts | import |

## Flags and configuration
### Common flags
- `--model_id` (int): index into `models.py` list.
- `--language` (str): typically `c++`, `java`, `swift`, or `go`.
- `--fine_tune_type` (str): `fine_tune`, `full_fine_tune`, `lora`, `fine_tune_cluster`.
- `CUDA_VISIBLE_DEVICES`: optional environment variable for selecting GPUs.

### Fine‑tune type choices
- `""` (empty): use the base/pretrained model with no fine‑tune applied.
- `fine_tune`: safety‑neuron masked fine‑tuning (see `fine_tune_without_clustering.py` outputs).
- `full_fine_tune`: full‑parameter secure‑guidance fine‑tuning (see `fine_tune_full_model.py`).
- `lora`: LoRA adapter fine‑tuning (see `fine_tune_model_with_lora.py`).
- `fine_tune_cluster`: clustered safety‑neuron fine‑tuning (see `fine_tune_clustering.py`); combine with `--random_neurons` when desired.

### Script parameters (at a glance)
- `main_inference.py`: `--model_id`, `--language`, `--fine_tune_type`, `--random_neurons`.
- `main_safety_weights.py`: `--model_id`, `--language`, `--fine_tune_type`, `--num_responses`.
- `safety_neuron_identifier.py`: `--model_id`, `--language`, `--top_k`.
- `fine_tune_without_clustering.py`: `--model_id`, `--language`, `--use_gradient_safety_neurons`.
- `fine_tune_clustering.py`: `--model_id`, `--language`, `--safe_neuron_threshold`, `--use_random_neurons`, `--random_fraction`, `--random_seed`, `--use_gradient_importance`, `--min_silhouette`, `--num_epochs`.
- `fine_tune_full_model.py`: `--model_id`, `--language`, `--half` (`first`, `second`, `full`).
- `fine_tune_model_with_lora.py`: `--model_id`, `--language`, `--num_epochs`, `--learning_rate`, `--max_length`, `--lora_rank`, `--lora_alpha`, `--lora_dropout`, `--dataset_name`, `--output_root`.
- `model_response_evaluator.py`: `--model_id`, `--language`, `--fine_tune_type`, `--model_language`, `--use_classifier`, `--batch_size`, `--use_random`, `--judge_model`.
- `evaluation_framework.py`: `--model_id` (judge path), `--languages`, `--batch_size`, `--max_new_tokens`, `--max_samples`, `--half`.

## Pipeline
- Define experiments in a YAML or JSON file. See `goodvibe_example.yaml`.
- Ensure you have a trained or downloaded judge checkpoint and pass it as `judge_model`; otherwise safety evaluation will fail.
- Run:
  ```bash
  python pipeline.py --config goodvibe_example.yaml
  ```
  This triggers: safety neuron discovery → (clustered) fine‑tuning → optional full/LoRA fine‑tune → inference → evaluation, for each experiment entry.

## Outputs
- Fine‑tuned checkpoints: `fine_tuned_models/`, `fine_tuned_cluster_models/`.
- Safety neuron artifacts: `safety_neuron_identifiers/`.
- Generated code: `responses/<model>/generated_code_*/*.npy`.
- Code security evaluation: `responses/<model>/generated_code_*/*evaluation_results_<model>_*.json`.
- Evaluation results: per‑run JSON/CSV under result folders.

## Citation
TBD (paper citation will be added upon publication).
