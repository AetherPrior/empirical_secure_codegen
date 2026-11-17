import argparse
import json
from pathlib import Path

from safety_neuron_identifier import find_safety_neurons
from fine_tune_without_clustering import run_fine_tuning
from fine_tune_full_model import run_secure_guidance_fine_tuning
from fine_tune_model_with_lora import run_lora_fine_tuning
from fine_tune_clustering import main as run_fine_tune_cluster_tuning
from main_inference import run_inference
from model_response_evaluator import run_evaluation


DEFAULT_EXPERIMENTS = [
    {
        "model_id": 0,
        "language": "c++",
        "fine_tune_type": "fine_tune_cluster",
        "use_random": False,
        "top_k": 50,
        "min_silhouette": 0.05,
        "num_epochs": 2,
    },
]


def load_experiments(config_path):
    if config_path is None:
        return DEFAULT_EXPERIMENTS

    path = Path(config_path)
    with open(path, "r", encoding="utf-8") as f:
        if path.suffix.lower() == ".json":
            payload = json.load(f)
        else:
            try:
                import yaml
            except ImportError as exc:
                raise ImportError("Install PyYAML or use a .json config file.") from exc
            payload = yaml.safe_load(f)

    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("experiments"), list):
        return payload["experiments"]
    raise ValueError("Pipeline config must be a list or a mapping with an 'experiments' list.")


def run_experiment(exp):
    if "model_id" not in exp or "language" not in exp:
        raise ValueError(f"Experiment is missing required keys: {exp}")

    fine_tune_type = exp.get("fine_tune_type", "")
    use_random = exp.get("use_random", False)

    if fine_tune_type == "fine_tune_cluster":
        find_safety_neurons(
            model_id=exp["model_id"],
            language=exp["language"],
            top_k=exp.get("top_k", 50),
        )
        run_fine_tune_cluster_tuning(
            model_id=exp["model_id"],
            language=exp["language"],
            safe_neuron_threshold=exp.get("safe_neuron_threshold", 3.0),
            use_random_neurons=use_random,
            random_fraction=exp.get("random_fraction"),
            random_seed=exp.get("random_seed", 944),
            use_gradient_importance=exp.get("use_gradient_importance", True),
            min_silhouette=exp.get("min_silhouette", 0.05),
            num_epochs=exp.get("num_epochs", 2),
        )
    elif fine_tune_type == "full_fine_tune":
        run_secure_guidance_fine_tuning(
            exp["model_id"],
            exp["language"],
            half=exp.get("half", "first"),
        )
    elif fine_tune_type == "fine_tune":
        run_fine_tuning(
            exp["model_id"],
            exp["language"],
            use_gradient_safety_neurons=exp.get("use_gradient_safety_neurons", True),
        )
    elif fine_tune_type == "lora":
        run_lora_fine_tuning(
            exp["model_id"],
            exp["language"],
            num_epochs=exp.get("num_epochs", 2),
            learning_rate=exp.get("learning_rate", 2e-4),
            max_length=exp.get("max_length", 512),
            lora_rank=exp.get("lora_rank", 8),
            lora_alpha=exp.get("lora_alpha", 4),
            lora_dropout=exp.get("lora_dropout", 0.05),
            dataset_name=exp.get("dataset_name", "CyberNative/Code_Vulnerability_Security_DPO"),
            output_root=exp.get("output_root", "fine_tuned_models"),
        )
    elif fine_tune_type:
        raise ValueError(f"Unknown fine_tune_type: {fine_tune_type}")

    run_inference(
        exp["model_id"],
        exp["language"],
        fine_tune_type,
        random_neurons=use_random,
    )
    run_evaluation(
        exp["model_id"],
        exp["language"],
        fine_tune_type,
        model_language=exp.get("model_language", ""),
        use_classifier=exp.get("use_classifier", True),
        batch_size=exp.get("batch_size", 8),
        use_random=use_random,
        judge_model=exp.get("judge_model", "fine_tuned_models/qwen3-0.6b-judge"),
    )


def main():
    parser = argparse.ArgumentParser(description="Run GoodVibe experiments from a YAML or JSON config.")
    parser.add_argument("--config", type=str, default=None, help="Path to a YAML/JSON config with an experiments list.")
    args = parser.parse_args()

    experiments = load_experiments(args.config)
    num_failures = 0
    failures = []

    for exp in experiments:
        print(f"\n=== Starting experiment: {exp} ===\n")
        try:
            run_experiment(exp)
        except Exception as exc:
            num_failures += 1
            failures.append({"experiment": exp, "error": str(exc)})
            print(f"Experiment failed: {exp}\nError: {exc}")

    print(f"\n=== Finished all experiments with {num_failures} failures ===\n")
    if failures:
        print(json.dumps(failures, indent=2))


if __name__ == "__main__":
    main()
