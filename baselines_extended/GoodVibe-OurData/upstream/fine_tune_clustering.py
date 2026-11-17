import os
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0,1,2,3")
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
import numpy as np
import torch
from torch import nn
from datasets import Dataset
from scipy.stats import zscore
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from torch.nn.utils import parametrize
from transformers import TrainingArguments
from trl import SFTTrainer
import argparse
import json
from jinja2 import TemplateError

import util
import util_model
from models import MODELS as models

MIN_SILHOUETTE = 0.05

def apply_chat_template(
    question: str,
    response: str,
    allow_system: bool = True,
) -> Dict[str, List[Dict[str, str]]]:
    system_prompt = (f"""Generate a SECURE code snippet based on the code task description that does not contain any vulnerabilities.
        Do not include any explanations or comments in your response.""")
    if allow_system:
        chat = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"User: {str(question)}"},
            {"role": "assistant", "content": str(response)},
        ]
    else:
        chat = [
            {
                "role": "user",
                "content": f"{system_prompt}\n\nUser: {str(question)}",
            },
            {"role": "assistant", "content": str(response)},
        ]
    return {"messages": chat}


class ClusteredRowParametrize(nn.Module):
    """
    Parametrization module tying neuron updates within each cluster.
    """

    def __init__(
        self,
        base_weight: torch.Tensor,
        row_idx: torch.Tensor,
        cluster_ids: torch.Tensor,
    ):
        super().__init__()
        self.register_buffer("base_weight", base_weight)
        self.register_buffer("row_idx", row_idx)
        self.register_buffer("cluster_ids", cluster_ids)

    def forward(self, cluster_updates: torch.Tensor) -> torch.Tensor:
        if self.row_idx.numel() == 0:
            return self.base_weight
        weight = self.base_weight.clone()
        updates = cluster_updates.index_select(0, self.cluster_ids)
        weight.index_add_(0, self.row_idx, updates)
        return weight


def gather_safety_neurons(weights_path: str, threshold: float) -> Dict[str, np.ndarray]:
    weights_sn = util.load_dict(weights_path)
    safety_neurons: Dict[str, np.ndarray] = {}
    for layer_name, weights in weights_sn.items():
        z_scores = zscore(weights)
        mask = (np.abs(z_scores) > threshold) & (weights > 0)
        safety_neurons[layer_name] = np.where(mask)[0]
    return safety_neurons


def cluster_safety_neurons(
    neuron_indices: Iterable[int],
    max_clusters: int,
    min_silhouette: float = MIN_SILHOUETTE,
    gradient_importance: Optional[np.ndarray] = None,
) -> Tuple[np.ndarray, float]:
    indices = np.asarray(list(neuron_indices), dtype=np.int32)
    if indices.size == 0:
        return np.empty(0, dtype=np.int64), float("nan")

    if gradient_importance is not None:
        feature_matrix = np.expand_dims(gradient_importance[indices], axis=0)
    else:
        return np.zeros(indices.size, dtype=np.int64), float("nan")

    if feature_matrix.ndim != 2:
        feature_matrix = np.expand_dims(feature_matrix, axis=0)

    neuron_features = feature_matrix.T
    if neuron_features.shape[0] == 1:
        return np.zeros(1, dtype=np.int64), float("nan")

    normalized = neuron_features

    unique_points = np.unique(normalized, axis=0)
    max_k = max(1, min(max_clusters, normalized.shape[0], unique_points.shape[0]))
    best_score = float("-inf")
    best_labels = np.zeros(normalized.shape[0], dtype=np.int64)
    best_k = 1

    for k in range(2, max_k + 1):
        try:
            model = KMeans(n_clusters=k, random_state=42, n_init="auto")
            labels = model.fit_predict(normalized)
            if len(np.unique(labels)) < 2:
                continue
            score = silhouette_score(normalized, labels)
        except Exception:
            continue
        if (
            score > best_score + 1e-4
            or (abs(score - best_score) <= 1e-4 and k < best_k)
        ):
            best_labels = labels
            best_score = score
            best_k = k

    if best_k == 1 or best_score < min_silhouette:
        return np.arange(normalized.shape[0], dtype=np.int64), float("nan")
    return best_labels.astype(np.int64), float(best_score)


def enable_clustered_training_for_linear(
    linear_module: nn.Linear,
    neuron_indices: Iterable[int],
    cluster_ids: Iterable[int],
) -> Tuple[int, int]:
    indices = list(int(i) for i in neuron_indices)
    if not indices:
        linear_module.weight.requires_grad_(False)
        if linear_module.bias is not None:
            linear_module.bias.requires_grad_(False)
        return 0, 0

    device = linear_module.weight.device
    dtype = linear_module.weight.dtype
    row_idx = torch.tensor(indices, device=device, dtype=torch.long)
    cluster_tensor = torch.tensor(
        list(int(c) for c in cluster_ids),
        device=device,
        dtype=torch.long,
    )
    num_clusters = (
        int(cluster_tensor.max().item()) + 1 if cluster_tensor.numel() > 0 else 0
    )

    if cluster_tensor.numel() != row_idx.numel():
        raise ValueError("Cluster assignment count does not match neuron indices.")

    if num_clusters == 0:
        linear_module.weight.requires_grad_(False)
        if linear_module.bias is not None:
            linear_module.bias.requires_grad_(False)
        return 0, 0

    base_weight = linear_module.weight.detach().clone().to(dtype)
    zero_updates = torch.zeros(
        (num_clusters, base_weight.shape[1]),
        dtype=dtype,
        device=device,
    )

    with torch.no_grad():
        linear_module.weight = nn.Parameter(zero_updates)

    parametrize.register_parametrization(
        linear_module,
        "weight",
        ClusteredRowParametrize(base_weight, row_idx, cluster_tensor),
        unsafe=True,
    )
    linear_module.parametrizations.weight.original.requires_grad_(True)

    if linear_module.bias is not None:
        linear_module.bias.requires_grad_(False)

    return zero_updates.numel(), num_clusters


def fold_and_remove_cluster_parametrizations(model: nn.Module) -> None:
    for module in model.modules():
        if isinstance(module, nn.Linear) and hasattr(module, "parametrizations"):
            if "weight" in module.parametrizations:
                try:
                    parametrize.remove_parametrizations(
                        module,
                        "weight",
                        leave_parametrized=True,
                    )
                except ValueError:
                    continue


def main(
    model_id=0,
    language="c++",
    safe_neuron_threshold=3.0,
    use_random_neurons: bool = False,
    random_fraction: Optional[float] = None,
    random_seed: int = 944,
    use_gradient_importance: bool = True,
    min_silhouette: float = MIN_SILHOUETTE,
    num_epochs: int = 2,
) -> None:
    project_root = Path(__file__).resolve().parent

    language_name = language
    if language_name == "c++":
        language_name = "cpp"
    model_id_index = max(0, min(model_id, len(models) - 1))
    model_name = models[model_id_index].split("/")[-1]
    print(f"Cluster fine-tuning {model_name}")
    is_gemma = "gemma" in model_name.lower()
    if use_random_neurons:
        print("Using random neurons for clustering.")

    code_texts, _, prompts = util.load_code_datasets(lang=language, only_secure=True)

    model, tokenizer = util_model.load_model(models[model_id_index], device="auto")
    num_mlp = util_model.count_mlp_module(model, model_name)
    print("Number of transformer blocks (and typically MLP layers):", num_mlp)

    base_ds = Dataset.from_dict({"question": prompts, "code": code_texts})
    base_ds = base_ds.shuffle(seed=42)
    base_ds = base_ds.map(lambda x: apply_chat_template(x["question"], x["code"], allow_system=not is_gemma))

    ds_split = base_ds.train_test_split(test_size=0.1, seed=42)
    train_dataset, eval_dataset = ds_split["train"], ds_split["test"]

    safety_neuron_path = project_root / "safety_neuron_identifiers" / f"{model_name}_{language_name}"

    weights_path = safety_neuron_path / f"weights_{model_name}.p"
    print(f"Loading safety weights from {weights_path}")
    gradient_importance: Optional[Dict[str, np.ndarray]] = None
    metadata_top_k: Optional[int] = None

    gradient_dir = project_root / f"safety_neuron_identifiers/{model_name}_{language_name}_sn_gradient"
    safety_neurons_path = gradient_dir / f"safety_neurons_{model_name}.p"
    if use_gradient_importance: 
        print(f"Loading safety neurons from {safety_neurons_path}")
        safety_neurons = util.load_dict(str(safety_neurons_path))
        gradient_path = gradient_dir / f"gradient_importance_{model_name}.p"
        if gradient_path.exists():
            print(f"Loading gradient importance from {gradient_path}")
            gradient_importance = util.load_dict(str(gradient_path))
        else:
            print("Gradient importance file missing; clustering will rely on activations only.")
        meta_path = gradient_dir / f"run_metadata_{model_name.split('/')[-1]}.p"
        if meta_path.exists():
            try:
                metadata_top_k = util.load_dict(str(meta_path)).get("top_k")
            except Exception:
                metadata_top_k = None
    else:
        print("Falling back to z-score selection.")
        safety_neurons = gather_safety_neurons(
            str(weights_path),
            safe_neuron_threshold,
        )

    for p in model.parameters():
        p.requires_grad = False

    rng = np.random.default_rng(random_seed)

    def select_neuron_indices(layer_key: str, linear_module: nn.Linear) -> List[int]:
        safety_indices = safety_neurons.get(layer_key, [])
        if not use_random_neurons:
            return safety_indices

        total_neurons = linear_module.weight.shape[0]
        target_count = len(safety_indices)
        if random_fraction is not None and random_fraction > 0:
            target_count = max(1, int(total_neurons * random_fraction))
        elif target_count == 0:
            target_count = max(1, int(total_neurons * 0.05))
        target_count = min(target_count, total_neurons)

        if target_count == total_neurons:
            return list(range(total_neurons))
        return rng.choice(total_neurons, size=target_count, replace=False).tolist()

    if model_name.lower().startswith("gemma"):
        layers = model.model.language_model.layers
    else:
        layers = model.model.layers
    effective_trainable = 0
    total_clusters = 0
    silhouette_scores = []
    for i, layer in enumerate(layers):
        attention_modules = [
            ("q_proj", layer.self_attn.q_proj),
            ("k_proj", layer.self_attn.k_proj),
            ("v_proj", layer.self_attn.v_proj),
            ("o_proj", layer.self_attn.o_proj),
        ]

        for proj_name, linear_module in attention_modules:
            layer_key = f"model.layers.{i}.self_attn.{proj_name}"
            if model_name.lower().startswith("gemma"):
                layer_key = f"model.language_model.layers.{i}.self_attn.{proj_name}"
            neuron_indices = select_neuron_indices(layer_key, linear_module)

            proj_gradient_importance = (
                gradient_importance.get(layer_key) if gradient_importance is not None else None
            )

            clusters, score = cluster_safety_neurons(
                neuron_indices,
                max_clusters=len(neuron_indices),
                gradient_importance=proj_gradient_importance,
            ) if proj_gradient_importance is not None else (
                np.zeros(len(neuron_indices), dtype=np.int64),
                float("nan"),
            )

            params, cluster_count = enable_clustered_training_for_linear(
                linear_module,
                neuron_indices,
                clusters,
            )

            effective_trainable += params
            total_clusters += cluster_count
            if not np.isnan(score):
                silhouette_scores.append(float(score))
            print(
                f"{layer_key}: neurons={len(neuron_indices)}, clusters={cluster_count}, silhouette={score:.4f}"
            )

        mlp_modules = [
            ("gate_proj", layer.mlp.gate_proj),
            ("up_proj", layer.mlp.up_proj),
        ]

        for proj_name, linear_module in mlp_modules:
            layer_key = f"model.layers.{i}.mlp.{proj_name}"
            if model_name.lower().startswith("gemma"):
                layer_key = f"model.language_model.layers.{i}.mlp.{proj_name}"
            neuron_indices = select_neuron_indices(layer_key, linear_module)
            proj_gradient_importance = (
                gradient_importance.get(layer_key) if gradient_importance is not None else None
            )

            clusters, score = cluster_safety_neurons(
                neuron_indices,
                max_clusters=len(neuron_indices),
                min_silhouette=min_silhouette,
                gradient_importance=proj_gradient_importance,
            ) if proj_gradient_importance is not None else (
                np.zeros(len(neuron_indices), dtype=np.int64),
                float("nan"),
            )

            params, cluster_count = enable_clustered_training_for_linear(
                linear_module,
                neuron_indices,
                clusters,
            )

            effective_trainable += params
            total_clusters += cluster_count
            if not np.isnan(score):
                silhouette_scores.append(float(score))
            print(
                f"{layer_key}: neurons={len(neuron_indices)}, clusters={cluster_count}, silhouette={score:.4f}"
            )

    num_params = sum(p.numel() for p in model.parameters())
    num_trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"Total parameters: {num_params:,}")
    print(f"Trainable parameters (optimizer view): {num_trainable:,}")
    print(f"Effective cluster parameters: {effective_trainable:,}")
    print(f"Total clusters across model: {total_clusters}")

    cluster_report = {
        "model total parameters": f"{num_params:,}",
        "cluster parameters": f"{effective_trainable:,}",
        "total clusters": total_clusters,
        "min_silhouette_config": float(min_silhouette),
    }
    if metadata_top_k is not None:
        cluster_report["top_k"] = metadata_top_k
    if silhouette_scores:
        cluster_report["silhouette_min"] = float(np.min(silhouette_scores))
    cluster_report["neuron_selection"] = "random" if use_random_neurons else "safety"
    if use_random_neurons:
        cluster_report["random_fraction"] = random_fraction
        cluster_report["random_seed"] = random_seed

    model.gradient_checkpointing_enable()
    model.enable_input_require_grads()

    def merge_system_into_first_user(messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        system_parts = [m["content"] for m in messages if m.get("role") == "system"]
        filtered = [m for m in messages if m.get("role") != "system"]
        if not system_parts:
            return filtered

        merged_system = "\n\n".join(system_parts).strip()
        if filtered:
            first = filtered[0].copy()
            first["content"] = f"{merged_system}\n\n{first.get('content', '')}"
            filtered = [first, *filtered[1:]]
        else:
            filtered = [{"role": "user", "content": merged_system}]
        return filtered

    def chat_formatting_func(example: dict) -> str:
        """
        Turns a messages-style dict into a string using the tokenizer's chat template.
        Assumes example['messages'] exists and is a list of role/content dicts.
        """
        messages = example["messages"]
        # Gemma processors don't expose `name_or_path`; rely on the model flag instead.
        normalized_messages = merge_system_into_first_user(messages) if is_gemma else messages
        try:
            result = tokenizer.apply_chat_template(normalized_messages, tokenize=False)
        except TemplateError as err:
            if "system role not supported" in str(err).lower():
                normalized_messages = merge_system_into_first_user(messages)
                result = tokenizer.apply_chat_template(normalized_messages, tokenize=False)
            else:
                raise
        return result

    mode_folder = "cluster_random" if use_random_neurons else "cluster"
    output_path = f"fine_tuned_cluster_models/{mode_folder}/train_model/{model_name}_{language_name}"
    folder_path = Path(output_path)
    folder_path.mkdir(parents=True, exist_ok=True)

    training_args = TrainingArguments(
        output_dir=output_path,
        num_train_epochs=num_epochs,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=4,
        learning_rate=1e-4,
        warmup_ratio=0.1,
        weight_decay=0.01,
        optim="adamw_torch",
        lr_scheduler_type="cosine",
        fp16=False,
        bf16=True,
        logging_dir=f"fine_tuned_cluster_models/{mode_folder}/logs",
        logging_steps=20,
        save_strategy="epoch",
        report_to="none",
        save_total_limit=2,
        eval_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="loss",
        greater_is_better=False,
        save_on_each_node=False,
        group_by_length=True,
        gradient_checkpointing=True,
        disable_tqdm=False,
    )

    trainer = SFTTrainer(
        model=model,
        processing_class=tokenizer,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        args=training_args,
        formatting_func=chat_formatting_func
    )
    trainer.model.config.use_cache = False
    train_start = time.time()
    train_result = trainer.train()
    train_elapsed = time.time() - train_start

    metrics = {
        "train_loss": train_result.training_loss,
        "best_eval_metric": trainer.state.best_metric,
        "best_model_checkpoint": trainer.state.best_model_checkpoint,
        "train_time_seconds": train_elapsed,
    }
    total_flos = getattr(trainer.state, "total_flos", None)
    if total_flos is not None and train_elapsed > 0:
        metrics["total_flos"] = int(total_flos)
        metrics["flops_per_second"] = float(total_flos / train_elapsed)
    eval_losses = [log.get("eval_loss") for log in trainer.state.log_history if "eval_loss" in log]
    if eval_losses:
        metrics["last_eval_loss"] = eval_losses[-1]
    cluster_report.update(metrics)

    cluster_report_path = f"{output_path}/cluster_report.json"
    with open(cluster_report_path, "w") as f:
        json.dump(cluster_report, f, indent=4)

    print(f"Saved cluster report to {cluster_report_path}")

    fold_and_remove_cluster_parametrizations(trainer.model)

    checkpoint_dir = f"{output_path}/final_checkpoint/{model_name}_{language_name}"
    trainer.model.save_pretrained(checkpoint_dir)
    tokenizer.save_pretrained(checkpoint_dir)

    del model
    del tokenizer
    del trainer
    torch.cuda.empty_cache()
    import gc
    gc.collect()


if __name__ == "__main__":
    os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0,1,2,3")
    parser = argparse.ArgumentParser()
    parser.add_argument("--model_id", type=int, default=0, help="Model ID to fine-tune.")
    parser.add_argument("--language", type=str, default="c++", help="Programming language.")
    parser.add_argument("--safe_neuron_threshold", type=float, default=3.0, help="Z-score threshold for safety neurons.")
    parser.add_argument(
        "--use_random_neurons",
        action="store_true",
        help="Select random neurons instead of precomputed safety neurons.",
    )
    parser.add_argument(
        "--random_fraction",
        type=float,
        default=None,
        help="Optional fraction of neurons per layer to tune when using random selection.",
    )
    parser.add_argument(
        "--use_gradient_importance",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Load gradient safety neurons when available.",
    )
    parser.add_argument("--min_silhouette", type=float, default=MIN_SILHOUETTE, help="Minimum silhouette score for multi-cluster grouping.")
    parser.add_argument("--num_epochs", type=int, default=2, help="Number of fine-tuning epochs.")
    parser.add_argument(
        "--random_seed",
        type=int,
        default=42,
        help="Seed for random neuron selection.",
    )

    args = parser.parse_args()

    main(
        args.model_id,
        args.language,
        args.safe_neuron_threshold,
        args.use_random_neurons,
        args.random_fraction,
        args.random_seed,
        args.use_gradient_importance,
        args.min_silhouette,
        args.num_epochs,
    )
