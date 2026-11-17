import os
import gc
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0,1,2,3")
import torch
from torch.optim import AdamW
import util
import util_model
from models import MODELS as models
from pathlib import Path

from scipy.stats import zscore
import numpy as np
from datasets import load_dataset
from tqdm import tqdm
import argparse
import time
import json

def run_fine_tuning(model_id, language, use_gradient_safety_neurons=True):
    project_root = Path(__file__).resolve().parent
    model_name = models[model_id].split('/')[1]
    model = models[model_id]
    device = util.get_free_gpu()
    model, tokenizer = util_model.load_model(model, device)

    print("Freezing all parameters except safety neurons...")
    for param in model.parameters():
        param.requires_grad = False

    safe_neuron_threshold = 3
    language_name = language
    if language_name == "c++":
        language_name = "cpp"
    weight_extraction_path = project_root / "safety_neuron_identifiers" / f"{model_name}_{language_name}"

    gradient_dir = project_root / f"safety_neuron_identifiers/{model_name}_{language_name}_sn_gradient"
    gradient_safety_path = gradient_dir / f"safety_neurons_{model_name}.p"
    safety_neuron_source = "zscore"
    safety_neurons_all = {}

    if use_gradient_safety_neurons and gradient_safety_path.exists():
        print(f"Loading safety neurons from {gradient_safety_path}")
        safety_neurons_all = util.load_dict(str(gradient_safety_path))
        safety_neuron_source = "gradient"
    else:
        if use_gradient_safety_neurons:
            weights_all = util.load_dict(str(weight_extraction_path / f"weights_{model_name}.p"))
        for layer_name, weights in weights_all.items():
            z_scores = zscore(weights)
            candidate_neurons = np.where((np.abs(z_scores) > safe_neuron_threshold) & (weights > 0))[0]
            safety_neurons_all[layer_name] = candidate_neurons

    trainable_param_tensors = []
    mask_info = {}
    hook_handles = []
    total_effective_entries = sum(p.numel() for p in model.parameters())

    named_modules = dict(model.named_modules())
    total_effective_entries = 0

    for layer_name, neuron_indices in safety_neurons_all.items():
        if layer_name not in named_modules:
            print(f"Layer {layer_name} not found in model.named_modules(), skipping.")
            continue

        target_layer = named_modules[layer_name]

        if not hasattr(target_layer, "weight"):
                continue
        mask = torch.zeros_like(target_layer.weight, dtype=torch.float32, device="cpu")
        neuron_indices = np.array(neuron_indices, dtype=np.int64)
        neuron_indices = neuron_indices[neuron_indices < mask.shape[0]]
        if neuron_indices.size == 0:
            continue

        mask[torch.tensor(neuron_indices, device=mask.device), :] = 1.0
        target_layer.weight.requires_grad = True

        def make_grad_hook(mask_tensor):
            def grad_hook(grad):
                if grad is None:
                    return None

                m = mask_tensor.to(grad.device).to(grad.dtype)
                return grad * m
            return grad_hook

        handle = target_layer.weight.register_hook(make_grad_hook(mask))
        hook_handles.append(handle)

        trainable_param_tensors.append(target_layer.weight)

        effective = int(mask.sum().item())
        total_effective_entries += effective
        mask_info[layer_name] = {
            "mask_rows": mask.shape[0],
            "effective_entries": effective,
            "neuron_count": len(neuron_indices)
        }
        print(f"Applied gradient mask to {layer_name} — {len(neuron_indices)} safety neurons, {effective:,} effective entries.")

    if len(trainable_param_tensors) == 0:
        raise ValueError("No trainable parameter tensors found after mask application. Check name matching.")
    else:
        total_model_params = sum(p.numel() for p in model.parameters())
        print("\nEffective training summary (mask-based):")
        print(f"Total model parameters: {total_model_params:,}")
        print(f"Total effective trainable entries (masked): {total_effective_entries:,}")
        print(f"Effective trainable %: {100.0 * total_effective_entries / total_model_params:.6f}%")

    learning_rate = 1e-4
    weight_decay = 0.0
    optimizer = AdamW(trainable_param_tensors, lr=learning_rate, weight_decay=weight_decay)
    print(f"Optimizer initialized with {sum(p.numel() for p in trainable_param_tensors):,} parameter entries (these are full tensors; effective trainable entries printed above).")

    def make_chat_prompt_and_labels(prompt, response, tokenizer, max_length=1024):
        messages = [
            {"role": "system", "content": """Generate a SECURE code snippet based on the code task description that does not contain any vulnerabilities.
        Do not include any explanations or comments in your response."""},
            {"role": "user", "content": prompt},
            {"role": "assistant", "content": response},
        ]

        try:
            rendered = tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=False,
            )
        except Exception:
            rendered = f"<s>[SYS]{messages[0]['content']}[/SYS]\n[USER]{prompt}[/USER]\n[ASSIST]{response}[/ASSIST]"

        tokenized = tokenizer(
            rendered,
            truncation=True,
            padding="max_length",
            max_length=max_length,
            return_tensors="pt",
        )

        labels = tokenized.input_ids.clone()
        if tokenizer.pad_token_id is not None:
            labels[labels == tokenizer.pad_token_id] = -100

        answer_ids = tokenizer(response, add_special_tokens=False)["input_ids"]
        seq = labels[0].tolist()
        start = -1
        for i in range(len(seq) - len(answer_ids) + 1):
            if seq[i : i + len(answer_ids)] == answer_ids:
                start = i
                break

        if start != -1:
            labels[:, :start] = -100
        else:
            labels[:, : max(0, len(seq) - len(answer_ids))] = -100

        tokenized["labels"] = labels
        return tokenized


    ds = load_dataset("CyberNative/Code_Vulnerability_Security_DPO")
    ds = ds.filter(lambda x: x['lang'] == language)
    ds_split = ds['train'].train_test_split(test_size=0.2, seed=42)

    train_ds = ds_split['train']
    test_ds = ds_split['test']

    num_epochs = 2
    start_time = time.perf_counter()

    from transformers import get_cosine_schedule_with_warmup
    total_steps = len(train_ds) * num_epochs
    scheduler = get_cosine_schedule_with_warmup(
        optimizer,
        num_warmup_steps=int(0.05 * total_steps),
        num_training_steps=total_steps,
    )

    try:
        for epoch in range(num_epochs):
            print(f"\nEpoch {epoch+1}/{num_epochs}")
            
            for prompt, response in tqdm(zip(train_ds['question'], train_ds['chosen']), 
                                        total=len(train_ds), desc=f"Epoch {epoch+1}"):
                
                batch = make_chat_prompt_and_labels(prompt, response, tokenizer)
                batch = {k: v.to(device) for k, v in batch.items()}

                optimizer.zero_grad()
                outputs = model(**batch)
                loss = outputs.loss

                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                optimizer.step()
                scheduler.step()
                
                tqdm.write(f"Loss: {loss.item():.4f}")

        end_time = time.perf_counter()
        elapsed_time = end_time - start_time
        hours, rem = divmod(elapsed_time, 3600)
        minutes, seconds = divmod(rem, 60)

        suffix = ""
        model_dir = project_root / "fine_tuned_models" / f"{model_name}_{suffix}safety-neurons_{language_name}"
        model.save_pretrained(str(model_dir))
        tokenizer.save_pretrained(str(model_dir))
        print(f"Saved fine-tuned model at {model_dir}")

        total_params = sum(p.numel() for p in model.parameters())
        trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
        effective_percent = 100 * total_effective_entries / total_params
        apparent_percent = 100 * trainable_params / total_params

        print("\nParameter Statistics:")
        print(f"Total parameters: {total_params:,}")
        print(f"Trainable parameters (tensor rows): {trainable_params:,}")
        print(f"Total effective trainable entries (masked rows only): {total_effective_entries:,}")
        print(f"Apparent trainable % (full tensors): {apparent_percent:.4f}%")
        print(f"Effective trainable % (masked entries): {effective_percent:.6f}%")

        results = {
            "total_parameters": total_params,
            "trainable_parameters": trainable_params,
            "total_effective_trainable_entries": total_effective_entries,
            "apparent_percent_trainable": apparent_percent,
            "effective_percent_trainable": effective_percent,
            "elapsed_time_seconds": elapsed_time,
            "elapsed_time_hms": f"{int(hours)}h {int(minutes)}m {seconds:.1f}s",
            "learning_Rate": learning_rate,
            "num_epochs": num_epochs,
            "training_split_size": len(train_ds),
            "safety_neuron_source": safety_neuron_source,
        }

        results_file = model_dir / f"{model_name}_{language_name}_results.json"

        model_dir.mkdir(parents=True, exist_ok=True)
        with open(results_file, "w") as f:
            json.dump(results, f, indent=4)
    finally:
        for handle in hook_handles:
            handle.remove()
        del trainable_param_tensors
        del optimizer
        del scheduler
        del train_ds
        del test_ds
        del model
        del tokenizer
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        gc.collect()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model_id", type=int, default=2)
    parser.add_argument("--language", type=str, default="c++")
    parser.add_argument(
        "--use_gradient_safety_neurons",
        action="store_true",
        help="Load safety neurons from the gradient folder instead of recomputing via z-score.",
    )

    args = parser.parse_args()

    run_fine_tuning(
        args.model_id,
        args.language,
        args.use_gradient_safety_neurons,
    )
