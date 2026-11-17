import os
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0,1,2,3")
import torch
import numpy as np
import matplotlib.pyplot as plt
from tqdm import tqdm
from scipy.stats import zscore
import torch.nn as nn
import random as ran

import util
import util_model
import probe
import re
from pathlib import Path
import argparse
from models import MODELS as models

def activation_hook(layer_name, activations):
    def hook(module, input, output):
        act = output.max(dim=1)[0].detach().cpu().float().numpy()
        activations.setdefault(layer_name, []).append(act)
    return hook

def is_linear(module):
    return isinstance(module, nn.Linear)

def register_activation_hooks(model, target_layers, activations):
    handles = []
    for name, module in model.named_modules():
        if target_layers == "all":
            if is_linear(module):
                print(f"Registered activation hook for {name}")
                handle = module.register_forward_hook(activation_hook(name, activations))
                handles.append(handle)
        elif any(keyword in name.lower() for keyword in target_layers):
            print(f"Registered activation hook for {name}")
            handle = module.register_forward_hook(activation_hook(name, activations))
            handles.append(handle)
    return handles

def get_activation(model, prompts, tokenizer, activations, batch_size=8, num_responses=1):
    num_batches = (len(prompts) + batch_size - 1) // batch_size
    for batch_prompts in tqdm(util.batchify(prompts, batch_size), total=num_batches):
        input_tokens = tokenizer(batch_prompts, return_tensors="pt", padding=True, truncation=True)

        for _ in range(num_responses):
            with torch.no_grad():
                model(**input_tokens)
            
    for layer_name in activations:
        activations[layer_name] = np.concatenate(activations[layer_name], axis=0)

def run_experiment(
    model_id: int,
    language: str = "c++",
    fine_tune_type: str = "",
    safe_neuron_threshold: int = 3,
    num_responses: int = 3
):
    os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0,1,2,3")
    device = util.get_free_gpu()

    project_root = Path(__file__).resolve().parent
    perform_safety_prob = True
    model_name = models[model_id].split("/")[1]
    language_name = "cpp" if language == "c++" else language

    output_path = project_root / "safety_neuron_identifiers" / f"{model_name}_{language_name}"
    output_path.mkdir(parents=True, exist_ok=True)

    print(f"===== Tested Model: {model_name} =====")
    if fine_tune_type:
        model, tokenizer = util_model.load_fine_tuned_model(
            str(project_root / "fine_tuned_models" / f"{model_name}_{language_name}"), device
        )
    else:
        model, tokenizer = util_model.load_model(models[model_id], device)
    device = model.device

    code, dataset_labels, _ = util.load_code_datasets(language)

    system_prompt = """You are an AI that returns only a single number: 1 or 0.
Return 1 **only** if the given code snippet is unsafe or contains vulnerabilities.
Return 0 if the code is safe.
Respond with **only** the number 1 or 0 — no other text, symbols, or explanations.
"""

    prompts = util_model.construct_prompt(tokenizer, model_name, code, system_prompt=system_prompt)

    activations = {}
    hook_handles = register_activation_hooks(model, "all", activations)
    get_activation(model, prompts, tokenizer, activations, batch_size=1, num_responses=num_responses)
    folder_path = output_path
    folder_path.mkdir(exist_ok=True)
    print("saving activations...")
    util.save_dict(activations, str(output_path / f"neuron_activation_{model_name}.p"))

    for h in hook_handles:
        h.remove()

    torch.cuda.empty_cache()
    import gc
    gc.collect()

    model_labels = util_model.generate_output(model, tokenizer, prompts, batch_size=1, max_new_tokens=10)
    cleaned_model_labels = []

    for output in model_labels:
        output_str = str(output).lower()
        
        digits = re.findall(r"[01]", output_str)
        if digits:
            label = int(digits[-1])
        else:
            if "unsafe" in output_str:
                label = 1
            elif re.search(r"\bsafe\b", output_str):
                label = 0
            else:
                label = ran.randint(0, 1)
        
        cleaned_model_labels.append(label)

    model_labels = cleaned_model_labels
    
    labels = dataset_labels.copy()
        
    matching_indices = [i for i, (m, l) in enumerate(zip(model_labels, dataset_labels)) if str(m) == str(l)]
    
    print(f"Identified labels: {labels}")
    util.save_dict(labels, str(output_path / f"model_labels_{model_name}.p"))
    util.save_dict(matching_indices, str(output_path / f"matching_indices_{model_name}.p"))
    
    print(f"Saved model labels to {output_path}/model_labels_{model_name}.p")
    safety_neurons_all = {}
    extraction_dir = project_root / "safety_neuron_identifiers" / model_name
    util.create_dir(str(extraction_dir))

    if perform_safety_prob:
        weights_all = {}
        safety_neurons_all = {}

        correct_indices = matching_indices
        filtered_labels = [labels[i] for i in correct_indices]
        labels_tensor = torch.tensor(filtered_labels, dtype=torch.float32).unsqueeze(1).to(device)

        print(f"Using {len(correct_indices)} correctly predicted samples out of {len(labels)} total.")

        for layer_name, act_matrix in activations.items():
            print(f"Processing layer: {layer_name}")

            filtered_activations = act_matrix[correct_indices, :]
            activations_tensor = torch.tensor(filtered_activations, dtype=torch.float32).to(device)

            print(f"Filtered activations tensor shape: {activations_tensor.shape}")
            print(f"Labels tensor shape: {labels_tensor.shape}")

            weights = probe.safety_probe(activations_tensor, labels_tensor, device)

            z_scores = zscore(weights)
            weights_all[layer_name] = weights

            candidate_neurons = np.where(
                (np.abs(z_scores) > safe_neuron_threshold) & (weights > 0)
            )[0]

            safety_neurons_all[layer_name] = candidate_neurons

            plt.plot(weights)
            plt.title(f"Weights for {layer_name}")
            plt.savefig(extraction_dir / f"{layer_name}.png")
            plt.clf()

        util.save_dict(weights_all, str(output_path / f"weights_{model_name}.p"))
        print(f"Saved filtered weights to {output_path}/weights_{model_name}.p")

    del model
    del tokenizer
    del activations
    gc.collect()
    torch.cuda.empty_cache()
    print(f"Finished {model_name}.\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--model_id", type=int, default=0)
    parser.add_argument("--language", type=str, default="c++")
    parser.add_argument("--fine_tune_type", type=str, default="")

    args = parser.parse_args()

    run_experiment(
        model_id=args.model_id,
        language=args.language,
        fine_tune_type=args.fine_tune_type)
