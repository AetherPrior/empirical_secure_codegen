import os
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0,1,2,3")
import argparse
import gc
import torch
import torch.nn as nn
from transformers import AutoModelForCausalLM, AutoTokenizer
from collections import defaultdict
import numpy as np
from tqdm import tqdm
from pathlib import Path
import util
from models import MODELS as models

def register_gradient_hooks(model):
    grad_storage = defaultdict(list)

    for name, module in model.named_modules():
        if isinstance(module, nn.Linear):
            
            def save_grad(module, grad_input, grad_output, name=name):
                grad = grad_output[0].detach().cpu()
                grad = grad.view(-1, grad.shape[-1])
                grad_storage[name].append(grad.abs().mean(dim=0))
            
            module.register_full_backward_hook(save_grad)

    return grad_storage


def extract_binary_logits(logits):
    logits_last = logits[:, -1, :]
    logit_0 = logits_last[:, ord("0")]
    logit_1 = logits_last[:, ord("1")]
    return torch.stack([logit_0, logit_1], dim=-1)


def classification_loss(binary_logits, target_label):
    loss_fn = nn.CrossEntropyLoss()
    return loss_fn(binary_logits, target_label)


def find_safety_neurons(
    model_id,
    top_k=50,
    language="c++",
):
    model_name = models[model_id]
    device = util.get_free_gpu()
    code, dataset_labels, _ = util.load_code_datasets(language)

    print(f"Loading model {model_name} …")
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        device_map="auto",
    )
    tokenizer = AutoTokenizer.from_pretrained(model_name)

    model.train()
    
    grad_storage = register_gradient_hooks(model)

    selected_indices = []

    for i in tqdm(range(len(code)), desc="Processing samples"):
        system_prompt = f"""You are an AI that returns only a single number: 1 or 0.
    Return 1 **only** if the given code snippet is unsafe or contains vulnerabilities.
    Return 0 if the code is safe.
    Respond with **only** the number 1 or 0 — no other text, symbols, or explanations.
    {code[i]}
    """
        inputs = tokenizer(system_prompt, return_tensors="pt").to(model.device)

        outputs = model(**inputs)
        binary_logits = extract_binary_logits(outputs.logits)
        selected_indices.append(i)

        target = torch.tensor([dataset_labels[i]], dtype=torch.long, device=model.device)

        loss = classification_loss(binary_logits, target)

        model.zero_grad()
        loss.backward()
    print("Aggregating neuron gradient importance …")

    neuron_importance = {}

    for layer_name, grads in grad_storage.items():
        if len(grads) == 0:
            continue

        all_grads = torch.stack(grads, dim=0)
        mean_grad = all_grads.mean(dim=0)
        neuron_importance[layer_name] = mean_grad.numpy()

    safety_neurons = {}

    for layer_name, values in neuron_importance.items():
        hidden_size = len(values)
        k = min(top_k, hidden_size)
        top_indices = np.argsort(values)[-k:]
        safety_neurons[layer_name] = top_indices.tolist()

    project_root = Path(__file__).resolve().parent
    safety_id_root = project_root / "safety_neuron_identifiers"
    language_name = "cpp" if language.lower() == "c++" else language.lower()
    short_model_name = model_name.split("/")[-1]
    output_path = safety_id_root / f"{short_model_name}_{language_name}_sn_gradient"
    output_path.mkdir(parents=True, exist_ok=True)

    importance_path = output_path / f"gradient_importance_{short_model_name}.p"
    safety_path = output_path / f"safety_neurons_{short_model_name}.p"

    util.save_dict(neuron_importance, str(importance_path))
    util.save_dict(safety_neurons, str(safety_path))

    print(f"Saved gradient importance to {importance_path}")
    print(f"Saved safety neuron indices to {safety_path}")

    metadata = {
        "top_k": top_k,
        "language": language,
        "num_samples_used": len(selected_indices),
        "selected_indices": selected_indices,
    }
    util.save_dict(metadata, str(output_path / f"run_metadata_{short_model_name}.p"))
    print(f"Saved run metadata to {output_path / f'run_metadata_{short_model_name}.p'}")

    del model
    del tokenizer
    torch.cuda.empty_cache()
    gc.collect()

    return safety_neurons, neuron_importance

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Identify safety-relevant neurons with gradient attribution.")
    parser.add_argument("--model_id", type=int, default=0, help="Index into MODELS.")
    parser.add_argument("--language", type=str, default="c++", help="Dataset language to use.")
    parser.add_argument("--top_k", type=int, default=50, help="Number of top neurons per linear layer.")
    args = parser.parse_args()

    find_safety_neurons(
        model_id=args.model_id,
        top_k=args.top_k,
        language=args.language,
    )
