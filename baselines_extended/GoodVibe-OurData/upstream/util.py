import pickle
import GPUtil
import numpy as np
from datasets import load_dataset
import torch
import pathlib
import re
from datasets import DatasetDict, Dataset
import json
import os
import GPUtil

def batchify(lst, batch_size):
    for i in range(0, len(lst), batch_size):
        yield lst[i:i + batch_size]      

def load_code_datasets(lang="c++", only_secure=False):
    all_texts = []
    all_labels = []
    prompts = []
    raw_ds = load_dataset("CyberNative/Code_Vulnerability_Security_DPO")["train"]
    if lang == "all":
        target_langs = {"c++", "java", "python", "c#", "swift", "go"}
        raw_ds = raw_ds.filter(lambda example: example.get("lang") in target_langs)
    else:
        raw_ds = raw_ds.filter(lambda example: example.get("lang") == lang)

    filtered_ds = filter_code_dataset_for_comments(raw_ds)
    prompts += filtered_ds["train"]["question"] * 2

    all_texts += filtered_ds["train"]["chosen"] + filtered_ds["train"]["rejected"]
    all_labels += [0] * len(filtered_ds["train"]["chosen"]) + [1] * len(filtered_ds["train"]["rejected"])

    if only_secure:
        filtered = [(t, l, p) for t, l, p in zip(all_texts, all_labels, prompts) if l == 0]
        if filtered:
            all_texts, all_labels, prompts = map(list, zip(*filtered))
        else:
            all_texts, all_labels, prompts = [], [], []
    return all_texts, all_labels, prompts

def filter_code_dataset_for_comments(ds):
    filtered_data = {
        "lang": [],
        "chosen": [],
        "rejected": [],
        "question": []
    }

    for lang, chosen, rejected, question in zip(ds['lang'], ds['chosen'], ds['rejected'], ds['question']):
        chosen_clean = remove_comments(chosen, lang)
        rejected_clean = remove_comments(rejected, lang)
        filtered_data['lang'].append(lang)
        filtered_data['chosen'].append(chosen_clean)
        filtered_data['rejected'].append(rejected_clean)
        filtered_data['question'].append(question)

    filtered_train_ds = Dataset.from_dict(filtered_data)
    return DatasetDict({"train": filtered_train_ds})

def shuffle(inputs, labels):
    indices = torch.randperm(inputs.size(0))

    shuffled_data = inputs[indices]
    shuffled_labels = labels[indices]
    return shuffled_data, shuffled_labels

def save_dict(data, dir):
    with open(dir, 'wb') as fp:
        pickle.dump(data, fp, protocol=pickle.HIGHEST_PROTOCOL)
    
def load_dict(dir):
    with open(dir, 'rb') as fp:
        data = pickle.load(fp)
    return data

def create_dir(dir):
    pathlib.Path(dir).mkdir(parents=True, exist_ok=True) 

def get_free_gpu():
    visible_devices = os.environ.get("CUDA_VISIBLE_DEVICES", "")
    visible_list = [int(i) for i in visible_devices.split(",") if i.strip().isdigit()]

    gpus = GPUtil.getGPUs()
    visible_gpus = [gpu for gpu in gpus if gpu.id in visible_list]

    if not visible_gpus:
        raise RuntimeError("No visible GPU available.")

    best_gpu = max(visible_gpus, key=lambda gpu: gpu.memoryFree)

    logical_index = visible_list.index(best_gpu.id)
    print(f"Selected physical GPU: {best_gpu.id} (logical ID: {logical_index})")
    return logical_index

def remove_comments(code, lang):
    """Remove comments from code, keeping indentation intact."""
    single_line = r'//.*?$|#.*?$'
    multi_line = r'/\*[\s\S]*?\*/|\'\'\'[\s\S]*?\'\'\'|\"\"\"[\s\S]*?\"\"\"'

    if lang.lower() in ['python', 'ruby']:
        single_line = r'#.*?$'
        multi_line = r'\'\'\'[\s\S]*?\'\'\'|\"\"\"[\s\S]*?\"\"\"'
    elif lang.lower() in ['c++', 'java', 'c#', 'kotlin', 'javascript', 'php', 'go', 'swift']:
        single_line = r'//.*?$'
        multi_line = r'/\*[\s\S]*?\*/'
    elif lang.lower() == 'fortran':
        single_line = r'!.*?$'
        multi_line = None

    if multi_line:
        code = re.sub(multi_line, '', code, flags=re.MULTILINE)

    code = re.sub(single_line, '', code, flags=re.MULTILINE)

    lines = code.splitlines()
    cleaned_lines = [line for line in lines if line.strip() != '']

    return '\n'.join(cleaned_lines)

def read_jsonl_file(filepath):
    data = []
    with open(filepath, 'r', encoding='utf-8') as file:
        for line in file:
            line = line.strip()
            if line:
                try:
                    entry = json.loads(line)
                    data.append(entry)
                except json.JSONDecodeError as e:
                    print(f"Skipping malformed line: {e}")
    return data

def read_json_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as file:
        try:
            data = json.load(file)
            return data
        except json.JSONDecodeError as e:
            print(f"Error reading JSON file: {e}")
            return None
