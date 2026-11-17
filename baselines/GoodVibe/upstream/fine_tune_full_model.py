import os
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0,1,2,3")
import argparse
import json
import time
from pathlib import Path
from typing import Dict, List

import torch
from datasets import load_dataset
from models import MODELS as models
from transformers import AutoModelForCausalLM, AutoTokenizer, DataCollatorForLanguageModeling, Trainer, TrainingArguments


def _filter_and_split(dataset, language: str, half: str):
    """Filter to a language and return the requested half."""
    ds_lang = dataset.filter(lambda ex: str(ex.get("lang", "")).lower() == language.lower())
    total_len = len(ds_lang)
    if total_len == 0:
        return ds_lang
    half_len = total_len // 2
    if half == "first":
        return ds_lang.select(range(half_len))
    if half == "second":
        return ds_lang.select(range(half_len, total_len))
    return ds_lang


def _build_supervised_dataset(raw_ds, tokenizer, max_length: int):
    """
    Build tokenized dataset where prompt = question, target = chosen secure code.
    Prompt tokens are masked from the loss (-100).
    """
    def preprocess(batch: Dict[str, List[str]]):
        input_ids, attention_masks, labels = [], [], []
        for question, chosen in zip(batch["question"], batch["chosen"]):
            prompt = f"Question:\n{question}\n\n answer:\n"
            full_text = prompt + chosen
            enc = tokenizer(
                full_text,
                truncation=True,
                max_length=max_length,
            )
            prompt_ids = tokenizer(
                prompt,
                truncation=True,
                max_length=max_length,
                add_special_tokens=False,
            )["input_ids"]

            lbl = enc["input_ids"].copy()
            mask_len = min(len(lbl), len(prompt_ids))
            lbl[:mask_len] = [-100] * mask_len

            input_ids.append(enc["input_ids"])
            attention_masks.append(enc["attention_mask"])
            labels.append(lbl)

        return {"input_ids": input_ids, "attention_mask": attention_masks, "labels": labels}

    columns_to_remove = [c for c in raw_ds.column_names if c not in ("question", "chosen")]
    tokenized = raw_ds.map(
        preprocess,
        batched=True,
        remove_columns=columns_to_remove,
        desc="Tokenizing",
    )
    return tokenized


def run_secure_guidance_fine_tuning(model_id: int, language: str, half: str = "first"):
    base_model_id = models[model_id]
    model_name = base_model_id.split("/")[1]
    language_norm = "cpp" if language == "c++" else language

    full_ds = load_dataset("CyberNative/Code_Vulnerability_Security_DPO", split="train")
    full_ds = full_ds.filter(lambda ex: str(ex.get("lang", "")).lower() in {"c++", "java", "python", "go", "swift"})
    lang_ds = _filter_and_split(full_ds, language, half=half)

    tokenizer = AutoTokenizer.from_pretrained(base_model_id, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    tokenized = _build_supervised_dataset(lang_ds, tokenizer, max_length=2048)
    split_ds = tokenized.train_test_split(test_size=0.2, seed=42)

    model = AutoModelForCausalLM.from_pretrained(
        base_model_id,
        trust_remote_code=True,
        device_map="auto",
        torch_dtype=torch.bfloat16 if torch.cuda.is_available() else None,
    )
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)

    data_collator = DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False)

    
    output_dir = Path("fine_tuned_models") / f"{model_name}_full_safety-neurons_{language_norm}"
    training_args = TrainingArguments(
        output_dir=str(output_dir),
        learning_rate=1e-4,
        num_train_epochs=2,
        per_device_train_batch_size=1,
        per_device_eval_batch_size=1,
        gradient_accumulation_steps=4,
        eval_strategy="epoch",
        save_strategy="epoch",
        save_total_limit=2,
        logging_steps=20,
        save_steps=20,
        eval_steps=10,
        report_to=[],
        bf16=torch.cuda.is_available(),
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
    )

    print(f"Start fine-tuning secure-guidance model {model_name}...")
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=split_ds["train"],
        eval_dataset=split_ds["test"],
        tokenizer=tokenizer,
        data_collator=data_collator,
    )

    train_start = time.time()
    train_result = trainer.train()
    train_elapsed = time.time() - train_start

    trainer.save_model(str(output_dir))
    tokenizer.save_pretrained(str(output_dir))
    metrics = {
        "train_time_seconds": train_elapsed,
        "train_loss": getattr(train_result, "training_loss", None),
        "best_model_checkpoint": getattr(trainer.state, "best_model_checkpoint", None),
        "total_parameters": total_params,
        "trainable_parameters": trainable_params,
    }
    total_flos = getattr(trainer.state, "total_flos", None)
    if total_flos is not None:
        metrics["total_flos"] = int(total_flos)
        if train_elapsed > 0:
            metrics["flops_per_second"] = float(total_flos / train_elapsed)
    report_path = Path(output_dir) / "training_report.json"
    with open(report_path, "w") as f:
        json.dump(metrics, f, indent=4)
    print(f"Saved training report to {report_path}")
    print(f"Saved secure-guidance model to {output_dir}")


def main():
    parser = argparse.ArgumentParser(description="Fine-tune secure guidance model on DPO data.")
    parser.add_argument("--model_id", type=int, default=0, help="Index into predefined model list.")
    parser.add_argument("--language", type=str, default="c++", choices=["c++", "java", "python"])
    parser.add_argument("--half", type=str, default="first", choices=["first", "second", "full"], help="Which half of the language-specific dataset to use.")
    args = parser.parse_args()
    run_secure_guidance_fine_tuning(args.model_id, args.language, half=args.half)


if __name__ == "__main__":
    main()
