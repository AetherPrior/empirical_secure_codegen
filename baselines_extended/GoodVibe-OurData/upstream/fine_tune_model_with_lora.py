import os
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0,1,2,3")
import argparse
import time
import json
import torch
from transformers import Trainer, TrainingArguments, DataCollatorForLanguageModeling
from peft import LoraConfig, get_peft_model
from datasets import Dataset
from models import MODELS

import util
import util_model

def run_lora_fine_tuning(
    model_id: int,
    language: str = "c++",
    num_epochs: int = 2,
    learning_rate: float = 1e-4,
    max_length: int = 512,
    lora_rank: int = 2,
    lora_alpha: int = 4,
    lora_dropout: float = 0.1,
    dataset_name: str = "CyberNative/Code_Vulnerability_Security_DPO",
    output_root: str = "fine_tuned_models",
):
    if model_id < 0 or model_id >= len(MODELS):
        raise ValueError(f"model_id must be between 0 and {len(MODELS) - 1}")

    lang_raw = (language or "").lower()
    lang_out = "cpp" if lang_raw in {"c++", "cpp"} else lang_raw
    model_name = MODELS[model_id]
    short_name = model_name.split("/")[-1]

    requested_device = None
    if torch.cuda.is_available():
        device_idx = util.get_free_gpu()
        requested_device = torch.device(f"cuda:{device_idx}")
    device = requested_device or torch.device("cpu")

    model, tokenizer = util_model.load_model(model_name, device)
    text_tokenizer = getattr(tokenizer, "tokenizer", tokenizer)
    device = next(model.parameters()).device
    if hasattr(text_tokenizer, "pad_token") and text_tokenizer.pad_token is None:
        text_tokenizer.pad_token = text_tokenizer.eos_token
    if hasattr(text_tokenizer, "padding_side"):
        text_tokenizer.padding_side = "left"
    lora_cfg = LoraConfig(
        r=lora_rank,
        lora_alpha=lora_alpha,
        target_modules=[
            "q_proj",
            "k_proj",
            "v_proj",
            "o_proj",
            "up_proj",
            "gate_proj",
        ],
        lora_dropout=lora_dropout,
        bias="none",
        task_type="CAUSAL_LM",
    )
    model = get_peft_model(model, lora_cfg)
    model.config.use_cache = False
    model.train()
    print("\nTrainable parameters (LoRA):")
    model.print_trainable_parameters()

    code_texts, _, prompts = util.load_code_datasets(lang=lang_raw, only_secure=True)
    if not code_texts:
        raise ValueError(f"No secure code samples found for language '{language}'.")

    def build_text(prompt: str, response: str) -> str:
        if hasattr(text_tokenizer, "apply_chat_template"):
            messages = [
                {"role": "user", "content": prompt},
                {"role": "assistant", "content": response},
            ]
            return text_tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=False
            )
        return f"{(prompt or '').strip()}\n\n{(response or '').strip()}"

    texts = [build_text(p, c) for p, c in zip(prompts, code_texts)]
    ds = Dataset.from_dict({"text": texts})
    ds_split = ds.train_test_split(test_size=0.2, seed=42)
    train_ds, eval_ds = ds_split["train"], ds_split["test"]

    def tokenize_fn(example):
        return text_tokenizer(
            text=example["text"],
            truncation=True,
            max_length=max_length,
        )

    train_ds = train_ds.map(tokenize_fn, batched=True, remove_columns=["text"])
    eval_ds = eval_ds.map(tokenize_fn, batched=True, remove_columns=["text"])

    data_collator = DataCollatorForLanguageModeling(tokenizer=text_tokenizer, mlm=False)

    training_args = TrainingArguments(
        output_dir=os.path.join(output_root, f"{short_name}_lora_{lang_out}"),
        num_train_epochs=num_epochs,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=4,
        learning_rate=learning_rate,
        weight_decay=0.01,
        logging_steps=20,
        save_strategy="epoch",
        report_to="none",
        fp16=False,
        bf16=True,
    )

    model.config.use_cache = False
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
        data_collator=data_collator,
    )

    train_start = time.perf_counter()
    print("\nStarting LoRA fine-tuning …")
    trainer.train()
    elapsed = time.perf_counter() - train_start
    hours, rem = divmod(elapsed, 3600)
    minutes, seconds = divmod(rem, 60)

    save_dir = training_args.output_dir
    trainer.save_model(save_dir)
    tokenizer.save_pretrained(save_dir)

    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    percent_trainable = 100 * trainable_params / total_params
    total_flos = getattr(trainer.state, "total_flos", None)
    flops_per_second = (total_flos / elapsed) if total_flos and elapsed > 0 else None
    results = {
        "total_parameters": total_params,
        "trainable_parameters": trainable_params,
        "percent_trainable": percent_trainable,
        "elapsed_time_seconds": elapsed,
        "elapsed_time_hms": f"{int(hours)}h {int(minutes)}m {seconds:.1f}s",
    }
    if total_flos:
        results.update(
            {
                "total_flos": int(total_flos),
                "flops_per_second": flops_per_second,
            }
        )
    with open(os.path.join(save_dir, f"{short_name}_{lang_out}_results.json"), "w") as f:
        json.dump(results, f, indent=4)

    print(f"Saved fine-tuned model at {save_dir}")
    print(f"\nFine-tuning completed in {int(hours)}h {int(minutes)}m {seconds:.1f}s.")
    print("\nParameter Statistics:")
    print(f"Total parameters: {total_params:,}")
    print(f"Trainable parameters: {trainable_params:,}")
    print(f"Percentage of trainable parameters: {percent_trainable:.4f}%")

    return save_dir

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LoRA fine-tune for code generation.")
    parser.add_argument("--model_id", type=int, default=0, help="Index into MODELS list.")
    parser.add_argument("--language", type=str, default="java", help="Language to filter the dataset.")
    parser.add_argument("--num_epochs", type=int, default=2)
    parser.add_argument("--learning_rate", type=float, default=2e-4)
    parser.add_argument("--max_length", type=int, default=512)
    parser.add_argument("--warmup_steps", type=int, default=200)
    parser.add_argument("--lora_rank", type=int, default=8)
    parser.add_argument("--lora_alpha", type=int, default=4)
    parser.add_argument("--lora_dropout", type=float, default=0.05)
    parser.add_argument(
        "--dataset_name",
        type=str,
        default="CyberNative/Code_Vulnerability_Security_DPO",
        help="HF dataset to use for fine-tuning.",
    )
    parser.add_argument("--output_root", type=str, default="fine_tuned_models")

    cli_args = parser.parse_args()
    run_lora_fine_tuning(
        model_id=cli_args.model_id,
        language=cli_args.language,
        num_epochs=cli_args.num_epochs,
        learning_rate=cli_args.learning_rate,
        max_length=cli_args.max_length,
        lora_rank=cli_args.lora_rank,
        lora_alpha=cli_args.lora_alpha,
        lora_dropout=cli_args.lora_dropout,
        dataset_name=cli_args.dataset_name,
        output_root=cli_args.output_root,
    )
