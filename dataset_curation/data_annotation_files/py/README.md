# Data annotation — Python test-case audit

Scripts and rubrics for reviewing security benchmark rows with an LLM, then comparing original vs rewritten `test_code` and `ground_truth_solution`.

## Quick start

Create a .env and set to  

```
OPENAI_API_KEY='sk-123456'
OPENAI_BASE_URL=https://us.api.openai.com/v1
```

And run:  

```bash
cd data_annotation_files
set -a && source .env && set +a   

python3 prompt_parquet_py.py --input-parquet anonymous/python_cwe_GRPO --cwes CWE-770 --max-rows 20
```

### Parquet / Hugging Face (`prompt_parquet_py.py`)

Same audit as `prompt_py.py`, but reads VeRL/GRPO **parquet** (no human annotations). Writes a plain `*_rewrites.csv` with original + rewritten code. Input: local path or HF id (`org/repo` downloads `{repo}.parquet`; e.g. [`anonymous/python_cwe_GRPO`](https://huggingface.co/datasets/anonymous/python_cwe_GRPO)).
## What you need to edit

| Item | Who | Location |
|------|-----|----------|
| CWE rubric | Assigned owner | `rubrics_py/<number>.txt` (e.g. `78.txt` for CWE-78) |

Only change rubrics for **your** CWEs. Open a PR with rubric updates when done. PLEASE ONLY REWRITE 20-25 rows.

## CWE assignments

| Owner | CWEs |
|-------|------|
| Annotator A | 200, 295, 915, 918 |
| Annotator B | 22, 78, 79, 89 |
| Annotator E | 352, 502, 601 |
| Annotator C | 770, 862, 863 |
| Annotator D | 95, 611, 1333 |


## Review workflow

1. Run the script for your CWE(s). Ideally, annotate 20 prompts per CWE. Please do not run it on the entire dataset.
2. Open the `*_rewrites.csv` and check whether rewrites look better than the originals. Use a [csv viewer/editor extension](https://marketplace.cursorapi.com/items/?itemName=ReprEng.csv) to be able to see it on vscode. 
3. Iterate on your rubric in `rubrics_py/` if the model misses systematic issues.
4. Submit a PR with rubric changes - and provide your labels post rewrite - and a table of # of prompts rewritten/rejected.

## Repo layout

```
data_annotation_files/
├── prompt_py.py              # main audit script (CSV → compare CSV)
├── prompt_parquet_py.py      # parquet / HF → plain rewrites CSV
├── const_cwe_id_desc.py      # CWE descriptions for prompts
├── utils_py.py               # test_code AST validation
├── rubrics_py/               # per-CWE rewrite rubrics (78.txt, …)
├── data_annotation-python-original.csv
└── .env                      # API keys (not committed)
```
