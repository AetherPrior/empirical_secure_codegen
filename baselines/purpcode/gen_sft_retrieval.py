"""PurpCode-32B-SFT with our retrieval: generate from the saved prompts of the Qwen3-8B retrieval run
(baselines_extended/Our-Retrieval/outputs_no_impl/repaired/<bench>/prepared_cases.json), with the same sampling
settings as the other PurpCode runs. Scoring is done afterwards by benchmarks/run_plain_vllm.py --operation evaluate."""
import argparse, json, sys
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'benchmarks'))
import run_plain_vllm as R  # noqa: E402

p = argparse.ArgumentParser()
p.add_argument('--model', required=True)
p.add_argument('--benchmark', required=True)
p.add_argument('--out', type=Path, required=True)
p.add_argument('--cases', type=Path, help='prepared cases (default: the repaired no-implementation retrieval prompts of the benchmark)')
p.add_argument('--seeds', type=int, nargs='+', default=[42, 43, 44])
a = p.parse_args()
cases = json.load(open(a.cases or REPO / f'baselines_extended/Our-Retrieval/outputs_no_impl/repaired/{a.benchmark}/prepared_cases.json'))
a.out.mkdir(parents=True, exist_ok=True)
args = argparse.Namespace(model=a.model, tp=1, dtype='bfloat16', max_model_len=24576, concurrency=64, gpu_memory_utilization=0.9,
                          trust_remote_code=False, temperature=0.6, top_p=0.95, max_tokens=16384, enable_thinking=None,
                          seeds=a.seeds, out=a.out)
R.generate(args, [dict(id=c['id'], messages=c['messages']) for c in cases])
