"""SVEN (prefix-tuned Qwen3-8B, secure control) generation with thinking on, same sampling as the vLLM runs (temperature 0.6, top-p 0.95,
16,384 new tokens). vLLM cannot run a learned per-layer key/value prefix, so this is a small continuous-batching loop on a slot cache:
each slot holds [10 prefix positions | prompt | generated tokens]; finished slots are refilled from the queue. Resumable.
Usage: sven_generate.py --prefix-dir <checkpoint-last> --cases <cases.json> --out <dir> [--seeds 42] [--slots 16] [--limit N]"""
import argparse, json, os, sys, time
from pathlib import Path
import torch
HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
torch.backends.cuda.enable_cudnn_sdp(False)
from transformers import AutoTokenizer, DynamicCache  # noqa: E402
from transformers.cache_utils import DynamicLayer  # noqa: E402
from safecoder.sven_models import Qwen3Prefix  # noqa: E402

p = argparse.ArgumentParser()
p.add_argument('--prefix-dir', type=Path, required=True); p.add_argument('--cases', type=Path, required=True); p.add_argument('--out', type=Path, required=True)
p.add_argument('--base', default='Qwen/Qwen3-8B'); p.add_argument('--seeds', type=int, nargs='+', default=[42]); p.add_argument('--slots', type=int, default=16)
p.add_argument('--max-new', type=int, default=16384); p.add_argument('--temperature', type=float, default=0.6); p.add_argument('--top-p', type=float, default=0.95)
p.add_argument('--limit', type=int); p.add_argument('--max-prompt', type=int, default=8192)
a = p.parse_args()
a.out.mkdir(parents=True, exist_ok=True)
NP = 10  # prefix length of SVEN

tok = AutoTokenizer.from_pretrained(a.base)
model = Qwen3Prefix.from_pretrained(a.base, torch_dtype=torch.bfloat16, device_map={'': 0})
model.prefix_params.load_state_dict(torch.load(a.prefix_dir / 'pytorch_model.bin'))
model.eval()
cfg = model.config; L, KVH = cfg.num_hidden_layers, cfg.num_key_value_heads; HD = getattr(cfg, 'head_dim', None) or cfg.hidden_size // cfg.num_attention_heads
STOP = {tok.convert_tokens_to_ids('<|im_end|>'), tok.convert_tokens_to_ids('<|endoftext|>')}

cases = json.loads(a.cases.read_text())[:a.limit]
path = a.out / 'generations.jsonl'
done = set()
if path.exists():
    for line in path.open():
        try: r = json.loads(line); done.add((r['case_id'], r['seed']))
        except json.JSONDecodeError: pass
todo = [(c, s) for s in a.seeds for c in cases if (c['id'], s) not in done]
prompts = {c['id']: tok.apply_chat_template(c['messages'], tokenize=True, add_generation_prompt=True, enable_thinking=True) for c, _ in todo}
prompts = {k: (v['input_ids'] if hasattr(v, 'keys') else v) for k, v in prompts.items()}
todo = [(c, s) for c, s in todo if len(prompts[c['id']]) <= a.max_prompt]
queue = sorted(todo, key=lambda t: len(prompts[t[0]['id']]))[::-1]   # longest first, so slot memory is sized once
print(f'{len(todo)} generations to do ({len(done)} done)', flush=True)
if not todo: sys.exit(0)

cap = NP + max(len(v) for v in prompts.values()) + a.max_new + 1
B = a.slots
K = [torch.zeros(B, KVH, cap, HD, dtype=torch.bfloat16, device='cuda') for _ in range(L)]
V = [torch.zeros(B, KVH, cap, HD, dtype=torch.bfloat16, device='cuda') for _ in range(L)]
lens = torch.zeros(B, dtype=torch.long, device='cuda')   # valid cache columns per slot (prefix + prompt + generated)


class SlotLayer(DynamicLayer):
    """Writes the new key/value of each slot at its own column and exposes the columns up to the longest active slot."""
    def __init__(self, i, active_max, write_cols=None):
        super().__init__(); self.i, self.active_max, self.write_cols = i, active_max, write_cols
        self.is_initialized = True; self.dtype = torch.bfloat16; self.device = torch.device('cuda')
    def update(self, k, v, cache_kwargs=None):
        if self.write_cols is None:   # prefill of one slot handled outside
            raise RuntimeError
        rows = torch.arange(k.shape[0], device=k.device)
        K[self.i][rows, :, self.write_cols] = k[:, :, 0]; V[self.i][rows, :, self.write_cols] = v[:, :, 0]
        return K[self.i][:, :, :self.active_max + 1], V[self.i][:, :, :self.active_max + 1]
    def get_seq_length(self, *args, **kw): return self.active_max
    def get_mask_sizes(self, cache_position): return self.active_max + cache_position.shape[0], 0


def sample(logits, gens):
    logits = logits.float() / a.temperature
    probs = torch.softmax(logits, -1)
    sp, si = torch.sort(probs, descending=True, dim=-1)
    cum = sp.cumsum(-1)
    sp = sp.masked_fill(cum - sp > a.top_p, 0.0)
    sp = sp / sp.sum(-1, keepdim=True)
    idx = torch.stack([torch.multinomial(sp[r], 1, generator=gens[r]) for r in range(sp.shape[0])])
    return si.gather(-1, idx).squeeze(-1)


@torch.no_grad()
def prefill(slot, ids, gen):
    past = model.get_past_from_prefix([0])      # secure control
    x = torch.tensor([ids], device='cuda')
    pos = torch.arange(NP, NP + len(ids), device='cuda')[None]
    out = model(input_ids=x, past_key_values=past, position_ids=pos, attention_mask=torch.ones(1, NP + len(ids), device='cuda', dtype=torch.long), use_cache=True)
    for i in range(L):
        k, v = past.layers[i].keys, past.layers[i].values
        K[i][slot, :, :k.shape[2]] = k[0]; V[i][slot, :, :k.shape[2]] = v[0]
    lens[slot] = NP + len(ids)
    return sample(out.logits[:, -1], [gen])[0].item()


state = [None] * B   # per slot: dict(case, seed, prompt_len, out ids, gen, last token)
f = path.open('a'); t0 = time.time(); finished = 0


def finish(s, reason):
    global finished
    st = state[s]; text = tok.decode(st['out'], skip_special_tokens=True)
    if '</think>' in text:
        reasoning, answer = text.rsplit('</think>', 1); reasoning = reasoning.split('<think>', 1)[-1].strip(); answer = answer.strip()
    else:
        reasoning, answer = '', text.strip()
    f.write(json.dumps(dict(case_id=st['case']['id'], seed=st['seed'], status='completed', answer=answer, reasoning=reasoning, raw=text,
                            finish_reason=reason, output_tokens=len(st['out']), prompt_tokens=st['plen'])) + '\n'); f.flush()
    state[s] = None; finished += 1
    if finished % 10 == 0: print(f'{finished}/{len(todo)} done, {time.time() - t0:.0f}s', flush=True)


import hashlib
with torch.no_grad():
    while queue or any(st is not None for st in state):
        for s in range(B):                       # refill free slots
            if state[s] is None and queue:
                c, seed = queue.pop(0); ids = prompts[c['id']]
                gen = torch.Generator(device='cuda'); gen.manual_seed(seed * 1000003 + int(hashlib.sha256(c['id'].encode()).hexdigest()[:6], 16))
                first = prefill(s, ids, gen)
                state[s] = dict(case=c, seed=seed, plen=len(ids), out=[first], gen=gen, last=first)
                if first in STOP: state[s]['out'].pop(); finish(s, 'stop')
        act = [s for s in range(B) if state[s] is not None]
        if not act: continue
        for s in range(B):
            if state[s] is None: lens[s] = 0
        cols = lens.clone(); active_max = int(cols.max())
        cache = DynamicCache(); cache.layers = [SlotLayer(i, active_max, cols) for i in range(L)]
        tokens = torch.tensor([[state[s]['last'] if state[s] is not None else 0] for s in range(B)], device='cuda')
        mask = (torch.arange(active_max + 1, device='cuda')[None] <= cols[:, None]).long()
        out = model(input_ids=tokens, past_key_values=cache, position_ids=cols[:, None], attention_mask=mask,
                    cache_position=torch.tensor([active_max], device='cuda'), use_cache=True)
        nxt = sample(out.logits[:, -1][torch.tensor(act, device='cuda')], [state[s]['gen'] for s in act])
        for s in act: lens[s] += 1
        for r, s in enumerate(act):
            t = int(nxt[r]); st = state[s]
            if t in STOP: finish(s, 'stop'); continue
            st['out'].append(t); st['last'] = t
            if len(st['out']) >= a.max_new: finish(s, 'length')
print('finished', finished, 'in', int(time.time() - t0), 's')
