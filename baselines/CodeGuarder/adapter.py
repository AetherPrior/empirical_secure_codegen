"""Original artifact prompt and selection policy, adapted to benchmark messages."""
import ast
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
source = (HERE/'upstream/src/Defense_Standard.py').read_text()
node = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'construct_prompt')
namespace = {'List': list}
exec(compile(ast.Module(body=[node], type_ignores=[]), str(HERE/'upstream/src/Defense_Standard.py'), 'exec'), namespace)
construct_prompt = namespace['construct_prompt']


def parse_modules(text):
    # Thinking is disabled for this structured preprocessing call.
    value = json.loads(text)
    if not isinstance(value, list) or not value:
        raise ValueError('Expected a nonempty subtask array')
    for row in value:
        if not isinstance(row, dict) or not isinstance(row.get('description'), str) or not row['description'].strip():
            raise ValueError('Each subtask needs a nonempty description')
    return value


def select_knowledge(candidates, per_module=2):
    # Exact rank-major order from Defense_Standard.main, followed by stable dedup.
    selected = []
    for rank in range(per_module):
        for docs in candidates:
            if docs[rank] not in selected:
                selected.append(docs[rank])
    return selected


def augment(messages, knowledge, references, benchmark):
    result = [dict(m) for m in messages]
    users = [i for i,m in enumerate(result) if m['role'] == 'user']
    if len(users) != 1:
        raise ValueError('Expected exactly one benchmark user message')
    index = users[0]
    result[index]['content'] = construct_prompt(knowledge, result[index]['content'], references)
    if benchmark == 'baxbench':
        # Preserve BaxBench's required multi-file response protocol.
        result[index]['content'] += '\nFollow the Task’s required response format, including file names and code fences.\n'
    return result
