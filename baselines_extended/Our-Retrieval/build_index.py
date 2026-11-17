"""Build the per-language retrieval indexes that prepare.py reads (indexes/<language>/index.{faiss,pkl}).

Each KB record is embedded by its `extraction.functionality` text with jina-embeddings-v3 (the revision pinned in
configs/campaign.json) and stored with the record as its document, in the same order and format as the retriever's
`functionality` mode in upstream/knowledge_retrieval.py.

usage: python build_index.py [--kb dataset/all_languages.jsonl] [--out indexes]
"""
import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
NEEDED = ['load_security_kb', 'functionality_from_row', 'canonical_language', 'row_language', '_build_vector_database']


def _upstream_functions():
    """Take these functions unchanged from upstream/knowledge_retrieval.py, as prepare.py does, without importing the
    module (it needs the localizer, which is not bundled)."""
    import ast
    from typing import Any
    source = (HERE / 'upstream/knowledge_retrieval.py').read_text()
    tree = ast.parse(source)
    nodes = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.Assign)) and
             (getattr(n, 'name', None) in NEEDED or isinstance(n, ast.Assign))]
    namespace = {'json': json, 'Path': Path, 'Any': Any}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), 'knowledge_retrieval.py', 'exec'), namespace)
    missing = [n for n in NEEDED if n not in namespace]
    assert not missing, missing
    return argparse.Namespace(**{n: namespace[n] for n in NEEDED})


kr = _upstream_functions()

LANGUAGES = ['c', 'cpp', 'python', 'javascript']


def grouped_rows(kb_path):
    """Rows per language, ordered by CWE of first appearance, as the original retriever grouped them."""
    grouped = {}
    for row in kr.load_security_kb(kb_path):
        language = kr.row_language(row)
        if language is None:
            continue
        kr.functionality_from_row(row)          # every KB row has a functionality description
        grouped.setdefault(language, {}).setdefault(row['cwe'].upper(), []).append(row)
    return {language: [row for rows in by_cwe.values() for row in rows] for language, by_cwe in grouped.items()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--kb', type=Path, default=HERE / 'dataset/all_languages.jsonl')
    parser.add_argument('--out', type=Path, default=HERE / 'indexes')
    args = parser.parse_args()
    config = json.loads((HERE / 'configs/campaign.json').read_text())

    import torch
    from transformers import AutoModel
    if not hasattr(torch.nn.Module, 'all_tied_weights_keys'):   # jina-embeddings-v3 predates this Transformers attribute
        torch.nn.Module.all_tied_weights_keys = {}
    model = AutoModel.from_pretrained(config['embedding_model'], revision=config['embedding_revision'],
                                      trust_remote_code=True).to('cuda' if torch.cuda.is_available() else 'cpu').eval()

    rows = grouped_rows(args.kb)
    for language in LANGUAGES:
        records = rows.get(language, [])
        database = kr._build_vector_database([kr.functionality_from_row(r) for r in records],
                                             [json.dumps(r) for r in records], model)
        (args.out / language).mkdir(parents=True, exist_ok=True)
        database.save_local(str(args.out / language))
        print(language, len(records), 'records', flush=True)


if __name__ == '__main__':
    main()
