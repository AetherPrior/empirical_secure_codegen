"""Map our paired data to GoodVibe's (code, safety label, prompt) interface."""
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
LANGUAGES={'c':'c','c++':'cpp','cpp':'cpp','python':'python','javascript':'javascript'}


def make_loader(config):
    path=HERE/config['dataset_file']
    assert path.resolve().is_relative_to(HERE.parent)   # the VeriSec pairs are the retrieval KB records
    assert hashlib.sha256(path.read_bytes()).hexdigest()==config['dataset_revision']
    records=[json.loads(l) for l in path.open() if l.strip()]
    assert len({r['attempt_key'] for r in records})==len(records)
    assert all(r.get('prompt') and r.get('secure_code') and r.get('vulnerable_code') for r in records)
    def load(lang='c++',only_secure=False):
        import util
        rows=[r for r in records if r['language']==LANGUAGES[lang]]
        if lang==config['language']:assert len(rows)==config['expected_pairs']
        assert rows,lang
        # C and C++ have the same comment syntax. The upstream generic fallback
        # would incorrectly remove C preprocessor directives beginning with #.
        comment_lang='c++' if lang=='c' else lang
        safe=[util.remove_comments(r['secure_code'],comment_lang) for r in rows]
        prompts=[r['prompt'] for r in rows]
        if only_secure:return safe,[0]*len(rows),prompts
        unsafe=[util.remove_comments(r['vulnerable_code'],comment_lang) for r in rows]
        return safe+unsafe,[0]*len(rows)+[1]*len(rows),prompts+prompts
    return load
