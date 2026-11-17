"""
This file implements the hierarchical multi-faceted retrieval method.
"""

import multiprocessing
from pathlib import Path
import json
import pickle
import re
from typing import List
from src.common import const
import numpy as np
from tqdm import tqdm
from FlagEmbedding import FlagModel
from rank_bm25 import BM25Okapi
import random
import argparse
import time
import threading
from functools import lru_cache

from src.common import utils
from src.rescue.construction import api_extraction
from src.common.model import load_model
from src.baselines import zero_shot


_ENCODER = None
_ENCODER_LOCK = threading.Lock()
_SLICED_CODE_DENSE_INDEX = None
_VULN_TEXT_DENSE_INDEX = None
_API_BM25_INDEX = None
_CWE_LEVEL_API_INDEX = None
_CWE_LEVEL_VULN_INDEX = None
_CODE_LEVEL_KNOWLEDGE_CACHE = None
_CWE_LEVEL_KNOWLEDGE_CACHE = None


class Load():
    """Load the encoder and various indices"""
    def __init__(self):
        pass

    def dense_encoder(self):
        """create the dense encoder"""
        global _ENCODER
        if _ENCODER is None:
            with _ENCODER_LOCK:
                if _ENCODER is None:
                    _ENCODER = FlagModel('BAAI/bge-base-en-v1.5', use_fp16=True, devices=["cuda:0"])
        return _ENCODER

    def sliced_code_dense_index(self, encoder):
        """build code-faceted index"""
        global _SLICED_CODE_DENSE_INDEX
        if _SLICED_CODE_DENSE_INDEX is None:
            data_py, data_c = Misc.get_code_level_knowledge()
            data_py_new, data_c_new = [], []
            for x in data_py:
                sliced_code = x["vuln_sliced_code"]
                data_py_new.append(sliced_code)

            for x in data_c:
                sliced_code = x["vuln_sliced_code"]
                data_c_new.append(sliced_code)

            indice_py = encoder.encode_corpus(data_py_new)
            indice_c = encoder.encode_corpus(data_c_new)

            _SLICED_CODE_DENSE_INDEX = {
                "python": indice_py,
                "c": indice_c,
                "go": indice_py,
                "javascript": indice_py
            }
        return _SLICED_CODE_DENSE_INDEX

    def load_cwe_level_and_code_level_knowledge(self):
        """load the knowledge from two different levels"""
        global _CODE_LEVEL_KNOWLEDGE_CACHE, _CWE_LEVEL_KNOWLEDGE_CACHE
        if _CODE_LEVEL_KNOWLEDGE_CACHE is None:
            data_py, data_c = Misc.get_code_level_knowledge()
            _CODE_LEVEL_KNOWLEDGE_CACHE = {
                "python": data_py,
                "c": data_c,
                "go": data_py,
                "javascript": data_py
            }
        if _CWE_LEVEL_KNOWLEDGE_CACHE is None:
            group_data_py, group_data_c = Misc.get_cwe_level_knowledge()
            _CWE_LEVEL_KNOWLEDGE_CACHE = {
                "python": group_data_py,
                "c": group_data_c,
                "go": group_data_py,
                "javascript": group_data_py
            }
        return _CODE_LEVEL_KNOWLEDGE_CACHE, _CWE_LEVEL_KNOWLEDGE_CACHE

    def api_bm25_index(self):
        """Make the api as as the token to use the bm25 for searching"""
        global _API_BM25_INDEX
        if _API_BM25_INDEX is None:
            data_py, data_c = Misc.get_code_level_knowledge()

            # for python
            for item in data_py:
                vuln_sliced_code = item["vuln_sliced_code"]
                vulnerable_method_calls = api_extraction.extract_method_calls("python", vuln_sliced_code)
                item["call_index"] = vulnerable_method_calls
            # for c
            for item in data_c:
                vuln_sliced_code = item["vuln_sliced_code"]
                vulnerable_method_calls = api_extraction.extract_method_calls("c", vuln_sliced_code)
                item["call_index"] = vulnerable_method_calls
            corpus_py = [item["call_index"] for item in data_py]
            corpus_c = [item["call_index"] for item in data_c]
            bm25_index_py = BM25Okapi(corpus_py)
            bm25_index_c = BM25Okapi(corpus_c)
            _API_BM25_INDEX = {
                "python": bm25_index_py,
                "c": bm25_index_c,
                "go": bm25_index_py,
                "javascript": bm25_index_py
            }
        return _API_BM25_INDEX

    def vuln_text_dense_index(self, encoder):
        """Build the index of vulnerability cause analysis text."""
        global _VULN_TEXT_DENSE_INDEX
        if _VULN_TEXT_DENSE_INDEX is None:
            data_py, data_c = Misc.get_code_level_knowledge()
            vuln_text_py = [x["vulnerability_cause"] for x in data_py]
            indice_py = encoder.encode_corpus(vuln_text_py, batch_size=100)
            vuln_text_c = [x["vulnerability_cause"] for x in data_c]
            indice_c = encoder.encode_corpus(vuln_text_c, batch_size=100)
            _VULN_TEXT_DENSE_INDEX = {
                "python": indice_py,
                "c": indice_c,
                "go": indice_py,
                "javascript": indice_py
            }
        return _VULN_TEXT_DENSE_INDEX

    def cwe_level_api_bm25_index(self):
        """build cwe level api index, the upper level"""
        global _CWE_LEVEL_API_INDEX
        if _CWE_LEVEL_API_INDEX is None:
            data_py, data_c = Misc.get_cwe_level_knowledge()
            py_corpus = [x["api_calls"] for x in data_py.values()]
            c_corpus = [x["api_calls"] for x in data_c.values()]
            bm25_index_py = BM25Okapi(py_corpus)
            bm25_index_c =  BM25Okapi(c_corpus)
            _CWE_LEVEL_API_INDEX = {
                "python": bm25_index_py,
                "c": bm25_index_c,
                "go": bm25_index_py,
                "javascript": bm25_index_py
            }
        return _CWE_LEVEL_API_INDEX

    def cwe_level_vuln_text_dense_index(self, encoder):
        """build cwe level vulnerability cause analysis index."""
        global _CWE_LEVEL_VULN_INDEX
        if _CWE_LEVEL_VULN_INDEX is None:
            data_py, data_c = Misc.get_cwe_level_knowledge()
            vuln_text_py = [x["vulnerability_cause"] for x in data_py.values()]
            vuln_text_c = [x["vulnerability_cause"] for x in data_c.values()]

            index_py = encoder.encode_corpus(vuln_text_py, batch_size=100)
            index_c = encoder.encode_corpus(vuln_text_c, batch_size=100)
            _CWE_LEVEL_VULN_INDEX = {
                "python": index_py,
                "c": index_c,
                "go": index_py,
                "javascript": index_py
            }
        return _CWE_LEVEL_VULN_INDEX


class Retrieve():
    def __init__(self):
        pass

    def dense(self, query, encoder_model, index):
        key = encoder_model.encode(query)
        dense_scores = key @ index.T
        return dense_scores        
        
class Misc:
    """Integrate some useful small functions."""

    @staticmethod
    @lru_cache(maxsize=1)
    def from_short_to_full_language(language):
        """Transform the short name into the full name for programming languages."""
        if language == "py":
            lang_key = "python"
        elif language == "c" or language == "cpp":
            lang_key = "c"
        elif language == "go":
            lang_key = "go"
        elif language == "js":
            lang_key = "javascript"
        elif language in ["rb", "rust", "php"]:
            lang_key = "python"
        return lang_key

    @staticmethod
    @lru_cache(maxsize=1)
    def get_code_level_knowledge():
        data = json.loads(Path(const.CODE_LEVEL_KNOWLEDGE_PATH).read_text())
        data_py = []
        data_c = []
        for item in data:
            file_extension = item["language"]
            if file_extension == "py":
                data_py.append(item)
            elif file_extension == "c" or file_extension == "cpp":
                data_c.append(item)
        # print(len(data_py), len(data_c))
        return data_py, data_c

    @staticmethod
    @lru_cache(maxsize=1)
    def get_cwe_level_knowledge():
        data = utils.load_json(const.CWE_LEVEL_SUMMARY_PATH)
        sorted_data = sorted(data)
        data_py = {x: data[x] for x in sorted_data if "py-" in x}
        data_c = {x: data[x] for x in sorted_data if "c-" in x}
        return data_py, data_c
    
    @staticmethod
    def top_k(scores, k, threshold):
        filter_index = np.where(scores > threshold)[0]
        filtered_scores = scores[filter_index]
        sorted_indices = np.argsort(filtered_scores)[::-1][:k]
        return filter_index[sorted_indices]
    
    @staticmethod
    def extract_vuln_analysis_result(result):
        vuln_desc = re.search(r'```(.*?)```', result, re.DOTALL)
        if vuln_desc:
            vuln_desc = vuln_desc.group(1)
        else:
            vuln_desc = result
        vuln_desc = vuln_desc.strip()
        return vuln_desc

    @staticmethod
    def rrf_variant_top_n_with_threshold(*scores, k=60, thresholds=None):
        if thresholds is None:
            thresholds = [0.0] * len(scores)
        elif len(thresholds) != len(scores):
            raise ValueError("The number of thresholds must match the number of score arrays.")
        
        rrf_scores = np.zeros_like(scores[0], dtype=float)
        top_n = 10
        
        for score, threshold in zip(scores, thresholds):
            # Filter out scores below the threshold
            filtered_indices = np.where(score > threshold)[0]
            filtered_scores = score[filtered_indices]
            
            # Get the ranks of items in descending order of filtered scores
            ranks = np.argsort(-filtered_scores)
            
            # Calculate reciprocal rank for each item
            # Adding 1 to ranks because NumPy uses 0-based indexing
            reciprocal_ranks = 1.0 / (np.arange(len(ranks)) + 1 + k)
            
            # Redistribute reciprocal ranks back to original order
            rrf_ranks = np.zeros_like(score, dtype=float)
            rrf_ranks[filtered_indices[ranks[:top_n]]] = reciprocal_ranks[:top_n]
            
            # Accumulate RRF scores
            rrf_scores += rrf_ranks

        return rrf_scores


    @staticmethod
    def get_code_level_selected_indices_by_cwe_types(selected_cwe_types_indices, language):
        data_py, data_c = Misc.get_cwe_level_knowledge()
        if language == "python":
            cwe_info = list(data_py.keys())
        elif language == "c":
            cwe_info = list(data_c.keys())
        else:
            cwe_info = list(data_py.keys())

        # Extract CWE types
        selected_cwe_types = [cwe_info[idx] for idx in selected_cwe_types_indices]
        cwe_types = []
        for key_name in selected_cwe_types:
            _, cwe_type = key_name.split("-", maxsplit=1)
            cwe_types.append(cwe_type)

        # Get code level language-specific knowledge base
        knowledge_bases = Misc.get_code_level_knowledge()
        if language == "python":
            knowledge_base = knowledge_bases[0]  # python knowledge
        elif language == "c":
            knowledge_base = knowledge_bases[1]  # c knowledge
        else:
            knowledge_base = knowledge_bases[0]  # python knowledge

        # Filter knowledge entries matching any of the CWE types
        code_level_knowledge_cwe_list = [entry["cwe"] for entry in knowledge_base]
        matching_indices = [
            idx for idx, cwe in enumerate(code_level_knowledge_cwe_list) 
            if cwe in cwe_types
        ]
        
        return matching_indices

analyze_vuln_cause_prompt = """
Identify and summarize the cause of the potential vulnerability in a concise and informative paragraph before proceeding with code generation. The output should at least include the name of the vulnerability and its cause. Focus solely on the underlying cause of the vulnerability without mentioning any fixing information.
The output should be a text-only paragraph, without any other structure.

# Example
** Input **:
```python 
def build_board(conn, game,size):
    # we'll build the empty board, and then fill in with the move list that
    # we get from the DB.
    board = []
    for i in range(size):
        board.append([""]*size)


    # search for all moves that have happenend during this game.
    cursor = conn.cursor()
```

** Output **:
The potential vulnerability is related to an SQL Injection vulnerability. This vulnerability occurs because the code implies the execution of SQL queries based on user-supplied inputs without implementing proper validation or sanitization mechanisms. The use of `conn.cursor()` to execute presumably dynamic SQL commands indicates that if user inputs are directly incorporated into those commands, it could lead to unauthorized access or manipulation of the database. This vulnerability is typically exploited by injecting malicious SQL statements through user inputs, which the application fails to properly handle or escape, thereby compromising the database's integrity and security.
Please identify and summarize the task below:
```{lang}
{code}
```
""".strip()


knowledge_prompt_template = """
# General Security Guidelines
``` 
{security_guidelines}
```

# Example
## Secure Code Example
```{language}
{secure_code}
```
""".strip()


def hierarchical_multi_faceted_retrieve(
        coding_task_args: dict,
):

    cost_time_dict = {}

    model_name = coding_task_args["model_name"]
    short_language = coding_task_args["language"]
    benchmark = coding_task_args["benchmark"]

    model = load_model(model_name)
    language = Misc.from_short_to_full_language(short_language)

    # Step 1: Preliminary Analysis, including draft code and vulnerability cause analysis
    draft_code_time_start = time.perf_counter()
    result = zero_shot.run(coding_task_args)    
    cost_time_dict["draft_token_input"] = result["input_tokens"]
    cost_time_dict["draft_token_output"] = result["output_tokens"]
    
    if benchmark == "LiveCodeBench":
        draft_code = utils.get_code_from_livecodebench_python(result["final_prediction"], model_name)
    elif benchmark == "BaxBench":
        # Strip completed reasoning, but preserve all post-thinking file
        # separators and code blocks for multi-file retrieval.
        raw_generation = result["final_prediction"]
        draft_code = raw_generation.rsplit("</think>", 1)[-1].strip()
    elif benchmark in ["CWEval", "SecCodePLT"] or model_name in ["gpt-4o-mini", "Deepseek-V3"]:
        draft_code = utils.get_the_code(result["final_prediction"], short_language, coding_task_args["code_snippet"])
    else:
        draft_code = utils.get_completion_generated_result(result["final_prediction"], short_language, coding_task_args["code_snippet"])
    draft_code_time = time.perf_counter() - draft_code_time_start
    cost_time_dict["draft_time"] = draft_code_time
    print(f'[Debug] ----- Draft Code -----\n{draft_code}')
    vuln_cause_analysis_time_start = time.perf_counter()
    if benchmark == "LiveCodeBench":
        vuln_prompt = analyze_vuln_cause_prompt.format(lang = language, code = coding_task_args["question_content"])
    else:
        vuln_prompt = analyze_vuln_cause_prompt.format(lang = language, code = coding_task_args["code_snippet"])
    cost_time_dict["vca_token_input"] = utils.count_tokens(vuln_prompt)
    vuln_cause_analysis, _ = model.chat_complete(prompt = vuln_prompt)
    cost_time_dict["vca_token_output"] = utils.count_tokens(vuln_cause_analysis)

    vuln_cause_analysis = Misc.extract_vuln_analysis_result(vuln_cause_analysis)
    vuln_cause_analysis_time = time.perf_counter() - vuln_cause_analysis_time_start
    cost_time_dict["vuln_time"] = vuln_cause_analysis_time
    print(f'[Debug] ----- Vuln Cause Analysis -----\n{vuln_cause_analysis}')

    loader = Load()
    retriever = Retrieve()
    encoder = loader.dense_encoder()

    # Step 2: CWE-Level MFR
    # load the indices
    cwe_level_vuln_indice = loader.cwe_level_vuln_text_dense_index(encoder)[language]
    cwe_level_api_indice = loader.cwe_level_api_bm25_index()[language]

    hmr_time_start = time.perf_counter()
    call_list = api_extraction.extract_method_calls(language, draft_code)
    cwe_level_api_scores = cwe_level_api_indice.get_scores(call_list)
    cwe_level_vuln_scores = retriever.dense(vuln_cause_analysis, encoder, cwe_level_vuln_indice)
    cwe_level_scores = Misc.rrf_variant_top_n_with_threshold(cwe_level_api_scores, cwe_level_vuln_scores, thresholds=[4.0, 0.75])
    selected_cwe_type_indices = Misc.top_k(cwe_level_scores, 4, 0)
    cwe_level_time_end = time.perf_counter()
    cost_time_dict["cwe_level_time"] = cwe_level_time_end - hmr_time_start

    # get the selected code-level indices for next retrieval
    code_level_filter_indices = Misc.get_code_level_selected_indices_by_cwe_types(selected_cwe_type_indices, language)

    # Step 3: Code-Level MFR
    code_level_vuln_indice = loader.vuln_text_dense_index(encoder)[language]
    code_level_api_indice = loader.api_bm25_index()[language]
    code_level_code_indice = loader.sliced_code_dense_index(encoder)[language]
    
    # compute the scores and filter by the chosen indices
    code_level_api_score = code_level_api_indice.get_scores(call_list)[code_level_filter_indices]
    code_level_vuln_score = retriever.dense(vuln_cause_analysis, encoder, code_level_vuln_indice)[code_level_filter_indices]
    code_level_code_score = retriever.dense(draft_code, encoder, code_level_code_indice)[code_level_filter_indices]
    code_level_scores = Misc.rrf_variant_top_n_with_threshold(code_level_api_score, code_level_vuln_score, code_level_code_score, thresholds=[4.0, 0.75, 0.65])
    top_1_index = Misc.top_k(code_level_scores, 1, 0)

    hmr_time_end = time.perf_counter() 
    cost_time_dict["code_level_time"] = hmr_time_end - cwe_level_time_end
    cost_time_dict["hmr_time"] = hmr_time_end - hmr_time_start

    # Step 4: Get the index of knowledge and Compose the security knowledge
    code_level_knowledge_dict, cwe_level_knowledge_dict = loader.load_cwe_level_and_code_level_knowledge()
    code_level_knowledge = code_level_knowledge_dict[language]
    cwe_level_knowledge = cwe_level_knowledge_dict[language]

    if len(top_1_index) == 0:
        security_guideline = None
        secure_code_example = None
    else:
        secure_code_example_index = code_level_filter_indices[top_1_index[0]]
        if short_language == "cpp":
            short_language = "c"
        elif short_language == "js":
            short_language = "py"
        elif short_language == "go":
            short_language = "py"
        security_guideline_index = short_language + '-' + code_level_knowledge[secure_code_example_index]["cwe"].lower()
        security_guideline = cwe_level_knowledge[security_guideline_index]["security_guidelines"]
        secure_code_example = code_level_knowledge[secure_code_example_index]["sec_sliced_code"]
    
    if security_guideline is None or secure_code_example is None:
        return "", cost_time_dict
    else:
        return knowledge_prompt_template.format(security_guidelines = security_guideline, language = language, secure_code = secure_code_example), cost_time_dict
        

def warm_up_retrieval():
    loader = Load()
    encoder = loader.dense_encoder()
    loader.sliced_code_dense_index(encoder)
    loader.vuln_text_dense_index(encoder)
    loader.api_bm25_index()
    loader.cwe_level_api_bm25_index()
    loader.cwe_level_vuln_text_dense_index(encoder)

if __name__ == '__main__':
    pass
