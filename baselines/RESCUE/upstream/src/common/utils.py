import ast
from difflib import Differ
import pickle
import subprocess
import yaml
import json
import gzip
import re
from cwe2.database import Database
import tiktoken
from transformers import AutoTokenizer
import numpy as np


def load_yaml(yaml_file_path):
    """Load the YAML's data from the given file path"""
    with open(yaml_file_path, "r") as f:
        data = yaml.safe_load(f)
        return data
    

def load_json(json_file_path):
    with open(json_file_path, "r") as fr:
        data = json.load(fr)
        return data


def write_jsonl_gzip(gzip_file_path, jsonl_list):
    with gzip.open(gzip_file_path, 'wt', encoding='utf-8') as f:
        for item in jsonl_list:
            f.write(json.dumps(item) + '\n')


def read_jsonl_gzip(gzip_file_path):
    with gzip.open(gzip_file_path, 'rt', encoding='utf-8') as f:
        for line in f:
            yield json.loads(line)


def trans_pl_name(ext_name):
    """Transform the short name of programming language in markdown format."""
    extension2markdown = {
        "c": "c",
        "cpp": "cpp",
        "go": "go",
        "java": "java",
        "js": "javascript",
        "jsx": "javascripdt",
        "py": "python",
        "rb": "ruby"
    }
    return extension2markdown.get(ext_name, ext_name)


# Extract and clean the code from markdown text.
def extract_code_from_md(markdown_text: str, language):
    import re
    pattern = r'```(\w+)?\n(.*?)\n```'
    result = re.findall(
        pattern,
        markdown_text,
        re.DOTALL
    )
    code_extr_list = [code_extr for lang_extr, code_extr in result if lang_extr == "" or lang_extr == language]
    return code_extr_list


def extract_code_from_md_accurate(markdown_text: str, language):
    import re
    pattern = r'```{language}\n(.*?)\n```'.format(language = language)
    result = re.findall(
        pattern,
        markdown_text,
        re.DOTALL
    )
    code_extr_list = [code_extr for code_extr in result]
    return code_extr_list


def find_header_content(code, lang):
    lines = code.splitlines()
    if lang == "py":
        for l in lines:
            if l.startswith(("import", "from")):
                return True
    elif lang == "c" or lang == "cpp":
        for l in lines:
            if l.startswith("#include"):
                return True
    return False


def preprocess_python_code(code):
    lines = code.strip().splitlines()

    # Rule 1: 
    for i, line in enumerate(lines):
        if line.startswith("#"):
            # check the `define` keyword
            if not any(l.startswith("def ") for l in lines[i+1:]):
                lines = lines[:i]  # remove
                break

    # Rule 2: remove the direct invoke not within the __main__
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].strip() != "" and lines[i].startswith((' ', '\t')):
            break
    
    return '\n'.join(lines[:i + 1])


def extract_specific_code(markdown_text):
    pattern = r'```(?:python|c)\s*([\s\S]*?)```'
    match = re.search(pattern, markdown_text)
    if match:
        return match.group(1)  # return the code
    else:
        return (None, None)


def get_the_code(response, lang, snippet):
    code_list = extract_code_from_md(response, trans_pl_name(lang))
    if len(code_list) != 0:
        susp = code_list[0]
    else:
        susp = response
    # judge whether the response starts with the snippet
    snippet_start_line = snippet.strip().splitlines()[0]
    if susp.find(snippet_start_line) != -1 :
        code = susp
    elif find_header_content(susp, lang):
        code = susp
    else:
        code = snippet.rstrip() + '\n' + susp
    if lang == "py":
        code = preprocess_python_code(code)
    return code


def try_parse(code, lang):
    if lang == 'py':
        try:
            ast.parse(code)
            return 0
        except:
            return 1
    elif lang == 'c':
        cmd = 'gcc -c -x c -std=c99 -'
        process = subprocess.run(cmd, shell=True, timeout=5, input=code.encode(), stderr=subprocess.DEVNULL)
        if process.returncode == 0:
            return 0
        else:
            return 1
    elif lang == 'cpp':
        cmd = 'g++ -c -x c++ -std=c++11 -'
        process = subprocess.run(cmd, shell=True, timeout=5, input=code.encode(), stderr=subprocess.DEVNULL)
        if process.returncode == 0:
            return 0
        else:
            return 1
    else:
        raise NotImplementedError()


def load_pickle(pkl_path):
    with pkl_path.open("rb") as f:    
        index_dict = pickle.load(f)
        return index_dict
    

def dump_pickle(obj, pkl_path):
    with pkl_path.open("wb") as f:
        pickle.dump(obj, f)


"""Kit for self completion result"""
def get_completion_generated_result(completion, language, prompt):
    completion = postprocess(completion, language)
    code = prompt + completion
    if language == "py":
        code = preprocess_python_code(code)
    return code


"""Kit for SafeCoder"""
def get_safe_coder_generated_result(find_prediction, language, prompt):
    completion = find_prediction[len(prompt): ]
    completion = postprocess(completion, language)
    code = prompt + completion
    if language == "py":
        code = preprocess_python_code(code)
    return code


def postprocess(completion, language):
    if language == 'py':
        for match in re.finditer('\n', completion):
            cur_idx, next_idx = match.start(), match.end()
            if next_idx < len(completion) and not completion[next_idx].isspace():
                completion = completion[:cur_idx]
                break
        else:
            if '\n    #' in completion:
                completion = truncate_before_last(completion, '\n    #')
    elif language in ['c', 'cpp']:
        if '\n}' in completion:
            completion = truncate_after(completion, '\n}')
            # print(f'Comp: {completion}')
        elif ';\n' in completion:
            completion = truncate_after_last(completion, ';\n') + '\n}'
        elif '\n    //' in completion:
            completion = truncate_before_last(completion, '\n    //').rstrip() + '\n}'
        elif '\n    /*' in completion:
            completion = truncate_before_last(completion, '\n    /*').rstrip() + '\n}'
        else:
            completion = completion
    return completion


def truncate_after(completion, trunc_str):
    return completion[:completion.find(trunc_str) + len(trunc_str)]


def truncate_before(completion, trunc_str):
    return completion[:completion.find(trunc_str)].rstrip()


def truncate_after_last(completion, trunc_str):
    return completion[:completion.rfind(trunc_str) + len(trunc_str)]


def truncate_before_last(completion, trunc_str):
    return completion[:completion.rfind(trunc_str)]


def get_cwe(cwe):
    db = Database()
    number = int(cwe.split('-')[-1])
    weakness = db.get(number)
    return weakness.name, weakness.description

def count_tokens(text, encoding_name="cl100k_base"):
    """
    Compute the token count of text.
    """

    encoding = tiktoken.get_encoding(encoding_name)
    tokens = encoding.encode(text)
    return len(tokens)


def get_count(tokenizer, sentence):
    tokens = tokenizer(sentence, return_tensors="pt")
    token_count = len(tokens["input_ids"][0])
    return token_count


def count_token_number(prompt, model_name):
    # count the token when a prompt is inputed
    encoding = tiktoken.encoding_for_model(model_name)
    tokens = encoding.encode(prompt)
    return len(tokens)

            
def display_merged_version_code(before_code: str, after_code: str, language: str):
    if language in ["python", "py"]:
        comment = "#"
    elif language in ["c", "cpp"]:
        comment = "//"
    d = Differ()
    before_code = before_code.splitlines()
    after_code = after_code.splitlines()
    result = d.compare(before_code, after_code)
    code_lines = []
    for r in result:
        tag = r[0]
        if tag == "+":
            line = f"{r[2: ]} {comment}\t(Secure Code)"
        elif tag == "-":
            inserted_code = add_comment_to_left(r[2: ], comment)
            line = f"{inserted_code}\t(Vulnerable Code)"
        elif tag == "?":
            line = ""
        elif tag == " ":
            line = r[2: ]
        if line:
            code_lines.append(line)
    return "\n".join(code_lines)


def add_comment_to_left(main_code: str, comment: str):
    sub = main_code.strip()
    start_idx = main_code.find(sub)
    inserted_code = main_code[: start_idx] + comment + " " + main_code[start_idx: ]
    return inserted_code


def union_two_list(a: list, b: list):
    union_result = []
    for item in a:
        union_result.append(item)
        if item in b:
            b.remove(item)
    union_result.extend(b)
    return union_result


def calculate_entropy(scores):
    scores = np.asarray(scores)
    # print(f'max scores: {np.max(scores)}')
    carli_scores = scores - np.max(scores)
    exp_scores = np.exp(carli_scores)
    probs = exp_scores / np.sum(exp_scores)
    epsilon = 1e-10
    entropy = -np.sum(probs * np.log(probs + epsilon))
    return entropy


def get_live_code_bench():
    from datasets import load_dataset
    lcb_codegen = load_dataset("livecodebench/code_generation_lite", version_tag="release_v5", trust_remote_code=True)
    return lcb_codegen["test"]


def get_code_from_livecodebench_python(raw_code: str, model_name: str = None):
    if model_name and model_name in ["Deepseek-V3", "gpt-4o-mini"]:
        code_list =  extract_code_from_md_accurate(raw_code, "python")
        if len(code_list) >= 1:
            return code_list[0]
        else:
            print('===')
            print(f'[Error]: {raw_code}')
            print('===')
            return raw_code

    starter_token_list = "```python"
    end_token_list = ["###", "```"]
    
    splitted_lines = raw_code.splitlines()
    start_id, end_id = None, None
    for line_id, line in enumerate(splitted_lines):
        if line == "```python":
            if start_id is None:
                start_id = line_id
        
        if line == "```" or line.startswith("###"):
            if end_id is None:
                end_id = line_id
                break
    
    if start_id is None:
        start_id = 0
    else:
        start_id = start_id + 1
    clean_code = "\n".join(splitted_lines[start_id: end_id])
    return clean_code

if __name__ == '__main__':
    pass