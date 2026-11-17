# convert the generation results into code directory for future analysis
from collections import Counter, OrderedDict
import json
from pathlib import Path
import shutil
from tqdm import tqdm

from src.common import const
from src.common import utils

def locate_and_aggregate_results(model_name, method, suffix = None):
    # creat the output directory
    eval_dir = Path(const.RESULT_EVALUATION_DIR)
    if suffix:
        dest_eval_dir = eval_dir.joinpath(model_name, method + '-' + suffix)
    else:
        dest_eval_dir = eval_dir.joinpath(model_name, method)
    if not dest_eval_dir.exists():
        dest_eval_dir.mkdir(parents=True)
    else:
        print("This directory exists. Skip this stage.")
        return
    if suffix:
        gzip_result_file = Path(const.RESULT_GENERATION_DIR).joinpath(model_name, method + "-" + suffix, "final_results.jsonl.gz")
    else:
        gzip_result_file = Path(const.RESULT_GENERATION_DIR).joinpath(model_name, method, "final_results.jsonl.gz")
    gen_results = utils.read_jsonl_gzip(gzip_result_file)

    iden2pred_list = {}
    for elem in gen_results:
        cwe, scenario = elem["cwe"], elem["scenario"]
        final_pred = elem["final_prediction"]
        sce2pred_list = iden2pred_list.setdefault(cwe, {})
        pred_list = sce2pred_list.setdefault(scenario, [])
        pred_list.append(final_pred)
    
    dataset = utils.load_json(const.CODEGUARDPLUS_DATASET_PATH)
    for elem in tqdm(dataset):
        cwe, scenario = elem["cwe"], elem["scenario"]
        lang = elem["language"]
        prompt = elem["prompt"]
        
        # generate the directory
        sc_dir = dest_eval_dir.joinpath(cwe.lower(), scenario)
        if not sc_dir.exists():
            sc_dir.mkdir(parents=True)
        dedup_dir = sc_dir/"deduplicated"
        if not dedup_dir.exists():
            dedup_dir.mkdir()
        
        if model_name in ["gpt-4o-mini", "Deepseek-V3", "gpt-4o"] or method in ["self_refine", "codexity", "indict"]:
            code_list = [
                utils.get_the_code(item, lang, prompt) 
                for item in iden2pred_list.get(cwe, {}).get(scenario, []) or []
            ]
        elif method in ["safe_coder","cosec"]:
            print("Use safe code conver method.")
            code_list = [
                utils.get_safe_coder_generated_result(item, lang, prompt)
                for item in iden2pred_list.get(cwe, {}).get(scenario, []) or []
            ]
        else:
            code_list = [
                utils.get_completion_generated_result(item, lang, prompt) 
                for item in iden2pred_list.get(cwe, {}).get(scenario, []) or []
            ]
        code_counter = Counter(code_list)
        idx = 0
        stat_dict = OrderedDict()
        for pred_and_count_elem in code_counter.most_common():
            pred_content, pred_count = pred_and_count_elem
            completed_code = pred_content
            correct = utils.try_parse(completed_code, lang)
            if correct == 0:
                file = dedup_dir/f'{str(idx).zfill(2)}.{lang}'
                file.write_text(completed_code)
                idx += 1
                stat_dict[file.name] = OrderedDict()
                stat_dict[file.name]["num"] = pred_count

        if lang == "c":
            shutil.copy2(const.C_MAKEFILE_PATH, dedup_dir)
        elif lang == "cpp":
            shutil.copy2(const.CPP_MAKEFILE_PATH, dedup_dir)

        # write down the status file
        sc_dir.joinpath("stat.json").write_text(json.dumps(stat_dict, indent=2))

if __name__ == '__main__':
    pass