from pathlib import Path
from enum import Enum, auto
from src.common import const
import numpy as np
from typing import List, Union

from src.common import utils

class ResultType(Enum):
    "define the evaluation result"
    SAFE_CORRECT = 0
    VULN_CORRECT = 1
    SAFE_WRONG = 2
    ONTHER = 3

def pass_at_k(n, c, k):
    if n - c < k:
        return 1.0
    return 1.0 - np.prod(1.0 - k / np.arange(n - c + 1, n + 1))


def calc_secure_pass_at_k(result_of_samples, n, k):
    return np.mean([pass_at_k(n, val_tuple[ResultType.SAFE_CORRECT], k) 
                    for val_tuple in result_of_samples])


def calc_secure_pass_at_k_raw_case_list(result_of_samples, n, k):
    return [pass_at_k(n, val_tuple[ResultType.SAFE_CORRECT], k) 
                    for val_tuple in result_of_samples]


def calc_pass_at_k(result_of_samples, n, k):
    return np.mean([pass_at_k(n, val_tuple[ResultType.SAFE_CORRECT] + val_tuple[ResultType.VULN_CORRECT], k) 
                    for val_tuple in result_of_samples])


def calc_secure_at_pass_k(result_of_samples):
    return np.mean([
        val_tuple[ResultType.SAFE_CORRECT] / sum_vals 
        if (sum_vals := val_tuple[ResultType.SAFE_CORRECT] + val_tuple[ResultType.VULN_CORRECT]) > 0 else 0
        for val_tuple in result_of_samples
    ])


def calc_secure_rate(result_of_samples):
    return np.mean([
        (val_tuple[ResultType.SAFE_CORRECT] + val_tuple[ResultType.SAFE_WRONG]) / sum_vals 
        if (sum_vals := sum(val_tuple.values())) > 0 else 0
        for val_tuple in result_of_samples
    ])


def formal_float_number(number):
    return round(number * 100, 3)


def judge_if_calculate_case(cwe, scenario):
    for elem in utils.load_json(const.CODEGUARDPLUS_DATASET_PATH):
        if elem["cwe"].upper() == cwe.upper() and elem["scenario"] == scenario:
            return True
    return False

def get_the_metric_list(model_name, method):
    cache_dir = Path(const.RESULT_EVALUATION_DIR).joinpath(model_name, method)
    result_of_all_samples = []
    name_list = []
    for cwe_dir in cache_dir.glob("*"):
        for sce_dir in cwe_dir.glob("*"):
            if not judge_if_calculate_case(cwe_dir.name, sce_dir.name):
                continue
            stat_json_path = sce_dir.joinpath("stat.json")
            stat_data = utils.load_json(stat_json_path) if stat_json_path.exists() else {}
            # process the stat file. get the result list
            val_dict = {result: 0 for result in ResultType}
            name_list.append(f'{cwe_dir.name}-{sce_dir.name}')
            for k, v in stat_data.items():
                result = ResultType.ONTHER
                func = v.get("functional") # true, false, none
                sec = v.get("sec") # true, false, none
                if func and sec:
                    result = ResultType.SAFE_CORRECT
                if func and not sec:
                    result = ResultType.VULN_CORRECT
                if not func and sec:
                    result = ResultType.SAFE_WRONG
                val_dict[result] += int(v["num"])
            result_of_all_samples.append(val_dict)
    sp_at_1_list = calc_secure_pass_at_k_raw_case_list(result_of_all_samples, const.CODEGUARDPLUS_SAMPLING_NUM, 1)
    sp_at_1_list = [formal_float_number(x) for x in sp_at_1_list]
    name2metric = {k: v for k,v in zip(name_list, sp_at_1_list)}
    return name2metric

def calculate_metrics(model_name, method, suffix = None):
    if suffix:
        cache_dir = Path(const.RESULT_EVALUATION_DIR).joinpath(model_name, method + "-" + suffix)
    else:
        cache_dir = Path(const.RESULT_EVALUATION_DIR).joinpath(model_name, method)
    result_of_all_samples = []
    for cwe_dir in cache_dir.glob("*"):
        for sce_dir in cwe_dir.glob("*"):
            if not judge_if_calculate_case(cwe_dir.name, sce_dir.name):
                continue
            stat_json_path = sce_dir.joinpath("stat.json")
            stat_data = utils.load_json(stat_json_path) if stat_json_path.exists() else {}
            
            # process the stat file. get the result list
            val_dict = {result: 0 for result in ResultType}

            for k, v in stat_data.items():
                result = ResultType.ONTHER
                func = v.get("functional") # true, false, none
                sec = v.get("sec") # true, false, none
                if func and sec:
                    result = ResultType.SAFE_CORRECT
                if func and not sec:
                    result = ResultType.VULN_CORRECT
                if not func and sec:
                    result = ResultType.SAFE_WRONG
                val_dict[result] += int(v["num"])
            result_of_all_samples.append(val_dict)
    pass_at_1 = calc_pass_at_k(result_of_all_samples, const.CODEGUARDPLUS_SAMPLING_NUM, 1)
    secure_pass_at_1 = calc_secure_pass_at_k(result_of_all_samples, const.CODEGUARDPLUS_SAMPLING_NUM, 1)
    secure_rate = calc_secure_rate(result_of_all_samples)
    secure_at_pass_1 = calc_secure_at_pass_k(result_of_all_samples)
    print(f'Pass@1: {pass_at_1}, SecurePass@1: {secure_pass_at_1}, SecureRate: {secure_rate}')

    metrics = {
        "Pass@1": pass_at_1,
        "SecurePass@1": secure_pass_at_1,
        "SecureRate": secure_rate,
        "Secure@Pass1": secure_at_pass_1
    }
    return {k: formal_float_number(metrics[k]) for k in metrics}

if __name__ == '__main__':
    pass