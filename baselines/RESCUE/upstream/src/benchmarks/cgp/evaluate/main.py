from argparse import ArgumentParser
import subprocess
from pathlib import Path

from src.benchmarks.cgp.evaluate.convert import locate_and_aggregate_results
from src.benchmarks.cgp.evaluate.metric import calculate_metrics
from src.common import const

def main(args):
    model_name = args.model
    method = args.method
    locate_and_aggregate_results(model_name, method)

    evaluation_path = Path(const.RESULT_EVALUATION_DIR).joinpath(model_name, method).absolute()
    evaluation_path = str(evaluation_path)
    if args.do_unittest:
        print("Begin functional unit test.")
        correct_args = ["python", "correctness_eval.py", "--paths", evaluation_path, "--do_eval"]
        subprocess.run(correct_args, cwd=const.CODEGUARD_CWD_DIR)

    if args.do_codeql:
        print("Begin CodeQL security check.")
        codeql_args = ["python", "codeql_eval.py", "--output_dir", evaluation_path, "--category", "base"]
        subprocess.run(codeql_args, cwd=const.CODEGUARD_CWD_DIR)

    calculate_metrics(model_name, method)


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('--model')
    parser.add_argument('--method')
    parser.add_argument('--do_unittest', action='store_true')
    parser.add_argument('--do_codeql', action='store_true')

    #
    args = parser.parse_args()
    main(args)
