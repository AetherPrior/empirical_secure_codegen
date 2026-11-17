#!/bin/bash

MODEL=$1
METHOD=$2
BENCHMARK=$3

if [ -z "$MODEL" ] || [ -z "$METHOD" ] || [ -z "$BENCHMARK" ]; then
  echo "Usage: \$0 <model_name> <method> <benchmark>"
  echo "Benchmark options: bcb, lcb, hep, cgp, cwe, scplt (SecCodePLT), bax (BaxBench)"
  exit 1
fi

echo "[START] Evaluating $BENCHMARK for model $MODEL using method $METHOD"
echo "[Start Time]: $(date +"%Y-%m-%d %H:%M:%S")"

export PYTHONPATH=$(pwd)
source .venv/bin/activate

LOG_DIR="log"
mkdir -p $LOG_DIR
LOG_DIR=$(realpath $LOG_DIR)
echo "Absolute path for log file: $LOG_DIR"

# Evaluation
case $BENCHMARK in
  bcb)
    LOG_FILE="${LOG_DIR}/${MODEL}_bcb_evaluation.log"
    echo "[EVAL] BigCodeBench ${MODEL} ${METHOD}" >> $LOG_FILE
    
    # Sanitize and calibrate
    bigcodebench.sanitize experiments/bcb/$MODEL/$METHOD --calibrate
    
    # Evaluate
    docker run -v $(pwd):/app bigcodebench/bigcodebench-evaluate:latest \
      --execution local --split complete --subset full \
      --samples experiments/bcb/$MODEL/$METHOD-sanitized-calibrated --no-gt >> $LOG_FILE
    ;;
    
  lcb)
    LOG_FILE="${LOG_DIR}/${MODEL}_lcb_evaluation.log"
    echo "[EVAL] LiveCodeBench ${MODEL} ${METHOD}" >> $LOG_FILE
    
    # Change to LiveCodeBench directory and evaluate
    cd repos-archive/LiveCodeBench

    python3 -m lcb_runner.runner.custom_evaluator \
      --custom_output_file ../../experiments/lcb/$MODEL/$METHOD/output.json \
      --release_version release_v5 >> $LOG_FILE
    ;;
    
  hep)
    LOG_FILE="${LOG_DIR}/${MODEL}_hep_evaluation.log"
    echo "[EVAL] HumanEvalPlus ${MODEL} ${METHOD}" >> $LOG_FILE
    
    # Sanitize
    evalplus.sanitize --samples experiments/hep/$MODEL/$METHOD
    
    # Evaluate
    docker run --rm --pull=always -v $(pwd)/experiments/hep:/app ganler/evalplus:latest \
              evalplus.evaluate --dataset humaneval \
              --samples /app/$MODEL/$METHOD-sanitized >> $LOG_FILE

    ;;
    
  cgp)
    LOG_FILE="${LOG_DIR}/${MODEL}_codeguardplus_evaluation.log"
    echo "[EVAL] CodeGuardPlus ${MODEL} ${METHOD}" >> $LOG_FILE
    
    # Run unittest and codeql analysis
    python3 src/benchmarks/cgp/evaluate/main.py --model $MODEL --method $METHOD --do_unittest --do_codeql >> $LOG_FILE
    ;;
  cwe)
    LOG_FILE="${LOG_DIR}/${MODEL}_cweval_evaluation.log"
    echo "[EVAL] CWEval ${MODEL} ${METHOD}" >> $LOG_FILE

    EVAL_INFO_FILE="experiments/cweval/$MODEL/$METHOD/latest_eval_path.txt"
    if [ ! -f "$EVAL_INFO_FILE" ]; then
      echo "[EVAL][ERROR] Missing CWEval generation metadata at $EVAL_INFO_FILE" >> $LOG_FILE
      exit 1
    fi
    EVAL_PATH=$(cat "$EVAL_INFO_FILE")
    if [ ! -d "$EVAL_PATH" ]; then
      echo "[EVAL][ERROR] CWEval eval path $EVAL_PATH does not exist" >> $LOG_FILE
      exit 1
    fi

    pushd repos-archive/CWEval > /dev/null
    PYTHONPATH=$(pwd):$PYTHONPATH python3 cweval/evaluate.py pipeline \
      --eval_path "$EVAL_PATH" --num_proc ${CWEVAL_NUM_PROC:-4} --docker True >> $LOG_FILE
    popd > /dev/null

    RES_ALL="$EVAL_PATH/res_all.json"
    if [ -f "$RES_ALL" ]; then
      cp "$RES_ALL" "experiments/cweval/$MODEL/$METHOD/res_all.json"
    fi
    ;;
  scplt)
    LOG_FILE="${LOG_DIR}/${MODEL}_seccodeplt_evaluation.log"
    echo "[EVAL] SecCodePLT ${MODEL} ${METHOD}" >> $LOG_FILE
    python3 src/benchmarks/seccodeplt/evaluate.py --model "$MODEL" --method "$METHOD" >> $LOG_FILE
    ;;
  bax)
    LOG_FILE="${LOG_DIR}/${MODEL}_baxbench_evaluation.log"
    echo "[EVAL] BaxBench ${MODEL} ${METHOD}" >> $LOG_FILE
    python3 src/benchmarks/baxbench/evaluate.py --model "$MODEL" --method "$METHOD" >> $LOG_FILE
    ;;
    
  *)
    echo "Unknown benchmark: $BENCHMARK"
    exit 1
    ;;
esac
echo "[FINISH] Evaluation completed for $BENCHMARK with model $MODEL using method $METHOD" >> $LOG_FILE
echo "[Finish Time]: $(date +"%Y-%m-%d %H:%M:%S")" >> $LOG_FILE
