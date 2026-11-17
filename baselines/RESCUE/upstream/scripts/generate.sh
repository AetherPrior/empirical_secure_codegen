#!/bin/bash

MODEL=$1
METHOD=$2
BENCHMARK=$3

if [ -z "$MODEL" ] || [ -z "$METHOD" ] || [ -z "$BENCHMARK" ]; then
  echo "Usage: $0 <model_name> <method> <benchmark>"
  echo "Benchmark options: bcb, lcb, hep, cgp, cwe, scplt (SecCodePLT), bax (BaxBench)"
  exit 1
fi


echo "[START] Generating for $BENCHMARK with model $MODEL using method $METHOD"
echo "[Start Time]: $(date +"%Y-%m-%d %H:%M:%S")"

export PYTHONPATH=$(pwd)
source .venv/bin/activate

# Generation
case $BENCHMARK in
  bcb)
    python3 src/benchmarks/bcb/exec_benchmark.py --model $MODEL --method $METHOD
    ;;
  lcb)
    python3 src/benchmarks/lcb/exec_benchmark.py --model $MODEL --method $METHOD
    ;;
  hep)
    python3 src/benchmarks/hep/exec_benchmark.py --model $MODEL --method $METHOD
    ;;
  cgp)
    python3 src/benchmarks/cgp/exec_benchmark.py --model $MODEL --method $METHOD
    ;;
  cwe)
    python3 src/benchmarks/cweval/exec_benchmark.py --model $MODEL --method $METHOD
    ;;
  scplt)
    python3 src/benchmarks/seccodeplt/exec_benchmark.py --model $MODEL --method $METHOD
    ;;
  bax)
    python3 src/benchmarks/baxbench/exec_benchmark.py --model $MODEL --method $METHOD
    ;;
  *)
    echo "Unknown benchmark: $BENCHMARK"
    exit 1
    ;;
esac

echo "[FINISH] Generation completed for $BENCHMARK with model $MODEL using method $METHOD"
echo "[Finish Time]: $(date +"%Y-%m-%d %H:%M:%S")"
