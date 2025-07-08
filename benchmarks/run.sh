#!/bin/bash
set -euxo pipefail

MODEL=$1
MODEL_DIR=$2
MODEL_PATH=$MODEL_DIR/$(echo $MODEL | cut --delimiter='/' --fields=2-)
OUTPUT_FILE=$3

huggingface-cli download $MODEL --local-dir "$MODEL_PATH"
hatch run bench.py3.11:python benchmarks/time_serialize.py "$MODEL_PATH" \
    --output=$OUTPUT_FILE
