#!/bin/bash
set -euxo pipefail

MODEL_DIR=$1
OUTPUT_DIR=$2
REVISION=$3
FILENAME_BASE=$OUTPUT_DIR/$(date --utc +%Y%m%d%H%M%S)_$REVISION

for SIZE in 32 256; do
    for FILES in 64 512; do
        MODEL=${SIZE}gb_${FILES}files
        MODEL_PATH=$MODEL_DIR/$MODEL
        mkdir -p "$MODEL_PATH"
        SIZE_BYTES=$((SIZE * 1024 * 1024 * 1024))
        hatch run bench.py3.11:generate dir --root "$MODEL_PATH" -n "$FILES" "$SIZE_BYTES"
        hatch run bench.py3.11:python benchmarks/time_serialize.py "$MODEL_PATH" \
            --output="${FILENAME_BASE}_${MODEL}.json"
        rm -r "${MODEL_PATH}"
    done
done


