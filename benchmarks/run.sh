#!/bin/bash
set -euxo pipefail

MODEL_DIR=$1
OUTPUT_DIR=$2
REVISION=$3
FILENAME_BASE=$OUTPUT_DIR/$(date --utc +%Y%m%d%H%M%S)_$REVISION

for SIZE in 32 48 128; do
    MODEL=${SIZE}gb
    MODEL_PATH=$MODEL_DIR/$MODEL
    mkdir -p MODEL_PATH

    # simulate a handful of small metadata files in the repository
    hatch run bench.py3.11:generate dir --root "$MODEL_PATH" -n 8 16384
    # followed by model shards which are 8GiB each
    N=$((${SIZE}/8))
    SIZE_BYTES=$(($SIZE * 1024 * 1024 * 1024))
    hatch run bench.py3.11:generate dir --root "$MODEL_PATH" -n "$N" "$SIZE_BYTES"

    hatch run bench.py3.11:python benchmarks/time_serialize.py "$MODEL_PATH" \
        --output="${FILENAME_BASE}_${MODEL}.json"
done


