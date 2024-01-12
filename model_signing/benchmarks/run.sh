#!/bin/bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 identity-provider identity output_path <cleanup>"
    echo "Example: $0 https://accounts.google.com myemail@gmail.com"
    exit 1
fi

time_cmd() {
    local cmd="$1"
    local arguments="$2"
    # shellcheck disable=SC2086 # We want word splitting
    { time "${cmd}" ${arguments} >/dev/null; } 2>&1 | grep real | cut -f2
}

run() {
    local model_name="$1"
    local model_path="$2"
    local model_init="$3"

    echo "Initializing ${model_name} ..."
    eval "${model_init}"
    # Replace the '/' character.
    model_name="${model_name/\//_}"

    echo "Running sign / verify for ${model_name} ..."
    results["${model_name}[size]"]=$(du -hs "${model_path}" | cut -f1)
    results["${model_name}[sign_time]"]=$(time_cmd python3 "main.py sign --path ${model_path}")
    results["${model_name}[verify_time]"]=$(time_cmd python3 "main.py verify --path ${model_path} --identity-provider ${identity_provider} --identity ${identity}")
    if [[ "${cleanup}" == "true" ]]; then
        rm -rf "${model_path}" "${model_path}.sig" 2>/dev/null || true
    fi
}

# shellcheck disable=SC2317 # Called via model_init().
download_github_repository() {
    local repository="$1"
    local model_path="$2"

    # We download the zip which does _not_ contain the .git folder.
    wget "https://github.com/${repository}/archive/main.zip" -O "${model_path}".zip
    mkdir -p "${model_path}"
    shopt -s dotglob
    cd "${model_path}" && unzip ../"${model_path}".zip && rm ../"${model_path}".zip && mv "${model_path}"-main/* . && rmdir "${model_path}"-main/ && cd -
    shopt -u dotglob
}

# shellcheck disable=SC2317 # Called via model_init().
download_hf_repository() {
    local repository="$1"
    local model_path="$2"
    git clone --depth=1 "https://huggingface.co/${repository}" "${model_path}"
    # We delete the .git folder.
    rm -rf "${model_path}"/.git
}

# User inputs.
identity_provider="$1"
identity="$2"
cleanup=""

if [ "$#" -eq 3 ]; then
    cleanup="$3"
fi

echo
echo "INFO: Be patient, this will take a few minutes!"
echo

# Variable holding results.
declare -A results

# Init the environment.
if [[ ! -d "test_env/" ]]; then
    python3 -m venv test_env
fi
# shellcheck disable=SC1091 # We have access to source=test_env/bin/activate.
source test_env/bin/activate
python3 -m pip install --require-hashes -r install/requirements_Linux.txt

# =========================================
#               Warm up!
# =========================================
# We need to have the identity in the environment, so perform one signature.
file=$(mktemp)
python3 main.py sign --path "${file}"
python3 main.py verify --path "${file}" --identity-provider "${identity_provider}" --identity "${identity}"
rm "${file}" "${file}.sig"

# =========================================
#       PyTorch YOLOP model
# =========================================
model_name=hustvl/YOLOP
model_path=$(echo "${model_name}" | cut -d/ -f2)
# shellcheck disable=SC2317 # Reachable via run() call.
model_init() {
    if [[ ! -d "${model_path}" ]]; then
        download_github_repository "${model_name}" "${model_path}"
    fi
}
run "${model_name}" "${model_path}" model_init

# =========================================
#       ONNX Roberta-base-11 model
# =========================================
model_name=roberta-base-11
model_path="${model_name}.onnx"
# shellcheck disable=SC2317 # Reachable via run() call.
model_init() {
    if [[ ! -f "${model_path}" ]]; then
        wget "https://github.com/onnx/models/tree/857a3434216bd6f2be1ea1ff045fb94a437cbe10/text/machine_comprehension/roberta/model/${model_name}.onnx"
    fi
}
run "${model_name}" "${model_path}" model_init

# =========================================
#       tfhub bertseq2seq model
# =========================================
model_name=bertseq2seq
model_path="${model_name}"
# shellcheck disable=SC2317 # Reachable via run() call.
model_init() {
    if [[ ! -d "${model_path}" ]]; then
        wget "https://tfhub.dev/google/bertseq2seq/bert24_en_de/1?tf-hub-format=compressed" -O "${model_path}".tgz
        mkdir -p "${model_path}"
        cd "${model_path}" && tar xvzf ../"${model_path}".tgz && rm ../"${model_path}".tgz && cd -
    fi
}
run "${model_name}" "${model_path}" model_init

# =========================================
#       Huggingface bert base model
#       (Tensorflow and PyTorch)
# =========================================
model_name=bert-base-uncased
model_path="${model_name}"
# shellcheck disable=SC2317 # Reachable via run() call.
model_init() {
    if [[ ! -d "${model_path}" ]]; then
        download_hf_repository "${model_name}" "${model_path}"
    fi
}
run "${model_name}" "${model_path}" model_init

# =========================================
#           PyTorch falcon-7b model
# =========================================
model_name=tiiuae/falcon-7b
model_path=$(echo "${model_name}" | cut -d/ -f2)
# shellcheck disable=SC2317 # Reachable via run() call.
model_init() {
    if [[ ! -d "${model_path}" ]]; then
        download_hf_repository "${model_name}" "${model_path}"
    fi
}
run "${model_name}" "${model_path}" model_init


echo
echo "===== RESULTS ======"
# NOTE: Requires bash >= 4.4.
echo "results:" "${!results[@]}"
mapfile -d '' sorted < <(printf '%s\0' "${!results[@]}" | sort -z)
for key in "${sorted[@]}"; do
    echo "$key = ${results[${key}]}"
done

deactivate
