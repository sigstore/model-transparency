#!/usr/bin/env bash

DIR=$(dirname "$0")

PATH=$PATH:${PWD}/${DIR}
TMPDIR=$(mktemp -d) || exit 1

cleanup() {
	softhsm_setup teardown &>/dev/null
	rm -rf "${TMPDIR}"
}
trap cleanup SIGTERM EXIT

if ! msg=$(softhsm_setup setup); then
	echo -e "Could not setup softhsm:\n${msg}"
	exit 77
fi
pkcs11uri=$(echo "${msg}" | sed -n 's|^keyuri: \(.*\)|\1|p')

model_sig=${TMPDIR}/model.sig
pub_key=${TMPDIR}/pubkey.pem
model_path=${TMPDIR}

if ! msg=$(softhsm_setup getpubkey > "${pub_key}"); then
	echo -e "Could not get public key:\n${msg}"
	exit 77
fi

if ! python -m model_signing sign pkcs11-key \
	--signature "${model_sig}" \
	--pkcs11_uri "${pkcs11uri}" \
	"${model_path}"; then
	echo "Could not sign."
	exit 77
fi

if ! python -m model_signing verify key \
	--signature "${model_sig}" \
	--public_key "${pub_key}"  \
	"${model_path}"; then
	echo "Could not verify signature."
	exit 77
fi

exit 0
