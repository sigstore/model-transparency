#!/usr/bin/env bash

echo "Testing 'sign/verify ml-dsa'"

DIR=${PWD}/$(dirname "$0")
TMPDIR=$(mktemp -d) || exit 1
signfile1="${TMPDIR}/signme-1"
signfile2="${TMPDIR}/signme-2"
ignorefile="${TMPDIR}/ignore"
sigfile="${TMPDIR}/model.sig"
echo "signme-1" > "${signfile1}"
echo "signme-2" > "${signfile2}"
echo "ignore" > "${ignorefile}"

cleanup()
{
	rm -rf "${TMPDIR}"
}
trap cleanup EXIT QUIT

source "${DIR}/functions"

# Test ML-DSA-65 (default variant)
echo "Testing ML-DSA-65 signing and verification"

if ! python -m model_signing \
	sign ml-dsa \
	--signature "${sigfile}" \
	--private_key ./keys/ml-dsa/signing-key.priv \
	--ignore-paths "${ignorefile}" \
	"${TMPDIR}"; then
	echo "Error: 'sign ml-dsa' failed"
	exit 1
fi

if ! python -m model_signing \
	verify ml-dsa \
	--signature "${sigfile}" \
	--public_key ./keys/ml-dsa/signing-key.pub \
	--ignore-paths "${ignorefile}" \
	"${TMPDIR}"; then
	echo "Error: 'verify ml-dsa' failed"
	exit 1
fi

# Check which files are part of signature
res=$(get_signed_files "${sigfile}")
exp='["signme-1","signme-2"]'
if [ "${res}" != "${exp}" ]; then
	echo "Error: Unexpected files were signed"
	echo "Expected: ${exp}"
	echo "Actual  : ${res}"
	exit 1
fi

echo "✓ ML-DSA-65 sign/verify test passed"

# Test ML-DSA-44 (smaller keys)
echo
echo "Testing ML-DSA-44 signing and verification"

# Generate temporary ML-DSA-44 keys
TMPKEY_44_PRIV="${TMPDIR}/ml_dsa_44.priv"
TMPKEY_44_PUB="${TMPDIR}/ml_dsa_44.pub"

python3 -c "
from dilithium_py.ml_dsa import ML_DSA_44
import pathlib
pk, sk = ML_DSA_44.keygen()
pathlib.Path('${TMPKEY_44_PRIV}').write_bytes(sk)
pathlib.Path('${TMPKEY_44_PUB}').write_bytes(pk)
"

if ! python -m model_signing \
	sign ml-dsa \
	--signature "${sigfile}" \
	--private_key "${TMPKEY_44_PRIV}" \
	--variant ML_DSA_44 \
	--ignore-paths "${ignorefile}" \
	"${TMPDIR}"; then
	echo "Error: 'sign ml-dsa' with ML_DSA_44 failed"
	exit 1
fi

if ! python -m model_signing \
	verify ml-dsa \
	--signature "${sigfile}" \
	--public_key "${TMPKEY_44_PUB}" \
	--variant ML_DSA_44 \
	--ignore-paths "${ignorefile}" \
	"${TMPDIR}"; then
	echo "Error: 'verify ml-dsa' with ML_DSA_44 failed"
	exit 1
fi

echo "✓ ML-DSA-44 sign/verify test passed"

# Test ML-DSA-87 (larger keys)
echo
echo "Testing ML-DSA-87 signing and verification"

# Generate temporary ML-DSA-87 keys
TMPKEY_87_PRIV="${TMPDIR}/ml_dsa_87.priv"
TMPKEY_87_PUB="${TMPDIR}/ml_dsa_87.pub"

python3 -c "
from dilithium_py.ml_dsa import ML_DSA_87
import pathlib
pk, sk = ML_DSA_87.keygen()
pathlib.Path('${TMPKEY_87_PRIV}').write_bytes(sk)
pathlib.Path('${TMPKEY_87_PUB}').write_bytes(pk)
"

if ! python -m model_signing \
	sign ml-dsa \
	--signature "${sigfile}" \
	--private_key "${TMPKEY_87_PRIV}" \
	--variant ML_DSA_87 \
	--ignore-paths "${ignorefile}" \
	"${TMPDIR}"; then
	echo "Error: 'sign ml-dsa' with ML_DSA_87 failed"
	exit 1
fi

if ! python -m model_signing \
	verify ml-dsa \
	--signature "${sigfile}" \
	--public_key "${TMPKEY_87_PUB}" \
	--variant ML_DSA_87 \
	--ignore-paths "${ignorefile}" \
	"${TMPDIR}"; then
	echo "Error: 'verify ml-dsa' with ML_DSA_87 failed"
	exit 1
fi

echo "✓ ML-DSA-87 sign/verify test passed"

# Test encrypted keys with password
echo
echo "Testing ML-DSA with password-protected keys"

ENCRYPTED_KEY="${TMPDIR}/encrypted.priv"

# Encrypt the key using ml_dsa_key_tool.py
python3 ../ml_dsa_key_tool.py encrypt \
	./keys/ml-dsa/signing-key.priv \
	--output "${ENCRYPTED_KEY}" \
	--password "test_password_123"

if ! python -m model_signing \
	sign ml-dsa \
	--signature "${sigfile}" \
	--private_key "${ENCRYPTED_KEY}" \
	--password "test_password_123" \
	--ignore-paths "${ignorefile}" \
	"${TMPDIR}"; then
	echo "Error: 'sign ml-dsa' with encrypted key failed"
	exit 1
fi

if ! python -m model_signing \
	verify ml-dsa \
	--signature "${sigfile}" \
	--public_key ./keys/ml-dsa/signing-key.pub \
	--ignore-paths "${ignorefile}" \
	"${TMPDIR}"; then
	echo "Error: 'verify ml-dsa' after encrypted key signing failed"
	exit 1
fi

echo "✓ ML-DSA password-protected key test passed"

echo
echo "All ML-DSA sign/verify tests passed!"

exit 0
