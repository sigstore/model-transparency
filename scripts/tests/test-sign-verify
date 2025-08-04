#!/usr/bin/env bash

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

echo "Testing 'sign/verify key'"

if ! python -m model_signing \
	sign key \
	--signature "${sigfile}" \
	--private_key ./keys/certificate/signing-key.pem \
	--ignore-paths "${ignorefile}" \
	"${TMPDIR}"; then
	echo "Error: 'sign key' failed"
	exit 1
fi

if ! python -m model_signing \
	verify key \
	--signature "${sigfile}" \
	--public_key ./keys/certificate/signing-key-pub.pem \
	--ignore-paths "${ignorefile}" \
	"${TMPDIR}"; then
	echo "Error: 'verify key' failed"
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

echo
echo "Testing 'sign/verify' certificate"

if ! python -m model_signing \
	sign certificate \
	--signature "${sigfile}" \
	--private_key ./keys/certificate/signing-key.pem \
	--signing_certificate ./keys/certificate/signing-key-cert.pem \
	--certificate_chain ./keys/certificate/int-ca-cert.pem \
	--ignore-paths "${ignorefile}" \
	"${TMPDIR}"; then
	echo "Error: 'sign certificate' failed"
	exit 1
fi

if ! python -m model_signing \
	verify certificate \
	--signature "${sigfile}" \
	--certificate_chain ./keys/certificate/ca-cert.pem \
	--ignore-paths "${ignorefile}" \
	"${TMPDIR}"; then
	echo "Error: 'verify certificate' failed"
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
check_model_name "${sigfile}" "$(basename "${TMPDIR}")"

# Enter the model directory and sign and verify there
pushd "${TMPDIR}" &>/dev/null || exit 1

echo
echo "Testing 'sign key' when in model directory"

if ! python -m model_signing \
	sign key \
	--signature "$(basename "${sigfile}")" \
	--private_key "${DIR}/keys/certificate/signing-key.pem" \
	--ignore-paths "$(basename "${ignorefile}")" \
	. ; then
	echo "Error: 'sign key' failed"
	exit 1
fi

if ! python -m model_signing \
	verify key \
	--signature "$(basename "${sigfile}")" \
	--public_key "${DIR}/keys/certificate/signing-key-pub.pem" \
	--ignore-paths "$(basename "${ignorefile}")" \
	. ; then
	echo "Error: 'verify key' failed"
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
check_model_name "${sigfile}" "$(basename "${TMPDIR}")"

echo
echo "Testing 'sign/verify' certificate when in model directory"

if ! python -m model_signing \
	sign certificate \
	--signature "$(basename "${sigfile}")" \
	--private_key "${DIR}/keys/certificate/signing-key.pem" \
	--signing_certificate "${DIR}/keys/certificate/signing-key-cert.pem" \
	--certificate_chain "${DIR}/keys/certificate/int-ca-cert.pem" \
	--ignore-paths "$(basename "${ignorefile}")" \
	. ; then
	echo "Error: 'sign certificate' failed"
	exit 1
fi

if ! python -m model_signing \
	verify certificate \
	--signature "$(basename "${sigfile}")" \
	--certificate_chain "${DIR}/keys/certificate/ca-cert.pem" \
	--ignore-paths "$(basename "${ignorefile}")" \
	. ; then
	echo "Error: 'verify certificate' failed"
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
check_model_name "${sigfile}" "$(basename "${TMPDIR}")"

echo
echo "Creating a symlink, that is not part of the signature, to make signature verification fail (1)"

echo "foo" > symlinked
ln -s symlinked symlink

if python -m model_signing \
	verify certificate \
	--signature "$(basename "${sigfile}")" \
	--certificate_chain "${DIR}/keys/certificate/ca-cert.pem" \
	--ignore-paths "$(basename "${ignorefile}")" \
	. ; then
	echo "Error: 'verify certificate' succeeded after new file (symlink) was created"
	exit 1
fi

# This should pass without having to pass --allow_symlinks since the symlink
# will be ignored
echo
echo "Pass signature verification by ignoring any unsigned files or symlinks"
if ! python -m model_signing \
	verify certificate \
	--signature "$(basename "${sigfile}")" \
	--certificate_chain "${DIR}/keys/certificate/ca-cert.pem" \
	--ignore-paths "$(basename "${ignorefile}")" \
	--ignore_unsigned_files \
	. ; then
	echo "Error: 'verify certificate' failed with --ignore_unsigned_files while passing --allow_symlinks"
	exit 1
fi


rm -f symlinked symlink

echo
echo "Testing 'sign/verify' certificate when in subdir of model directory and using '..'"

rm -f "$(basename "${sigfile}")"
mkdir subdir

# Create a symlink'ed file
echo "foo" > subdir/symlinked
ln -s subdir/symlinked symlink

pushd subdir 1>/dev/null || exit 1

if ! python -m model_signing \
	sign certificate \
	--signature "../$(basename "${sigfile}")" \
	--private_key "${DIR}/keys/certificate/signing-key.pem" \
	--signing_certificate "${DIR}/keys/certificate/signing-key-cert.pem" \
	--certificate_chain "${DIR}/keys/certificate/int-ca-cert.pem" \
	--ignore-paths "../$(basename "${ignorefile}")" \
	--allow_symlinks \
	.. ; then
	echo "Error: 'sign certificate' failed"
	exit 1
fi

popd 1>/dev/null || exit 1   # exit subdir

if ! python -m model_signing \
	verify certificate \
	--signature "$(basename "${sigfile}")" \
	--certificate_chain "${DIR}/keys/certificate/ca-cert.pem" \
	--ignore-paths "$(basename "${ignorefile}")" \
	--allow_symlinks \
	. ; then
	echo "Error: 'verify certificate' failed"
	exit 1
fi

# Check which files are part of signature
res=$(get_signed_files "${sigfile}")
exp='["signme-1","signme-2","subdir/symlinked","symlink"]'
if [ "${res}" != "${exp}" ]; then
	echo "Error: Unexpected files were signed"
	echo "Expected: ${exp}"
	echo "Actual  : ${res}"
	exit 1
fi
check_model_name "${sigfile}" "$(basename "${TMPDIR}")"

echo
echo "Creating a symlink, that is not part of the signature, to make signature verification fail (2)"

# Create another symlinked file
ln -s subdir/symlinked symlink2

echo
echo "Fail signature verification by NOT ignoring any unsigned (symlinks)"
if python -m model_signing \
	verify certificate \
	--signature "$(basename "${sigfile}")" \
	--certificate_chain "${DIR}/keys/certificate/ca-cert.pem" \
	--ignore-paths "$(basename "${ignorefile}")" \
	--allow_symlinks \
	. ; then
	echo "Error: 'verify certificate' succeeded after new file (symlink) was created"
	exit 1
fi

echo
echo "Pass signature verification by ignoring any unsigned files"
if ! python -m model_signing \
	verify certificate \
	--signature "$(basename "${sigfile}")" \
	--certificate_chain "${DIR}/keys/certificate/ca-cert.pem" \
	--ignore-paths "$(basename "${ignorefile}")" \
	--allow_symlinks \
	--ignore_unsigned_files \
	. ; then
	echo "Error: 'verify certificate' failed with --ignore_unsigned_files to ignore symlink"
	exit 1
fi

rm symlink2

# Create a simple new file
echo
echo "Creating a regular file that is not part of the signature"
touch newfile

echo
echo "Fail signature verification by NOT ignoring any unsigned files (symlinks)"
if python -m model_signing \
	verify certificate \
	--signature "$(basename "${sigfile}")" \
	--certificate_chain "${DIR}/keys/certificate/ca-cert.pem" \
	--ignore-paths "$(basename "${ignorefile}")" \
	--allow_symlinks \
	. ; then
	echo "Error: 'verify certificate' succeeded after new file was created"
	exit 1
fi

echo
echo "Pass signature verification by ignoring any unsigned files"
if ! python -m model_signing \
	verify certificate \
	--signature "$(basename "${sigfile}")" \
	--certificate_chain "${DIR}/keys/certificate/ca-cert.pem" \
	--ignore-paths "$(basename "${ignorefile}")" \
	--allow_symlinks \
	--ignore_unsigned_files \
	. ; then
	echo "Error: 'verify certificate' failed with --ignore_unsigned_files to ignore regular file"
	exit 1
fi

popd 1>/dev/null || exit 1
