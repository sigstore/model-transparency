#!/usr/bin/env bash

TMPDIR=$(mktemp -d) || exit 1
MODELDIR="${TMPDIR}/model"

signfile1="${MODELDIR}/signme-1"
signfile2="${MODELDIR}/signme-2"
ignorefile="${MODELDIR}/ignore"

cleanup()
{
	rm -rf "${TMPDIR}"
}
trap cleanup EXIT QUIT

mkdir "${MODELDIR}" || exit 1
echo "signme-1" > "${signfile1}"
echo "signme-2" > "${signfile2}"
echo "ignore" > "${ignorefile}"

sigfile_key="${TMPDIR}/model.sig-key"
sigfile_certificate="${TMPDIR}/model.sig-certificate"
sigfile_sigstore="${TMPDIR}/model.sig-sigstore"

TOKENPROJ="${TMPDIR}/tokenproj"
mkdir -p "${TOKENPROJ}" || exit 1
token_file="${TOKENPROJ}/oidc-token.txt"

VENV="${TMPDIR}/venv"


# Create a signature with the currently active library

echo -n "Using model_signing tool: "
type -P model_signing

echo -n "Use version of model_signing tool for signing: "
model_signing --version

echo

echo "Signing with 'key' method"

if ! python -m model_signing \
	sign key \
	--signature "${sigfile_key}" \
	--private_key ./keys/certificate/signing-key.pem \
	--ignore-paths "${ignorefile}" \
	"${MODELDIR}" || \
  test ! -f "${sigfile_key}"; then
	echo "Error: 'sign key' failed"
	exit 1
fi

echo "Signing with 'certificate' method"

if ! python -m model_signing \
	sign certificate \
	--signature "${sigfile_certificate}" \
	--private_key ./keys/certificate/signing-key.pem \
	--signing_certificate ./keys/certificate/signing-key-cert.pem \
	--certificate_chain ./keys/certificate/int-ca-cert.pem \
	--ignore-paths "${ignorefile}" \
	"${MODELDIR}" || \
  test ! -f "${sigfile_certificate}"; then
	echo "Error: 'sign certificate' failed"
	exit 1
fi

echo "Getting OIDC test-token for sigstore signing"
if ! out=$(git clone \
	--single-branch \
	--branch current-token \
	--depth 1 \
	https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon \
	"${TOKENPROJ}" 2>&1);
then
	echo "git clone failed"
	echo "${out}"
	exit 1
fi

echo "Signing with 'sigstore' method"
if ! python -m model_signing \
	sign sigstore \
	--signature "${sigfile_sigstore}" \
	--identity_token "$(cat "${token_file}")" \
	--ignore-paths "${ignorefile}" \
	"${MODELDIR}" || \
  test ! -f ${sigfile_sigstore}; then
	echo "Error: 'sign sigstore' failed"
	exit 1
fi

# Setup and activate a venv
echo -e "\nSetting up $(python --version) venv"

python -m venv "${VENV}" || exit 1
source "${VENV}/bin/activate"

echo -e "Done\n"

# Install the following versions from pypi
for version in v1.0.1 v1.0.0 v0.3.1 v0.3.0; do

	if ! out=$(pip install "model-signing==${version}" 2>&1); then
		echo "pip install failed"
		echo "${out}"
		exit 1
	fi

	#Force usage of sigstore v3.6.5 on older model-signing versions
	case "${version}" in
	v1.0.1|v1.0.0|v0.3.1|v0.3.0)
		if ! out=$(pip install sigstore==v3.6.5 2>&1); then
			echo "pip install of sigstore v3.6.5 failed"
			echo "${out}"
			exit 1
		fi
		;;
	*)
	esac

	echo -n "Testing signature verification with version from pypi: "
	model_signing --version

	echo "Testing 'verify key' method"
	if ! out=$(python -m model_signing \
		verify key \
		--signature "${sigfile_key}" \
		--public_key ./keys/certificate/signing-key-pub.pem \
		--ignore-paths "${ignorefile}" \
		"${MODELDIR}" 2>&1); then
		echo "Error: 'verify key' failed with ${version}"
		echo "${out}"
		exit 1
	fi
	if ! grep -q "succeeded" <<< "${out}"; then
		echo "verification failed:"
		echo "${out}"
		exit 1
	fi

	case "${version}" in
	v0.3.1 | v0.3.0)
		# cannot verify
		echo "Skipping 'verify certificate' method"
		;;
	*)
		echo "Testing 'verify certificate' method"
		if ! out=$(python -m model_signing \
			verify certificate \
			--signature "${sigfile_certificate}" \
			--certificate_chain ./keys/certificate/ca-cert.pem \
			--ignore-paths "${ignorefile}" \
			"${MODELDIR}" 2>&1); then
			echo "Error: 'verify certificate' failed with ${version}"
			echo "${out}"
			exit 1
		fi
		if ! grep -q "succeeded" <<< "${out}"; then
			echo "verification failed:"
			echo "${out}"
			exit 1
		fi
	esac

	echo "Testing 'verify sigstore' method"
	if ! out=$(python -m model_signing \
		verify sigstore \
		--signature "${sigfile_sigstore}" \
		--identity https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main \
		--identity_provider https://token.actions.githubusercontent.com \
		--ignore-paths "${ignorefile}" \
		"${MODELDIR}" 2>&1); then
		echo "Error: 'verify sigstore' failed with ${version}"
		echo "${out}"
		exit 1
	fi
	if ! grep -q "succeeded" <<< "${out}"; then
		echo "verification failed:"
		echo "${out}"
		exit 1
	fi

	# Check against pre-created signatures
	# v represents version of the library that created a signature in the past
	for v in v1.1.0 v1.0.1 v1.0.0 v0.3.1 v0.2.0; do

		# key method
		modeldir=${v}-elliptic-key
		modeldir_sign=${modeldir}

		case "${version}-${v}" in
		v0.3.1-v1.0.1|v0.3.1-v1.1.0)
			# v0.3.1 cannot verify signatures created by v1.0.1
			;;
		*-v0.3.1|*-v1.0.0)
			# These versions signed only a single file
			modeldir_sign="${modeldir}/signme-1"
			;&  # fallthrough
		*)
			if [ -d "${modeldir}" ]; then
				echo "Testing 'verify key' method with signature created by ${v}"
				if ! out=$(python -m model_signing \
					verify key \
					--signature "${modeldir}/model.sig" \
					--public_key ./keys/certificate/signing-key-pub.pem \
					--ignore-paths "${modeldir}/ignore-me" \
					"${modeldir_sign}" 2>&1); then
					echo "Error: 'verify key' failed with ${version} on ${modeldir}"
					echo "${out}"
					exit 1
				fi
				if ! grep -q "succeeded" <<< "${out}"; then
					echo "verification failed on ${modeldir}:"
					echo "${out}"
					exit 1
				fi
			fi
			;;
		esac

		# certificate method
		modeldir=${v}-certificate

		case "${version}-${v}" in
		v0.3.0-*|v0.3.1-*|v1.0.0-v0.2.0)
			# cannot verify
			;;
		*)
			if [ -d "${modeldir}" ]; then
				echo "Testing 'verify certificate' method with signature created by ${v}"
				if ! out=$(python -m model_signing \
					verify certificate \
					--signature "${modeldir}/model.sig" \
					--certificate_chain ./keys/certificate/ca-cert.pem \
					--ignore-paths "${modeldir}/ignore-me" \
					"${modeldir}" 2>&1); then
					echo "Error: 'verify certificate' failed with ${version} on ${modeldir}"
					echo "${out}"
					exit 1
				fi
				if ! grep -q "succeeded" <<< "${out}"; then
					echo "verification failed on ${modeldir}:"
					echo "${out}"
					exit 1
				fi
			fi
			;;
		esac

		# sigstore method
		modeldir=${v}-sigstore

		case "${version}-${v}" in
		v0.3.1-v1.1.0|v0.3.1-v1.0.1|v0.3.1-v0.3.1|v0.3.1-v1.0.0)
			# cannot verify
			;;
		*)
			if [ -d "${modeldir}" ]; then
				echo "Testing 'verify sigstore' method with signature created by ${v}"
				if ! out=$(python -m model_signing \
					verify sigstore \
					--signature "${modeldir}/model.sig" \
					--identity_provider https://sigstore.verify.ibm.com/oauth2 \
					--identity stefanb@us.ibm.com \
					--ignore-paths "${modeldir}/ignore-me" \
					"${modeldir}" 2>&1); then
					echo "Error: 'verify sigstore' failed with ${version} on ${modeldir}"
					echo "${out}"
					exit 1
				fi
				if ! grep -q "succeeded" <<< "${out}"; then
					echo "verification failed on ${modeldir}:"
					echo "${out}"
					exit 1
				fi
			fi
			;;
		esac
	done

	echo
done

# deactivate the venv
deactivate

exit 0
