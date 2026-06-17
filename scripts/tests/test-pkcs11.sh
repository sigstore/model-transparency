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

# The SoftHSM PKCS #11 module is in a special path on Ubuntu
for p in "/usr/lib/pkcs11" "/usr/lib64/pkcs11" "/usr/lib/softhsm"; do
	add_options+=" --module-paths ${p}"
done

if ! softhsm_setup getpubkey &>"${pub_key}"; then
	echo -e "Could not get public key:\n${msg}"
	echo "${pub_key}"
	exit 77
fi

if ! python -m model_signing sign pkcs11-key \
	--signature "${model_sig}" \
	--pkcs11_uri "${pkcs11uri}" \
	${add_options:+${add_options}} \
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

if type -P openssl >/dev/null; then
	pub_key_cert=${TMPDIR}/pubkey-cert.pem
	ca_key="${TMPDIR}/ca-key.pem"
	ca_cert="${TMPDIR}/ca-cert.pem"
	v3ext="${TMPDIR}/v3.ext"

	if ! err=$(openssl req \
		-new \
		-x509 \
		-nodes \
		-days 3650\
		-subj "/CN=MyRootCA" \
		-keyout "${ca_key}" \
		-addext "basicConstraints=critical,CA:TRUE" \
		-addext "keyUsage=critical,keyCertSign" \
		-out "${ca_cert}" 2>&1); then
		echo "Could not create CA certificate."
		echo "${err}"
		exit 77
	fi
	echo "Created CA."

	cat <<- _EOF_ > "${v3ext}"
	keyUsage=critical, digitalSignature
	_EOF_

	if ! err=$(openssl x509 \
		-new \
		-CAkey "${ca_key}" \
		-CA "${ca_cert}" \
		-force_pubkey "${pub_key}" \
		-subj "/CN=MyCery" \
		-extfile "${v3ext}" \
		-out "${pub_key_cert}" 2>&1); then
		echo "Could not create certificate for HSM public key."
		echo "${err}"
		exit 77
	fi
	echo "Signed HSM public key with CA key."

	if ! python -m model_signing sign pkcs11-certificate \
		--signature "${model_sig}" \
		--pkcs11_uri "${pkcs11uri}" \
		--signing_certificate "${pub_key_cert}" \
		--certificate_chain "${pub_key_cert}" \
		${add_options:+${add_options}} \
		"${model_path}"; then
		echo "Could not sign with pkcs11-certificate method."
		exit 77
	fi

	if ! python -m model_signing verify certificate \
		--signature "${model_sig}" \
		--certificate_chain "${ca_cert}" \
		"${model_path}"; then
		echo "Could not verify signature created with pkcs11-certificate method."
		exit 77
	fi
fi

exit 0
