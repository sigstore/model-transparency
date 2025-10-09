#!/usr/bin/env bash

echo "Testing 'verify certificate'"
if ! python -m model_signing \
	verify certificate \
	--signature ./v0.2.0-certificate/model.sig \
	--certificate_chain ./keys/certificate/ca-cert.pem \
	./v0.2.0-certificate/; then
	echo "Error: 'verify certificate' failed on v0.2.0"
	exit 1
fi

exit 0
