#!/usr/bin/env bash

echo "Testing 'verify certificate'"
if ! python -m model_signing \
	verify certificate \
	--signature ./v1.0.0-certificate/model.sig \
	--certificate_chain ./keys/certificate/ca-cert.pem \
	./v1.0.0-certificate/; then
	echo "Error: 'verify certificate' failed on v1.0.0"
	exit 1
fi

exit 0
