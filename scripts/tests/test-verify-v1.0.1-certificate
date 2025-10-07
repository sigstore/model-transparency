#!/usr/bin/env bash

echo "Testing 'verify certificate'"
if ! python -m model_signing \
	verify certificate \
	--ignore-paths ./v1.0.1-certificate/ignore-me \
	--signature ./v1.0.1-certificate/model.sig \
	--certificate_chain ./keys/certificate/ca-cert.pem \
	./v1.0.1-certificate/; then
	echo "Error: 'verify certificate' failed on v1.0.1"
	exit 1
fi

exit 0
