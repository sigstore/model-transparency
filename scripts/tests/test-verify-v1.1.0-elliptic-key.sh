#!/usr/bin/env bash

echo "Testing 'verify key'"
if ! python -m model_signing \
	verify key \
	--ignore-paths ./v1.1.0-elliptic-key/ignore-me \
	--signature ./v1.1.0-elliptic-key/model.sig \
	--public_key ./keys/certificate/signing-key-pub.pem \
	./v1.1.0-elliptic-key ; then
	echo "Error: 'verify key' failed on v1.1.0"
	exit 1
fi

exit 0
