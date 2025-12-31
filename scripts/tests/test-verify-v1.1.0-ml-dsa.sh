#!/usr/bin/env bash

echo "Testing 'verify ml-dsa' for v1.1.0"
if ! python -m model_signing \
	verify ml-dsa \
	--ignore-paths ./v1.1.0-ml-dsa/ignore-me \
	--signature ./v1.1.0-ml-dsa/model.sig \
	--public_key ./keys/ml-dsa/signing-key.pub \
	./v1.1.0-ml-dsa ; then
	echo "Error: 'verify ml-dsa' failed on v1.1.0"
	exit 1
fi

echo "✓ ML-DSA v1.1.0 verification test passed"

exit 0
