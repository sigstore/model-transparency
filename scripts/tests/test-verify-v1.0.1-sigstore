#!/usr/bin/env bash

echo "Testing 'verify sigstore'"
if ! python -m model_signing \
	verify sigstore \
	--identity stefanb@us.ibm.com \
	--identity_provider https://sigstore.verify.ibm.com/oauth2 \
	--ignore-paths ./v1.0.1-sigstore/ignore-me \
	--signature ./v1.0.1-sigstore/model.sig \
	./v1.0.1-sigstore/; then
	echo "Error: 'verify sigstore' failed on v1.0.1"
	exit 1
fi

pushd v1.0.1-sigstore 1>/dev/null || exit 1

echo
echo "Testing 'verify sigstore' while in model directory"
if ! python -m model_signing \
	verify sigstore \
	--identity stefanb@us.ibm.com \
	--identity_provider https://sigstore.verify.ibm.com/oauth2 \
	--ignore-paths ignore-me \
	--signature model.sig \
	. ; then
	echo "Error: 'verify sigstore' failed on v1.0.1"
	exit 1
fi

popd 1>/dev/null || exit 1

exit 0
