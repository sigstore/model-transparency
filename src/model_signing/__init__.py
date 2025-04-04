# Copyright 2024 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Universal model signing library.

The API is split into 3 main components (and a glue `model_signing.manifest`
module for data types used in public interfaces):

- `model_signing.hashing`: responsible with generating a list of hashes for
  every component of the model. A component could be a file, a file shard, a
  tensor, etc., depending on the method used. We currently support only files
  and file shards. The result of hashing is a manifest, a listing of hashes for
  every object in the model.
- `model_signing.signing`: responsible with taking the manifest and generating a
  signature, based on a signing configuration. The signing configuration can
  select the method used to sign as well as the parameters.
- `model_signing.verifying`: responsible with taking a signature and verifying
  it. If the cryptographic parts of the signature can be validated, the
  verification layer would return an expanded manifest which can then be
  compared agains a manifest obtained from hashing the existing model. If the
  two manifest don't match then the model integrity was compromised and the
  `model_signing` package detected that.

The first two of these components allows configurability but can also be used
directly, with a default configuration. The only difference is for the
verification component where we need to configure the verification method since
there are no sensible defaults that can be used.

Signing can be done using the default configuration:

```python
model_signing.signing.sign("finbert", "finbert.sig")
```

This example generates the signature using Sigstore.

Alternatively, a custom configuration can be selected, for both signing and
hashing:

```python
model_signing.signing.Config().use_elliptic_key_signer(
    private_key="key"
).set_hashing_config(
    model_signing.hashing.Config().set_ignored_paths(
        paths=["README.md"], ignore_git_paths=True
    )
).sign("finbert", "finbert.sig")
```

This example generates a signature using a private key based on elliptic curve
cryptography. It also hashes the model by ignoring `README.md` and any git
related file present in the model directory.

We also support signing with signing certificates, using a similar API as above.

When verifying, we need to configure the cryptography configuration, so that the
code knows how to parse the signature.

For the Sigstore example, the simplest verification example would be:

```python
model_signing.verifying.Config().use_sigstore_verifier(
    identity=identity, oidc_issuer=oidc_provider
).verify("finbert", "finbert.sig")
```

Where `identity` and `oidc_provider` are the parameters obtained after the OIDC
flow during signing.

To verify the private key example, we could use the following:

```python
model_signing.verifying.Config().use_elliptic_key_verifier(
    public_key="key.pub"
).set_hashing_config(
    model_signing.hashing.Config().use_shard_serialization()
    )
).verify("finbert", "finbert.sig")
```

Alternatively, we also support automatic detection of the hashing configuration
during the verification process. So, the following should also work:

```python
model_signing.verifying.Config().use_elliptic_key_verifier(
    public_key="key.pub"
).verify("finbert", "finbert.sig")
```

A reminder that we still need to set the verification configuration. This sets
up the cryptographic primitives to verify the signature and is needed to know
how to parse the signature file.

For any signing method, the signature is a
[Sigstore bundle](https://docs.sigstore.dev/about/bundle/) which contains the
verification material (the information needed to verify the signature) and the
payload. The verification material depends on the method used for signing.

The payload in the signature is a
[DSSE envelope](https://github.com/secure-systems-lab/dsse) which contains an
[in-toto statement](https://github.com/in-toto/attestation/tree/main/spec/v1).
The in-toto statement contains the actual metadata that gets signed, and in our
case is a custom predicate that identifies all the components of the model.

Read more [on the repository's `README.md`][repo]. The CLI that maps over the
API is also documented there.

[repo]: https://github.com/sigstore/model-transparency/blob/main/README.md
"""

from model_signing import hashing
from model_signing import manifest
from model_signing import signing
from model_signing import verifying


__version__ = "1.0.0"


__all__ = ["hashing", "signing", "verifying", "manifest"]
