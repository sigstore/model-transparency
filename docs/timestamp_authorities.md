# Timestamp Authorities

Traditional key, certificate, and PKCS #11 signing can add an RFC 3161 trusted
timestamp to the signature bundle. Sigstore signing already obtains timestamps
from the services in its client trust configuration.

## Signing

Pass the timestamp authority endpoint with `--tsa-url`:

```bash
model_signing sign key model \
  --private-key key.pem \
  --tsa-url https://timestamp.sigstore.dev/api/v1/timestamp
```

The same option is available for `sign certificate`, `sign pkcs11-key`, and
`sign pkcs11-certificate`. Requesting a timestamp requires access to the TSA at
signing time.

## Verification

Sigstore's public production timestamp authority is trusted by default:

```bash
model_signing verify key model \
  --signature model.sig \
  --public-key key.pub \
  --require-timestamp
```

For a private TSA, pass either a complete Sigstore `ClientTrustConfig` or a
standalone Sigstore `TrustedRoot`:

```bash
model_signing verify key model \
  --signature model.sig \
  --public-key key.pub \
  --trust-config company-trusted-root.json \
  --require-timestamp
```

Key and certificate verification only use `timestampAuthorities` from this
file. Fulcio, Rekor, and signing service settings in a complete client trust
configuration are ignored.

## Creating a trusted root

A minimal standalone trusted root has this structure:

```json
{
  "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
  "tlogs": [],
  "certificateAuthorities": [],
  "ctlogs": [],
  "timestampAuthorities": [{
    "subject": {
      "organization": "Example",
      "commonName": "Example TSA"
    },
    "certChain": {
      "certificates": [
        {"rawBytes": "BASE64_DER_TSA_CERTIFICATE"},
        {"rawBytes": "BASE64_DER_ROOT_CERTIFICATE"}
      ]
    },
    "validFor": {"start": "2025-01-01T00:00:00Z"}
  }]
}
```

List certificates from the TSA signing certificate through any intermediates
to the root. Each `rawBytes` value is a base64-encoded DER certificate. Convert
a PEM certificate with:

```bash
openssl x509 -in tsa.pem -outform DER | base64 | tr -d '\n'
```

Set `validFor.start` to the first time this authority should be trusted. Add an
`end` value when the authority is retired:

```json
"validFor": {
  "start": "2025-01-01T00:00:00Z",
  "end": "2027-01-01T00:00:00Z"
}
```

## Verification policy

- A timestamp in the bundle is always verified, even without
  `--require-timestamp`.
- `--require-timestamp` rejects bundles that contain no timestamp.
- A malformed timestamp, signature mismatch, untrusted TSA, incomplete TSA
  chain, or generation time outside the authority's validity period fails
  verification.
- Timestamp-free signatures remain compatible unless `--require-timestamp` is
  used.

For certificate-backed model signatures, the verified timestamp is also used
as the signing-certificate verification time. This permits a signature created
while its certificate was valid to remain verifiable after that certificate
expires.

## Offline verification

Verification with a local `--trust-config` file is offline. Without one, the
verifier uses Sigstore production trust and may refresh TUF metadata. Trust is
loaded only when a bundle contains a timestamp and is cached for reuse by that
verifier.
