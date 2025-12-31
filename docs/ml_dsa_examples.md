# ML-DSA (Module Lattice Digital Signature Algorithm) Examples

This document provides comprehensive examples and use cases for using ML-DSA (FIPS 204) post-quantum signatures with the model signing library.

## Table of Contents

- [Introduction](#introduction)
- [Basic Usage](#basic-usage)
  - [Key Generation](#key-generation)
  - [Signing a Model](#signing-a-model)
  - [Verifying a Model](#verifying-a-model)
- [Advanced Features](#advanced-features)
  - [Password-Protected Keys](#password-protected-keys)
  - [Different Security Levels](#different-security-levels)
  - [Ignored Paths](#ignored-paths)
- [Integration Examples](#integration-examples)
  - [Python API Usage](#python-api-usage)
  - [CI/CD Integration](#cicd-integration)
  - [Automated Workflows](#automated-workflows)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Introduction

ML-DSA (Module Lattice Digital Signature Algorithm) is a post-quantum digital signature algorithm standardized by NIST as FIPS 204 in August 2024. It provides security against both classical and quantum computer attacks, making it essential for long-term model integrity protection.

**Why ML-DSA?**
- **Quantum-Resistant**: Secure against attacks from quantum computers
- **Standardized**: NIST FIPS 204 approved standard
- **Future-Proof**: Suitable for models that require long-term security (10+ years)
- **Widely Supported**: Growing ecosystem support

**Trade-offs:**
- **Larger Keys**: ML-DSA keys are larger than traditional ECDSA keys
- **Larger Signatures**: Signatures are approximately 3-5 KB vs 70 bytes for ECDSA
- **Performance**: Slightly slower signing/verification (but still sub-second)

## Basic Usage

### Key Generation

**Using CLI (Recommended):**

```bash
# Generate ML-DSA-65 key pair (recommended for most use cases)
model_signing keygen ml-dsa --output mykey --variant ML_DSA_65

# This creates:
# - mykey.priv (4032 bytes) - Private key
# - mykey.pub (1952 bytes) - Public key
```

**Using Python:**

```python
from dilithium_py.ml_dsa import ML_DSA_65
import pathlib

# Generate key pair
public_key, private_key = ML_DSA_65.keygen()

# Save to files
pathlib.Path("ml_dsa_65.pub").write_bytes(public_key)
pathlib.Path("ml_dsa_65.priv").write_bytes(private_key)

print(f"Public key size: {len(public_key)} bytes")
print(f"Private key size: {len(private_key)} bytes")
```

**One-liner (for quick testing):**

```bash
python -c "from dilithium_py.ml_dsa import ML_DSA_65; import pathlib; pk, sk = ML_DSA_65.keygen(); pathlib.Path('test.pub').write_bytes(pk); pathlib.Path('test.priv').write_bytes(sk)"
```

### Signing a Model

**Basic Signing:**

```bash
# Download a model
git clone --depth=1 https://huggingface.co/bert-base-uncased
rm -rf bert-base-uncased/.git

# Sign with ML-DSA
model_signing sign ml-dsa bert-base-uncased \
    --private_key mykey.priv \
    --signature model.sig

# By default, uses ML_DSA_65 variant
```

**Specifying Variant:**

```bash
# Use ML-DSA-87 for higher security
model_signing sign ml-dsa bert-base-uncased \
    --private_key ml_dsa_87.priv \
    --variant ML_DSA_87 \
    --signature model.sig
```

### Verifying a Model

**Basic Verification:**

```bash
model_signing verify ml-dsa bert-base-uncased \
    --public_key mykey.pub \
    --signature model.sig
```

**With Explicit Variant:**

```bash
model_signing verify ml-dsa bert-base-uncased \
    --public_key ml_dsa_87.pub \
    --variant ML_DSA_87 \
    --signature model.sig
```

## Advanced Features

### Password-Protected Keys

Encrypting private keys with a password adds an extra layer of security, especially useful for:
- Shared development environments
- CI/CD secrets management
- Long-term key storage

**Encrypting a Key:**

```bash
# Encrypt an existing private key
python scripts/ml_dsa_key_tool.py encrypt mykey.priv \
    --output mykey_encrypted.priv \
    --password "MySecurePassword123!"

# Verify the encrypted key
python scripts/ml_dsa_key_tool.py verify mykey_encrypted.priv \
    --password "MySecurePassword123!"
```

**Signing with Encrypted Key:**

```bash
model_signing sign ml-dsa bert-base-uncased \
    --private_key mykey_encrypted.priv \
    --password "MySecurePassword123!" \
    --signature model.sig
```

**Using Environment Variables:**

```bash
# Store password in environment variable (more secure)
export ML_DSA_PASSWORD="MySecurePassword123!"

model_signing sign ml-dsa bert-base-uncased \
    --private_key mykey_encrypted.priv \
    --password "$ML_DSA_PASSWORD" \
    --signature model.sig
```

**Decrypting a Key (if needed):**

```bash
python scripts/ml_dsa_key_tool.py decrypt mykey_encrypted.priv \
    --output mykey_decrypted.priv \
    --password "MySecurePassword123!"
```

### Different Security Levels

ML-DSA offers three security levels. Choose based on your threat model:

**ML-DSA-44 (IoT and Resource-Constrained):**

```bash
# Generate smaller keys
model_signing keygen ml-dsa --output iot_key --variant ML_DSA_44

# Sign with ML-DSA-44
model_signing sign ml-dsa my_model \
    --private_key iot_key.priv \
    --variant ML_DSA_44 \
    --signature model.sig

# Key sizes: Public: 1312 bytes, Private: 2560 bytes, Signature: ~2420 bytes
```

**ML-DSA-65 (Recommended for Production):**

```bash
# Generate standard keys (balanced security/size)
model_signing keygen ml-dsa --output prod_key --variant ML_DSA_65

# Sign with ML-DSA-65
model_signing sign ml-dsa my_model \
    --private_key prod_key.priv \
    --variant ML_DSA_65 \
    --signature model.sig

# Key sizes: Public: 1952 bytes, Private: 4032 bytes, Signature: ~3309 bytes
```

**ML-DSA-87 (Maximum Security):**

```bash
# Generate ultra-secure keys
model_signing keygen ml-dsa --output max_key --variant ML_DSA_87

# Sign with ML-DSA-87
model_signing sign ml-dsa my_model \
    --private_key max_key.priv \
    --variant ML_DSA_87 \
    --signature model.sig

# Key sizes: Public: 2592 bytes, Private: 4896 bytes, Signature: ~4627 bytes
```

**Comparison Table:**

| Variant | NIST Level | Public Key | Private Key | Signature | Use Case |
|---------|-----------|------------|-------------|-----------|----------|
| ML-DSA-44 | Level 2 | 1,312 B | 2,560 B | ~2,420 B | IoT, bandwidth-limited |
| ML-DSA-65 | Level 3 | 1,952 B | 4,032 B | ~3,309 B | **Recommended** for production |
| ML-DSA-87 | Level 5 | 2,592 B | 4,896 B | ~4,627 B | Ultra-high security |

### Ignored Paths

Exclude specific files or directories from signing:

```bash
# Ignore specific files
model_signing sign ml-dsa my_model \
    --private_key mykey.priv \
    --ignore_paths temp_data \
    --ignore_paths .DS_Store \
    --signature model.sig

# Ignore git-related files (enabled by default)
model_signing sign ml-dsa my_model \
    --private_key mykey.priv \
    --no-ignore_git_paths \
    --signature model.sig
```

## Integration Examples

### Python API Usage

**Basic Signing and Verification:**

```python
from model_signing import signing, verifying, hashing
from pathlib import Path

# Sign a model
signing.Config().use_ml_dsa_signer(
    private_key=Path("mykey.priv"),
    variant="ML_DSA_65"
).sign(
    model_path=Path("my_model"),
    signature_path=Path("model.sig")
)

# Verify a model
verifying.Config().use_ml_dsa_verifier(
    public_key=Path("mykey.pub"),
    variant="ML_DSA_65"
).verify(
    model_path=Path("my_model"),
    signature_path=Path("model.sig")
)
```

**With Password-Protected Keys:**

```python
import os
from model_signing import signing
from pathlib import Path

# Get password from environment
password = os.environ.get("ML_DSA_PASSWORD")

# Sign with encrypted key
signing.Config().use_ml_dsa_signer(
    private_key=Path("mykey_encrypted.priv"),
    variant="ML_DSA_65",
    password=password
).sign(
    model_path=Path("my_model"),
    signature_path=Path("model.sig")
)
```

**With Custom Hashing Configuration:**

```python
from model_signing import signing, hashing
from pathlib import Path

# Configure ignored paths
hashing_config = hashing.Config().set_ignored_paths(
    paths=["temp", ".cache", "model.sig"],
    ignore_git_paths=True
)

# Sign with custom hashing config
signing.Config().use_ml_dsa_signer(
    private_key=Path("mykey.priv"),
    variant="ML_DSA_65"
).set_hashing_config(hashing_config).sign(
    model_path=Path("my_model"),
    signature_path=Path("model.sig")
)
```

**Error Handling:**

```python
from model_signing import signing, verifying
from pathlib import Path

try:
    # Attempt to sign
    signing.Config().use_ml_dsa_signer(
        private_key=Path("mykey.priv"),
        variant="ML_DSA_65"
    ).sign(
        model_path=Path("my_model"),
        signature_path=Path("model.sig")
    )
    print("✓ Model signed successfully")

except FileNotFoundError as e:
    print(f"✗ Key file not found: {e}")
except ValueError as e:
    print(f"✗ Invalid key or parameters: {e}")
except Exception as e:
    print(f"✗ Signing failed: {e}")

try:
    # Attempt to verify
    verifying.Config().use_ml_dsa_verifier(
        public_key=Path("mykey.pub"),
        variant="ML_DSA_65"
    ).verify(
        model_path=Path("my_model"),
        signature_path=Path("model.sig")
    )
    print("✓ Signature verified successfully")

except Exception as e:
    print(f"✗ Verification failed: {e}")
```

### CI/CD Integration

**GitHub Actions:**

```yaml
name: Sign Model with ML-DSA

on:
  release:
    types: [published]

jobs:
  sign-model:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'

      - name: Install model-signing
        run: pip install model-signing[pqc]

      - name: Decode private key from secret
        run: echo "${{ secrets.ML_DSA_PRIVATE_KEY_BASE64 }}" | base64 -d > ml_dsa.priv

      - name: Sign model
        env:
          ML_DSA_PASSWORD: ${{ secrets.ML_DSA_KEY_PASSWORD }}
        run: |
          model_signing sign ml-dsa ./my_model \
            --private_key ml_dsa.priv \
            --password "$ML_DSA_PASSWORD" \
            --signature model.sig

      - name: Upload signature
        uses: actions/upload-artifact@v3
        with:
          name: model-signature
          path: model.sig

      - name: Clean up
        if: always()
        run: rm -f ml_dsa.priv
```

**GitLab CI:**

```yaml
sign_model:
  stage: build
  image: python:3.10
  before_script:
    - pip install model-signing[pqc]
  script:
    - echo "$ML_DSA_PRIVATE_KEY_BASE64" | base64 -d > ml_dsa.priv
    - |
      model_signing sign ml-dsa ./my_model \
        --private_key ml_dsa.priv \
        --password "$ML_DSA_KEY_PASSWORD" \
        --signature model.sig
  after_script:
    - rm -f ml_dsa.priv
  artifacts:
    paths:
      - model.sig
  only:
    - tags
```

**Docker Container:**

```dockerfile
FROM python:3.10-slim

# Install model-signing
RUN pip install model-signing[pqc]

# Copy model and keys
COPY my_model /app/my_model
COPY ml_dsa.priv /app/ml_dsa.priv

WORKDIR /app

# Sign the model
RUN model_signing sign ml-dsa my_model \
    --private_key ml_dsa.priv \
    --signature model.sig

# Remove private key
RUN rm ml_dsa.priv

# Verification can be done at runtime
CMD ["python", "-c", "from model_signing import verifying; verifying.Config().use_ml_dsa_verifier(public_key='ml_dsa.pub').verify('my_model', 'model.sig')"]
```

### Automated Workflows

**Batch Signing Script:**

```bash
#!/bin/bash
# sign_models.sh - Sign multiple models with ML-DSA

PRIVATE_KEY="ml_dsa_65.priv"
PASSWORD="${ML_DSA_PASSWORD}"

# Array of models to sign
MODELS=(
    "/path/to/model1"
    "/path/to/model2"
    "/path/to/model3"
)

for model in "${MODELS[@]}"; do
    echo "Signing: $model"

    model_signing sign ml-dsa "$model" \
        --private_key "$PRIVATE_KEY" \
        --password "$PASSWORD" \
        --signature "${model}/model.sig"

    if [ $? -eq 0 ]; then
        echo "✓ Successfully signed: $model"
    else
        echo "✗ Failed to sign: $model"
        exit 1
    fi
done

echo "All models signed successfully!"
```

**Python Batch Script:**

```python
#!/usr/bin/env python3
"""Batch sign multiple models with ML-DSA."""

import os
import sys
from pathlib import Path
from model_signing import signing

def sign_models(models, private_key, password=None):
    """Sign multiple models with the same key."""
    config = signing.Config().use_ml_dsa_signer(
        private_key=private_key,
        variant="ML_DSA_65",
        password=password
    )

    results = []
    for model_path in models:
        model_path = Path(model_path)
        signature_path = model_path / "model.sig"

        try:
            config.sign(model_path, signature_path)
            results.append((model_path, True, None))
            print(f"✓ Signed: {model_path}")
        except Exception as e:
            results.append((model_path, False, str(e)))
            print(f"✗ Failed: {model_path} - {e}")

    return results

if __name__ == "__main__":
    models = [
        "/path/to/model1",
        "/path/to/model2",
        "/path/to/model3",
    ]

    private_key = Path("ml_dsa_65.priv")
    password = os.environ.get("ML_DSA_PASSWORD")

    results = sign_models(models, private_key, password)

    # Print summary
    success = sum(1 for _, ok, _ in results if ok)
    print(f"\nSummary: {success}/{len(results)} models signed successfully")

    # Exit with error if any failed
    sys.exit(0 if success == len(results) else 1)
```

## Best Practices

### Key Management

1. **Generate Keys Securely:**
   ```bash
   # Generate keys on a secure machine
   model_signing keygen ml-dsa --output prod_key --variant ML_DSA_65

   # Immediately encrypt the private key
   python scripts/ml_dsa_key_tool.py encrypt prod_key.priv \
       --output prod_key_encrypted.priv \
       --password "$(openssl rand -base64 32)"
   ```

2. **Store Keys Safely:**
   - Never commit private keys to version control
   - Use secure key management systems (AWS KMS, HashiCorp Vault, etc.)
   - Encrypt private keys with strong passwords
   - Use environment variables for passwords in CI/CD

3. **Rotate Keys Periodically:**
   ```bash
   # Generate new keys every year
   model_signing keygen ml-dsa --output key_2024 --variant ML_DSA_65

   # Re-sign models with new keys
   model_signing sign ml-dsa my_model --private_key key_2024.priv
   ```

### Security Recommendations

1. **Choose Appropriate Security Level:**
   - ML-DSA-44: IoT devices, bandwidth-constrained environments
   - ML-DSA-65: Most production use cases (**recommended**)
   - ML-DSA-87: High-value models, regulatory compliance

2. **Use Password Protection:**
   ```bash
   # Always encrypt private keys in production
   python scripts/ml_dsa_key_tool.py encrypt mykey.priv \
       --output mykey_encrypted.priv \
       --password "$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)"
   ```

3. **Verify Signatures:**
   ```bash
   # Always verify signatures before deploying models
   model_signing verify ml-dsa my_model \
       --public_key mykey.pub \
       --signature model.sig
   ```

4. **Monitor and Audit:**
   - Log all signing operations
   - Track which keys were used to sign which models
   - Implement alerting for verification failures

### Performance Optimization

1. **Batch Operations:**
   - Sign multiple models in parallel when possible
   - Use the Python API for batch operations

2. **Choose Variant Based on Performance:**
   - ML-DSA-44: Fastest signing/verification
   - ML-DSA-65: Balanced performance
   - ML-DSA-87: Slower but most secure

3. **Cache Public Keys:**
   ```python
   # Load public key once for multiple verifications
   from model_signing import verifying
   from pathlib import Path

   verifier = verifying.Config().use_ml_dsa_verifier(
       public_key=Path("mykey.pub"),
       variant="ML_DSA_65"
   )

   # Verify multiple models with the same verifier
   for model in models:
       verifier.verify(model, f"{model}/model.sig")
   ```

## Troubleshooting

### Common Issues

**Issue: "Module 'dilithium_py' not found"**

```bash
# Solution: Install PQC dependencies
pip install model-signing[pqc]
```

**Issue: "Invalid password or corrupted key"**

```bash
# Solution: Verify key is encrypted and password is correct
python scripts/ml_dsa_key_tool.py verify mykey.priv --password "your_password"

# Check if key is encrypted
python scripts/ml_dsa_key_tool.py verify mykey.priv
# If output shows "Encrypted: Yes", password is required
```

**Issue: "Password required for encrypted key"**

```bash
# Solution: Provide password via --password flag
model_signing sign ml-dsa my_model \
    --private_key mykey_encrypted.priv \
    --password "your_password"
```

**Issue: "Password provided but key is not encrypted"**

```bash
# Solution: Remove --password flag for raw keys
model_signing sign ml-dsa my_model \
    --private_key mykey.priv
```

**Issue: "Verification failed - Hash mismatch"**

```bash
# Solution: Model was tampered with or wrong signature
# 1. Check if model was modified after signing
# 2. Verify you're using the correct signature file
# 3. Ensure ignored paths match between sign and verify
model_signing verify ml-dsa my_model \
    --public_key mykey.pub \
    --signature model.sig \
    --ignore_paths temp \
    --ignore_paths .cache
```

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
# Set log level to DEBUG
export LOG_LEVEL=DEBUG

# Run with verbose output
model_signing sign ml-dsa my_model \
    --private_key mykey.priv \
    --signature model.sig
```

### Getting Help

- **Documentation**: [model-signing documentation](https://github.com/sigstore/model-transparency)
- **Issues**: [GitHub Issues](https://github.com/sigstore/model-transparency/issues)
- **Security**: Report security issues to security@sigstore.dev
- **ML-DSA Spec**: [NIST FIPS 204](https://csrc.nist.gov/publications/detail/fips/204/final)

## Conclusion

ML-DSA provides quantum-resistant signatures for long-term model integrity protection. While the keys and signatures are larger than traditional methods, they ensure your models remain secure even against future quantum computers.

For most use cases, we recommend:
- **ML-DSA-65** for production models
- **Password-protected keys** for enhanced security
- **CI/CD integration** for automated signing
- **Regular key rotation** (annually or as needed)

Start with the basic examples and gradually adopt advanced features as your security requirements evolve.
