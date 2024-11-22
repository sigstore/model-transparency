FROM python:3.12-slim

COPY pyproject.toml ./
COPY src ./src

RUN pip install typing-extensions sigstore-protobuf-specs protobuf in-toto-attestation cryptography certifi pyOpenSSL sigstore

RUN echo '#!/bin/bash\n\
cd "/src" && python sign.py' > /usr/local/bin/sign

RUN echo '#!/bin/bash\n\
cd "/src" && python verify.py' > /usr/local/bin/verify

RUN echo '#!/bin/bash\n\
echo "Usage:"\n\
echo "  verify  - Runs the verify.py Python script"\n\
echo "  sign    - Runs the sign.py Python script"\n\
echo "  help    - Displays this help message"' > /usr/local/bin/help

RUN chmod +x /usr/local/bin/sign /usr/local/bin/verify /usr/local/bin/help

CMD ["help"]

