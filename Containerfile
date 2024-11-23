FROM python:3.13-slim

COPY pyproject.toml ./
COPY src ./src

RUN python -m pip install model_signing

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

