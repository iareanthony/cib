FROM python:3.12-alpine

ARG TRIVY_VERSION=0.70.0

RUN apk add --no-cache curl

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin v${TRIVY_VERSION}

# Pre-warm Trivy vulnerability + license DB
RUN trivy image --download-db-only --quiet || true

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY checker.py .
ENTRYPOINT ["python", "/app/checker.py"]
CMD []
