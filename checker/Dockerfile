FROM python:3.12-alpine3.23

ARG TRIVY_VERSION=0.76.2

RUN apk upgrade --no-cache && apk add --no-cache ca-certificates curl

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin v${TRIVY_VERSION}

# Pre-warm Trivy vulnerability + license DB
RUN trivy image --download-db-only --quiet || true

WORKDIR /app
COPY requirements.txt .
RUN python -m pip install --no-cache-dir --upgrade pip==26.3 \
    && pip install --no-cache-dir -r requirements.txt

COPY checker.py .
ENTRYPOINT ["python", "/app/checker.py"]
CMD []
