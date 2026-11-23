# Cloud Threat Investigation — single-user workspace container.
# Build:  docker build -t cloud-threat-investigation .
# Run:    docker run --rm -p 127.0.0.1:8765:8765 -v cti-workspace:/workspace cloud-threat-investigation
# Open:   http://127.0.0.1:8765
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN useradd --create-home --uid 10001 analyst \
    && mkdir /workspace && chown analyst:analyst /workspace

WORKDIR /app
COPY requirements.txt pyproject.toml MANIFEST.in README.md ./
COPY src ./src
RUN pip install --no-deps -r requirements.txt && pip install --no-deps .

USER analyst
VOLUME ["/workspace"]
EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8765/health', headers={'Host': '127.0.0.1:8765'}))" || exit 1

# The service binds to all interfaces inside the container only. Publish the
# port to loopback on the host (see "Run" above); there is no login.
ENTRYPOINT ["cloud-threat", "--workspace", "/workspace", "--host", "0.0.0.0", "--port", "8765", "--no-browser"]
