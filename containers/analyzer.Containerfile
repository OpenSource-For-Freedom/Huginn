# Huginn's malware analyzer: the vendored git_warden Tier-2 rules plus yara.
# Built by the capture workflow from this repository alone; run by
# PodmanScanner with no network, a read-only root and dropped capabilities.
FROM docker.io/library/python:3.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends yara \
    && rm -rf /var/lib/apt/lists/*

COPY src/huginn/analyzer /opt/huginn_analyzer
ENV PYTHONPATH=/opt PYTHONDONTWRITEBYTECODE=1
RUN python -c "import huginn_analyzer.package_entry"

USER 65534:65534
WORKDIR /work
ENTRYPOINT ["python", "-m", "huginn_analyzer.package_entry"]
