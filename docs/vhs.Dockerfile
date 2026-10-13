# ============================================================
# vhs.Dockerfile - renders docs/demo.gif from docs/demo.tape
# ------------------------------------------------------------
# VHS (github.com/charmbracelet/vhs) types a scripted session into
# a virtual terminal and records it. This image adds Python and the
# same pinned dependencies as pyproject.toml, so nothing is installed
# on your machine. Demo mode only: no AWS account, no network calls.
#
#   docker build -t cloudguard-vhs -f docs/vhs.Dockerfile .
#   docker run --rm -v "$PWD:/vhs" cloudguard-vhs docs/demo.tape
# ============================================================

FROM ghcr.io/charmbracelet/vhs:v0.12.1

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3-venv \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install -q --no-cache-dir \
      boto3==1.43.110 rich==15.0.0 "moto[ec2,iam,s3]==5.2.3"

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH=/vhs/src \
    PYTHONDONTWRITEBYTECODE=1
