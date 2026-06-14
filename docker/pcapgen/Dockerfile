# Deterministic, offline PCAP generator (Scapy).
# Scapy's pcap WRITER needs no libpcap, so this image crafts test traffic with
# zero network access — packets are synthesized in code, never captured.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="detection-rules-lab pcap generator" \
      org.opencontainers.image.description="Offline Scapy synthetic PCAP generator (local-only)" \
      org.opencontainers.image.licenses="MIT"

RUN pip install --no-cache-dir "scapy==2.5.0"

# Generators supply their own entrypoint (python) via --entrypoint.
ENTRYPOINT []
CMD ["python", "-c", "import scapy; print(scapy.__version__)"]
