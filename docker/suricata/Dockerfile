# Pinned local Suricata validator image (OISF / Jason Ish maintained base).
FROM jasonish/suricata:latest

LABEL org.opencontainers.image.title="detection-rules-lab suricata validator" \
      org.opencontainers.image.description="Offline Suricata rule validator (local-only)" \
      org.opencontainers.image.licenses="MIT"

# Sanity check the base build at image-build time.
RUN suricata --build-info > /dev/null

# Replay/validation commands supply their own entrypoint (suricata) via --entrypoint.
ENTRYPOINT []
CMD ["suricata", "--build-info"]
