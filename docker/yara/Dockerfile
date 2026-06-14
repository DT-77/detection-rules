# Minimal, self-contained YARA validator image.
# Provides both `yara` (scanner) and `yarac` (compiler) from the Alpine package.
FROM alpine:3.20

LABEL org.opencontainers.image.title="detection-rules-lab yara validator" \
      org.opencontainers.image.description="Offline YARA rule compiler/scanner (local-only)" \
      org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache yara && yara --version && yarac --version || true

# Compile/scan commands supply their own entrypoint (yarac|yara) via --entrypoint.
ENTRYPOINT []
CMD ["yara", "--version"]
