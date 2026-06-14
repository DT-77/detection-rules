# Pinned local Snort 3 validator image.
# Built FROM the Cisco Talos reference image so the local tag (drl/snort3:local)
# is decoupled from upstream tag drift. Rules and config are NEVER baked in —
# they are bind-mounted read-only at run time so the image stays content-free.
FROM ciscotalos/snort3:latest

LABEL org.opencontainers.image.title="detection-rules-lab snort3 validator" \
      org.opencontainers.image.description="Offline Snort 3 rule validator (local-only)" \
      org.opencontainers.image.licenses="MIT"

# The Talos image installs Snort under /home/snorty/snort3 and does NOT add it to
# PATH. Put the binary on PATH and expose the shipped Lua defaults dir so our
# config's `include 'snort_defaults.lua'` resolves.
ENV PATH="/home/snorty/snort3/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    SNORT_LUA_PATH="/home/snorty/snort3/etc/snort"

# Fail the build early if the binary is not where we expect it.
RUN snort --version

# Validation/replay commands supply their own entrypoint (snort) via --entrypoint.
ENTRYPOINT []
CMD ["snort", "--version"]
