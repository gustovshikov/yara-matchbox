# Base image (has yara installed already)
FROM local/so-strelka-backend:2.4.160
LABEL authors="eric"

# Create mount points and an idle entrypoint that keeps the container alive
USER root
RUN mkdir -p /data/rules /data/scans \
    && printf '#!/bin/sh\nset -eu\ntrap : TERM INT\n# stay alive forever but respond to signals\nwhile :; do sleep 2147483647 & wait $!; done\n' > /usr/local/bin/idle.sh \
    && chmod 0755 /usr/local/bin/idle.sh

# Optional: lightweight healthcheck (fails if yara missing)
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD yara -v >/dev/null 2>&1 || exit 1

# Drop back to the non-root user used by the base image
USER strelka
WORKDIR /data

# IMPORTANT: keep the container running for docker exec calls
ENTRYPOINT ["/usr/local/bin/idle.sh"]
# (No CMD: we do not auto-run yara here)