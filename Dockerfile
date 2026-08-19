# DNSGuard — multi-arch image. The admin SPA is prebuilt into dnsguard/web/dist,
# so no Node toolchain is needed at build time.
#
# Pinned to a specific Debian release, not bare `slim`: `python:3.12-slim`
# silently moves to the next Debian and can change system libraries under a
# build that was otherwise reproducible. Pin the digest too for a hard
# guarantee — `FROM python:3.12-slim-bookworm@sha256:...`.
FROM python:3.12-slim-bookworm AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app

# Dependencies resolve from pyproject alone, so install them against a stub
# package first. That layer then stays cached across code changes — without it
# every edit re-downloads and rebuilds the whole dependency set, which is slow
# and memory-hungry on a small board.
#
# The `build` directory has to go with the stub. setuptools only re-copies a
# source file into build/lib when the source is newer, and the stub is written
# during the build while the real sources carry their original mtimes — so a
# leftover build/lib silently ships the stub's version.py instead of the real
# one, and the image dies on `from ..version import USER_AGENT`.
COPY pyproject.toml README.md LICENSE ./
RUN mkdir -p dnsguard \
    && printf '__version__ = "0.0.0"\n' > dnsguard/version.py \
    && printf '' > dnsguard/__init__.py \
    && pip install --no-cache-dir . \
    && pip uninstall -y dnsguard \
    && rm -rf dnsguard build dnsguard.egg-info

# Application code: only this thin layer rebuilds when sources change.
COPY dnsguard ./dnsguard
RUN pip install --no-cache-dir --no-deps .

COPY deploy/healthcheck.py /usr/local/bin/dnsguard-healthcheck

# An unprivileged account for DNSGuard to drop into. The container still
# starts as root because :53 and :853 are privileged ports; set `server.user`
# in the config and DNSGuard sheds root itself once every listener is bound.
RUN useradd --no-create-home --shell /usr/sbin/nologin --uid 1000 dnsguard \
    && mkdir -p /data \
    && chown dnsguard:dnsguard /data

# Runtime
EXPOSE 53/udp 53/tcp 853/tcp 853/udp 8443/tcp 8089/tcp
VOLUME ["/data"]

# Probes resolution, not liveness: a process that is up but has stopped
# answering is the failure worth catching. It queries a .invalid name, so an
# upstream outage cannot turn into a restart loop.
HEALTHCHECK --interval=60s --timeout=8s --start-period=120s --retries=3 \
    CMD ["python3", "/usr/local/bin/dnsguard-healthcheck"]

ARG VERSION=2.0.0
ARG REVISION=unknown
LABEL org.opencontainers.image.title="DNSGuard" \
      org.opencontainers.image.description="Self-hosted DNS sinkhole, validating recursive resolver, and authoritative server" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/OWNER/dnsguard" \
      org.opencontainers.image.documentation="https://OWNER.github.io/dnsguard/"

ENTRYPOINT ["dnsguardd"]
CMD ["--config", "/data/dnsguard.yaml"]
