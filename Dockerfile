# Trench — multi-arch image. The admin SPA is prebuilt into trench/web/dist,
# so no Node toolchain is needed at build time.
#
# Pinned to a specific Debian release, not bare `slim`: `python:3.12-slim`
# silently moves to the next Debian and can change system libraries under a
# build that was otherwise reproducible. Pin the digest too for a hard
# guarantee — `FROM python:3.12-slim-bookworm@sha256:...`.
FROM python:3.14-slim-bookworm AS base

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
RUN mkdir -p trench \
    && printf '__version__ = "0.0.0"\n' > trench/version.py \
    && printf '' > trench/__init__.py \
    && pip install --no-cache-dir . \
    && pip uninstall -y trench \
    && rm -rf trench build trench.egg-info

# Application code: only this thin layer rebuilds when sources change.
COPY trench ./trench
RUN pip install --no-cache-dir --no-deps .

COPY deploy/healthcheck.py /usr/local/bin/trench-healthcheck

# An unprivileged account for Trench to drop into. The container still
# starts as root because :53 and :853 are privileged ports; set `server.user`
# in the config and Trench sheds root itself once every listener is bound.
# /data must be writable both before and after the privilege drop, and
# without relying on root's CAP_DAC_OVERRIDE — a hardened deployment drops it.
# root:trench 2775 gives root the owner bits and the dropped-to account the
# group bits; the setgid bit keeps files created either side of the drop in
# the group, so the other identity can still read them.
RUN useradd --no-create-home --shell /usr/sbin/nologin --uid 1000 trench \
    && mkdir -p /data \
    && chown root:trench /data \
    && chmod 2775 /data

# Runtime
EXPOSE 53/udp 53/tcp 853/tcp 853/udp 8443/tcp 8089/tcp
VOLUME ["/data"]

# Probes resolution, not liveness: a process that is up but has stopped
# answering is the failure worth catching. It queries a .invalid name, so an
# upstream outage cannot turn into a restart loop.
HEALTHCHECK --interval=60s --timeout=8s --start-period=120s --retries=3 \
    CMD ["python3", "/usr/local/bin/trench-healthcheck"]

ARG VERSION=2.0.0
ARG REVISION=unknown
LABEL org.opencontainers.image.title="Trench" \
      org.opencontainers.image.description="Self-hosted DNS sinkhole, validating recursive resolver, and authoritative server" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/dev-doshi/trench" \
      org.opencontainers.image.documentation="https://dev-doshi.github.io/trench/"

ENTRYPOINT ["trenchd"]
CMD ["--config", "/data/trench.yaml"]
