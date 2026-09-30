# Trench — multi-arch image. The admin SPA is prebuilt into trench/web/dist,
# so no Node toolchain is needed at build time.
#
# Pinned to a specific Debian release, not bare `slim`: `python:3.12-slim`
# silently moves to the next Debian and can change system libraries under a
# build that was otherwise reproducible. Pin the digest too for a hard
# guarantee — `FROM python:3.12-slim-bookworm@sha256:...`.

# uv is used for one thing: turning uv.lock into a hash-pinned requirements
# file. It is mounted for that step only and never lands in the image.
FROM ghcr.io/astral-sh/uv:0.12.21 AS uv

FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app

# Dependencies come from the lockfile, not from a fresh resolve. Without it,
# rebuilding the same tag a week later could ship different libraries than
# CI tested, and nothing would say so. --require-hashes makes pip refuse any
# artifact whose digest the lock does not name.
#
# This layer depends on pyproject.toml and uv.lock alone, so it stays cached
# across code changes — which matters on a small board, where rebuilding the
# dependency set is slow and memory-hungry.
COPY pyproject.toml uv.lock ./
RUN --mount=type=bind,from=uv,source=/uv,target=/usr/local/bin/uv \
    uv export --frozen --no-dev --no-emit-project --format requirements-txt \
        --output-file /tmp/requirements.txt \
    && pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

# Application code: only this thin layer rebuilds when sources change.
COPY README.md LICENSE ./
COPY trench ./trench
RUN pip install --no-cache-dir --no-deps . \
    && rm -rf build trench.egg-info

COPY deploy/healthcheck.py /usr/local/bin/trench-healthcheck

# An unprivileged account for Trench to drop into. The container still
# starts as root because :53 and :853 are privileged ports; set `server.user`
# in the config and Trench sheds root itself once every listener is bound.
# /data must be writable both before and after the privilege drop, and
# without relying on root's CAP_DAC_OVERRIDE — a hardened deployment drops it.
# root:trench 2775 gives root the owner bits and the dropped-to account the
# group bits; the setgid bit keeps files created either side of the drop in
# the group, so the other identity can still read them.
#
# /data/data is created here, not left to Trench: the example config's
# `data_dir: ./data` resolves to it (see WORKDIR below), and a directory root
# created at run time under a 022 umask would not be writable by the account
# Trench drops to. A named volume is seeded from this layout on first use.
RUN useradd --no-create-home --shell /usr/sbin/nologin --uid 1000 trench \
    && mkdir -p /data/data \
    && chown root:trench /data /data/data \
    && chmod 2775 /data /data/data

# Runtime
# Relative paths in the config resolve against the working directory, so it
# has to be the volume. Left at /app, `data_dir: ./data` put the database,
# the compiled blocklist and the initial admin password in the container's
# writable layer, where recreating the container threw them away.
WORKDIR /data
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
