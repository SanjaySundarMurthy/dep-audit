FROM python:3.12-slim AS builder

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir build && python -m build

FROM python:3.12-slim

LABEL maintainer="ssan" \
      org.opencontainers.image.source="https://github.com/ssan/dep-audit" \
      org.opencontainers.image.description="dep-audit-cli - DevOps CLI Tool"

RUN groupadd -r appuser && useradd -r -g appuser appuser
COPY --from=builder /app/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

USER appuser
ENTRYPOINT ["dep-audit"]
CMD ["--help"]
