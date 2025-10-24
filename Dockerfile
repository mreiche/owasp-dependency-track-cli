FROM python:3.13-alpine AS builder

WORKDIR /build
COPY pyproject.toml ./
RUN pip install --no-cache-dir build
COPY owasp_dt_cli ./owasp_dt_cli
RUN python -m build --wheel --outdir dist

FROM python:3.13-alpine
WORKDIR /app
COPY --from=builder /build/dist/*.whl ./
RUN pip install --no-cache-dir *.whl \
  && rm *.whl \
  && owasp-dtrack-cli --help

ENTRYPOINT [ "owasp-dtrack-cli" ]
