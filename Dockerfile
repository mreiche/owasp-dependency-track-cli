FROM python:3.13-alpine

WORKDIR /home/
COPY pyproject.toml ./
RUN pip3 install -e .
COPY owasp_dt_cli ./owasp_dt_cli
RUN python3 -m "owasp_dt_cli.cli" --help
ENTRYPOINT [ "python3",  "-m", "owasp_dt_cli.cli" ]
