FROM python:3.13-alpine

WORKDIR /home/
COPY requirements.txt ./
RUN pip3 install -r requirements.txt
COPY owasp_dt_cli ./owasp_dt_cli

ENTRYPOINT [ "python3",  "-m", "owasp_dt_cli.cli" ]
