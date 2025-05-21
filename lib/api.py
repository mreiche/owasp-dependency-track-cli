from lib.config import reqenv, parse_true, getenv
from owasp_dt import Client


def create_client_from_env() -> Client:
    return Client(
        base_url=reqenv("OWASP_DT_URL"),
        headers={
            "X-Api-Key": reqenv("OWASP_DT_API_KEY")
        },
        verify_ssl=getenv("OWASP_DT_VERIFY_SSL", "1", parse_true),
        raise_on_unexpected_status=True,
    )
