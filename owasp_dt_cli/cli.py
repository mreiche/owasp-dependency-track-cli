from owasp_dt_cli.args import create_parser
from owasp_dt_cli.log import LOGGER

def run():
    parser = create_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except Exception as e:
        LOGGER.error(e)
        exit(1)

if __name__ == "__main__":  # pragma: no cover
    run()  # pragma: no cover
