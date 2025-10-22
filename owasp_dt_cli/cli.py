import dotenv

from owasp_dt_cli.args import create_parser
from owasp_dt_cli.log import LOGGER

def main():
    parser = create_parser()
    try:
        args = parser.parse_args()
        if args.env:
            assert dotenv.load_dotenv(args.env), f"Unable to load env file: '{args.env}'"
        args.func(args)
    except Exception as e:
        LOGGER.error(e)
        exit(1)

if __name__ == "__main__":  # pragma: no cover
    main()  # pragma: no cover
