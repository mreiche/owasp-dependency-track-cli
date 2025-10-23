import dotenv

from owasp_dt_cli import log, arguments

def main():
    parser = arguments.create_parser()
    try:
        args = parser.parse_args()
        if args.env:
            assert dotenv.load_dotenv(args.env), f"Unable to load env file: '{args.env}'"
        args.func(args)
    except Exception as e:
        log.LOGGER.error(e)
        exit(1)

if __name__ == "__main__":  # pragma: no cover
    main()  # pragma: no cover
