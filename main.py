from lib.args import create_parser
from lib.log import LOGGER

parser = create_parser()
args = parser.parse_args()
try:
    args.func(args)
except Exception as e:
    LOGGER.error(e)
    exit(1)
