from pathlib import Path

from dotenv import load_dotenv

cwd = Path(__file__)


def load_env():
    assert load_dotenv(cwd.parent / "test.env")
