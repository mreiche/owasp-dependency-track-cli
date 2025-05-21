import os
from typing import Callable
type Mapper = Callable[[str], any]

def reqenv(key: str, mapper: Mapper = None):
    def raise_error():
        raise Exception(f"Environment variable {key} not defined or empty")

    return getenv(key, raise_error, mapper)


def getenv(key: str, default: any|Callable = None, mapper: Mapper = None):
    val = os.getenv(key, "")

    if mapper:
        val = mapper(val)

    if isinstance(val, str) and len(val) == 0:
        if isinstance(default, Callable):
            val = default()
        else:
            val = default

    return val

def parse_true(param: any) -> bool:
    return str(param).lower() in ["1", "on", "true", "yes"]
