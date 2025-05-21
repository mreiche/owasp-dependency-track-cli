import subprocess
from pathlib import Path
import os

import pytest

__base_dir = Path(__file__).parent

@pytest.mark.xfail(reason="Feature not implemented")
def test_convert():
    test_env = os.environ.copy()
    file = __base_dir / "test.sbom.json"
    ret = subprocess.run(
        ["python", __base_dir / "../main.py", "convert", file],
        capture_output=True,
        text=True,
        env=test_env
    )
    assert ret.returncode == 0
    xml_file = file.parent / f"{file.stem}.xml"
    assert xml_file.exists()
