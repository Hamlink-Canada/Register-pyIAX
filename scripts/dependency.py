"""Read the shared-library branch without importing application code."""

import re
import tomllib
from pathlib import Path

if __name__ == "__main__":
    project = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())
    pins = [
        re.fullmatch(
            r"rpt-protobuf(?:\[grpc\])? @ git\+https://github\.com/Hamlink-Canada/rpt_protobuf\.git@(main)",
            d,
        )
        for d in project["project"]["dependencies"]
        if d.startswith("rpt-protobuf")
    ]
    if len(pins) != 1 or pins[0] is None:
        raise SystemExit("Expected exactly one main branch reference for rpt-protobuf")
    print(pins[0][1])
