import os
import subprocess
import sys
from pathlib import Path


def main():
    project_root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["RUN_DOCKER_TESTS"] = "1"

    result = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_docker_integration", "-v"],
        cwd=project_root,
        env=env,
    )
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
