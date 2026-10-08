# Testing Guide

This project includes an automated test suite built with Python's standard `unittest` framework.

## Test Scope

`tests/test_app.py` (no network access needed) checks, among other things:

- login, forced password change, the 8-character password policy, POST-only logout and the open-redirect guard
- that changing a password signs out other sessions, and that the generated first-admin password file is deleted after the first change
- admin-only access to credential sets, schedules and templates
- `/start_scan` input validation (missing credentials, bad concurrency, oversized subnets)
- `/validate_subnets` reporting, template updates and duplicate names, scan deletion
- CSV export protection against spreadsheet formulas
- schedule timing (the first run at the start date)
- loading passphrase-protected private keys (correct, missing and wrong passphrase)

The tests use:

- Flask's test client
- A temporary SQLite database created only for test execution
- A seeded admin user for authenticated route checks

The tests do not touch the main application database in `instance/subnet_whisperer.db`.

Before importing the app, the tests set their own environment: a temporary `DATABASE_URL`, a test `SESSION_SECRET` and `ENCRYPTION_KEY`, and `START_SCHEDULER=false` so the background scheduler doesn't start during the run. If you write new tests or import the app from a script, set `START_SCHEDULER=false` yourself:

```bash
export START_SCHEDULER=false        # macOS / Linux
set START_SCHEDULER=false           # Windows cmd.exe
$env:START_SCHEDULER = "false"      # Windows PowerShell
```

## Test Files

- [tests/test_app.py](tests/test_app.py)
- [tests/README.md](tests/README.md)

## How To Run

From the repository root, with the app's virtualenv active (`source .venv/bin/activate` after `./setup.sh`), run:

```bash
python -m unittest discover -s tests -v
```

## Docker Integration Tests

There is also a separate integration test layer that uses two real Linux SSH containers:

- `ssh-password`: password-authenticated SSH target
- `ssh-key`: SSH target that accepts the bundled test key

These tests exercise actual SSH connectivity and command execution through the real scan code in [ssh_utils.py](ssh_utils.py).

Run them with:

```bash
python3 tests/run_docker_integration.py
```

Or directly:

macOS / Linux:

```bash
export RUN_DOCKER_TESTS=1
python3 -m unittest tests.test_docker_integration -v
```

Windows (cmd.exe):

```bat
set RUN_DOCKER_TESTS=1
python -m unittest tests.test_docker_integration -v
```

Windows (PowerShell):

```powershell
$env:RUN_DOCKER_TESTS = "1"
python -m unittest tests.test_docker_integration -v
```

The integration harness will:

- build the two SSH test containers
- wait for them to become healthy
- create an isolated SQLite test database
- run end-to-end SSH tests
- tear the containers down afterward

If your environment is missing dependencies, install the runtime packages first:

```bash
./setup.sh
```

or install the dependencies listed in `pyproject.toml` (pinned in `uv.lock`) into your environment, for example with `uv export --frozen --no-dev --no-emit-project --no-hashes -o requirements.txt && python3 -m pip install -r requirements.txt`. Python 3.11+ is required.

## Expected Output

A successful run looks like this:

```text
test_create_schedule_page_loads_for_authenticated_user ... ok
test_login_page_loads ... ok
test_scan_results_summary_returns_saved_results ... ok
test_start_scan_rejects_missing_manual_credentials ... ok
test_start_scan_requires_subnets ... ok

----------------------------------------------------------------------
Ran 5 tests in X.XXXs

OK
```

## How To Read The Outcome

`OK`

- All tests passed.
- The currently covered app flows are behaving as expected.
- This does not prove the whole application is correct; it only confirms the covered paths passed.
- For the Docker suite, it means the app successfully connected to the test SSH containers and executed real commands.

`FAIL`

- A test ran to completion but an assertion did not match the expected result.
- This usually means behavior changed, output content changed, or a route no longer responds as expected.
- Read the failing test name first, then the assertion message and traceback.

`ERROR`

- The test did not complete because of an exception during setup or execution.
- Common causes include missing dependencies, import failures, database initialization problems, or runtime exceptions in app code.
- For the Docker suite, it can also mean Docker Desktop is not running, images could not be pulled, containers did not become healthy, or SSH connectivity failed before assertions ran.
- Start with the first traceback shown in the output.

## Notes

- The suite currently focuses on route-level smoke tests, not full SSH execution or scheduler behavior.
- The Docker integration suite covers real SSH execution and threaded scan completion, but it is slower and should be treated as an explicit integration run rather than the default fast test pass.
- Some warnings may still appear during test runs from the application codebase, including SQLAlchemy legacy warnings and `datetime.utcnow()` deprecation warnings.
- Warnings do not fail the suite unless you explicitly configure them to do so.

## Next Useful Expansions

- Add tests for login/logout behavior and access control
- Add form submission tests for schedule and credential creation
- Add tests for export endpoints
- Mock SSH execution and cover successful and failed scan flows
