# Testing Guide

This project now includes a minimal automated test suite built with Python's standard `unittest` framework.

## Test Scope

The current suite is a smoke-test layer for the Flask app. It verifies:

- The login page renders successfully
- An authenticated user can access the schedule creation page
- The `/start_scan` endpoint rejects invalid requests
- The `/scan_results/<id>` endpoint returns the expected summary for saved results

The tests use:

- Flask's test client
- A temporary SQLite database created only for test execution
- A seeded admin user for authenticated route checks

The tests do not touch the main application database in `instance/subnet_whisperer.db`.

## Test Files

- [tests/test_app.py](C:/Users/mbelsis/Documents/GitHub/SubnetWhisperer/tests/test_app.py)
- [tests/README.md](C:/Users/mbelsis/Documents/GitHub/SubnetWhisperer/tests/README.md)

## How To Run

From the repository root, run:

```bash
python -m unittest discover -s tests -v
```

## Docker Integration Tests

There is also a separate integration test layer that uses two real Linux SSH containers:

- `ssh-password`: password-authenticated SSH target
- `ssh-key`: SSH target that accepts the bundled test key

These tests exercise actual SSH connectivity and command execution through the real scan code in [ssh_utils.py](C:/Users/mbelsis/Documents/GitHub/SubnetWhisperer/ssh_utils.py).

Run them with:

```bash
python tests/run_docker_integration.py
```

Or directly:

```bash
set RUN_DOCKER_TESTS=1
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
python -m pip install flask flask-login flask-sqlalchemy flask-wtf wtforms email-validator sqlalchemy paramiko cryptography pandas matplotlib bcrypt psycopg2-binary gunicorn
```

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
