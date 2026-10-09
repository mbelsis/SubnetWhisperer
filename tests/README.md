# Tests

This directory contains two test layers:

1. Fast app smoke tests
2. Docker-based SSH integration tests

## Fast Smoke Tests

These tests live in [tests/test_app.py](test_app.py).

They verify basic app behavior such as:

- login page rendering
- authenticated access to protected pages
- `/start_scan` request validation
- `/scan_results/<id>` response formatting

Run them with:

```bash
python -m unittest discover -s tests -v
```

By default, the Docker integration tests are skipped during this command unless explicitly enabled.

## Docker SSH Integration Tests

These tests live in:

- [tests/test_docker_integration.py](test_docker_integration.py)
- [tests/run_docker_integration.py](run_docker_integration.py)
- [tests/docker-compose.integration.yml](docker-compose.integration.yml)

They test the real SSH execution path of the application, not mocks.

### What They Actually Verify

The integration suite starts two Linux SSH targets in Docker:

- `ssh-password`: accepts username/password authentication
- `ssh-key`: accepts SSH private-key authentication

The application then connects to those containers using the real code in [ssh_utils.py](../ssh_utils.py).

The suite verifies:

- password-based SSH login works
- key-based SSH login works
- commands are actually executed remotely over SSH
- command output is stored in the database
- threaded scan execution marks the parent scan session as completed

### Commands Executed During the Tests

The tests currently execute simple remote commands such as:

- `echo password-target`
- `echo key-target`
- `echo threaded-target`

These are intentional smoke commands used only to prove the SSH execution path works end-to-end.

## How The Integration Setup Works

The Docker test setup uses:

- [tests/docker/ssh-password/Dockerfile](docker/ssh-password/Dockerfile)
- [tests/docker/ssh-key/Dockerfile](docker/ssh-key/Dockerfile)

The containers expose SSH to the host on:

- `127.0.0.1:2222` for password auth
- `127.0.0.1:2223` for key auth

The key-auth test uses a throwaway Ed25519 key pair, `tests/docker/keys/id_ed25519_valid`
and `id_ed25519_valid.pub`. It is generated on the first run (before the containers are
built) and is git-ignored, so no private key is committed. Delete both files and rebuild the
containers (`docker compose -f tests/docker-compose.integration.yml build`) to rotate it.

The test suite creates an isolated SQLite database just for the run and removes it afterward. It does not use the normal application database for its assertions.

The tests also set `SESSION_SECRET`, `ENCRYPTION_KEY` and `START_SCHEDULER=false` before importing the app, so the background scheduler never runs during tests.

The app verifies SSH host keys (`SSH_HOST_KEY_POLICY`, default `tofu`). The test containers generate new host keys when they are rebuilt, so a key recorded in a known-hosts file by an earlier run will no longer match. The integration tests should use a throwaway `SSH_KNOWN_HOSTS_FILE` (or `SSH_HOST_KEY_POLICY=warn`); if you run manual scans against the containers from the app, remove the `[127.0.0.1]:2222` and `[127.0.0.1]:2223` lines from `instance/known_hosts` after rebuilding.

## Prerequisites

Before running the Docker integration tests, make sure:

- Docker Desktop is running
- the Docker Linux engine is available
- Python dependencies for the app are installed

If Python dependencies are missing, install them with:

```bash
./setup.sh
source .venv/bin/activate   # run the commands below inside this virtualenv
```

or install the dependencies listed in `pyproject.toml` (pinned in `uv.lock`) into your environment, for example with `uv export --frozen --no-dev --no-emit-project --no-hashes -o requirements.txt && python3 -m pip install -r requirements.txt`. Python 3.11+ is required.

## How To Run The Integration Tests

Recommended command:

```bash
python tests/run_docker_integration.py
```

That runner sets the required environment flag and launches:

```bash
python -m unittest tests.test_docker_integration -v
```

You can also run it manually:

macOS / Linux:

```bash
export RUN_DOCKER_TESTS=1
python -m unittest tests.test_docker_integration -v
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

## What You Should Expect To See

A successful run looks like:

```text
test_key_container_executes_commands ... ok
test_password_container_executes_commands ... ok
test_start_scan_session_marks_parent_complete ... ok

----------------------------------------------------------------------
Ran 3 tests in XX.XXXs

OK
```

## How To Check The Results

### 1. Test Output

The first place to check is the console output.

If you see `OK`, then:

- both SSH containers started correctly
- the application connected to them
- commands were executed remotely
- the stored results matched the expected values

If you see `FAIL`, then:

- the test ran but the stored or returned behavior did not match expectations
- examples: wrong status, wrong command output, scan not marked completed

If you see `ERROR`, then:

- setup or execution failed before the assertion phase completed
- examples: Docker not running, SSH connection failure, bad key loading, app exception

### 2. What The Assertions Check Internally

The tests inspect database state after execution.

They check values on `ScanResult`, including:

- `status_code`
- `ssh_status`
- `command_output`

They also check values on `ScanSession`, including:

- `status == "completed"` for threaded scans
- `completed_at` being set

So if the suite passes, the app did not merely connect. It also persisted the expected execution results.

### 3. Docker Side Verification

If you want to inspect the test containers manually while debugging:

```bash
docker compose -f tests/docker-compose.integration.yml ps
docker logs subnet-whisperer-ssh-password
docker logs subnet-whisperer-ssh-key
```

### 4. Rebuilding The Test Containers

If you change the Dockerfiles or key material, rebuild with:

```bash
docker compose -f tests/docker-compose.integration.yml up -d --build
```

### 5. Keep Containers Running For Manual Inspection

If you want to inspect the SSH targets manually instead of using the automatic test runner, start them yourself:

```bash
docker compose -f tests/docker-compose.integration.yml up -d --build
```

This leaves the containers running so you can:

- inspect logs
- test SSH access manually
- verify ports are open
- debug command behavior outside the Python test harness

Useful commands:

```bash
docker compose -f tests/docker-compose.integration.yml ps
docker logs subnet-whisperer-ssh-password
docker logs subnet-whisperer-ssh-key
```

Manual SSH checks from the host:

```bash
ssh scanner@127.0.0.1 -p 2222
ssh -i tests/docker/keys/id_ed25519_valid scanner@127.0.0.1 -p 2223
```

When you are done debugging, stop and remove them with:

```bash
docker compose -f tests/docker-compose.integration.yml down --volumes
```

## Current Coverage Limits

The integration suite currently proves:

- real SSH auth works
- commands execute over SSH
- the app stores per-host results
- threaded scan completion works

It does not yet fully cover:

- sudo command flows
- server info collection
- scheduled scan execution
- multiple credential fallback logic
- export routes

## When To Use Which Test Layer

Use the fast smoke tests when:

- you want quick feedback on app routing and validation
- you are changing forms, pages, or response handling

Use the Docker integration tests when:

- you changed SSH logic
- you changed command execution behavior
- you changed credential handling
- you want to prove the app still executes commands on real SSH targets
