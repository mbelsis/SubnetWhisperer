import io
import os
import json
import time
import select
import socket
import logging
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

import paramiko
from paramiko.hostkeys import HostKeys, HostKeyEntry

from app import app, db
from models import ScanResult, ScanSession, CredentialSet
from encryption_utils import decrypt_data, DecryptionError
from security_utils import (
    validate_commands_list, mask_sensitive_data, mask_command_output, redact_literal
)

logger = logging.getLogger(__name__)

_REPO_DIR = os.path.dirname(os.path.abspath(__file__))


def _env_int(name, default, minimum=1):
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    return value if value >= minimum else default


# Upper bound for a scan's concurrency (worker threads)
MAX_CONCURRENCY = _env_int('MAX_CONCURRENCY', 100)
# Per-command deadline (seconds) for user commands
SSH_COMMAND_TIMEOUT = _env_int('SSH_COMMAND_TIMEOUT', 60)
# Per-command deadline (seconds) for server-info and sudo-check commands
SSH_INFO_COMMAND_TIMEOUT = min(15, SSH_COMMAND_TIMEOUT)
# Connection timeouts (seconds)
SSH_CONNECT_TIMEOUT = _env_int('SSH_CONNECT_TIMEOUT', 10)
SSH_BANNER_TIMEOUT = 15
SSH_AUTH_TIMEOUT = 15
# Maximum bytes kept per stream (stdout / stderr) of a command
MAX_OUTPUT_BYTES = _env_int('SSH_MAX_OUTPUT_BYTES', 1024 * 1024)

_KNOWN_HOSTS_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Host key handling
# ---------------------------------------------------------------------------

def _host_key_policy_name():
    policy = os.environ.get('SSH_HOST_KEY_POLICY', 'tofu').strip().lower()
    if policy not in ('tofu', 'reject', 'warn'):
        logger.warning("Unknown SSH_HOST_KEY_POLICY %r, using 'tofu'", policy)
        policy = 'tofu'
    return policy


def _known_hosts_file():
    return os.environ.get('SSH_KNOWN_HOSTS_FILE') or os.path.join(_REPO_DIR, 'instance', 'known_hosts')


class TofuHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Trust on first use: record unknown host keys in the app's known_hosts file.

    Keys of hosts that are already known are verified by paramiko itself, which
    raises BadHostKeyException on a mismatch.
    """

    def __init__(self, path):
        self.path = path

    def missing_host_key(self, client, hostname, key):
        with _KNOWN_HOSTS_LOCK:
            # Another thread may have recorded this host meanwhile
            current = HostKeys()
            if os.path.exists(self.path):
                current.load(self.path)
            known = current.lookup(hostname)
            if known is not None and key.get_name() in known:
                if known[key.get_name()] != key:
                    raise paramiko.BadHostKeyException(hostname, key, known[key.get_name()])
                client.get_host_keys().add(hostname, key.get_name(), key)
                return
            directory = os.path.dirname(self.path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, 'a') as f:
                f.write(HostKeyEntry([hostname], key).to_line())
            client.get_host_keys().add(hostname, key.get_name(), key)
        logger.info("Recorded new %s host key for %s (trust on first use)", key.get_name(), hostname)


def _new_client():
    """Create an SSHClient with host keys loaded and the configured policy."""
    client = paramiko.SSHClient()
    try:
        client.load_system_host_keys()
    except (IOError, OSError, paramiko.SSHException) as e:
        logger.debug("Could not load system host keys: %s", e)

    path = _known_hosts_file()
    with _KNOWN_HOSTS_LOCK:
        if os.path.exists(path):
            try:
                client.load_host_keys(path)
            except (IOError, OSError, paramiko.SSHException) as e:
                logger.warning("Could not load known hosts file %s: %s", path, e)

    policy = _host_key_policy_name()
    if policy == 'reject':
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    elif policy == 'warn':
        client.set_missing_host_key_policy(paramiko.WarningPolicy())
    else:
        client.set_missing_host_key_policy(TofuHostKeyPolicy(path))
    return client


class HostKeyError(Exception):
    """The host key could not be verified; no credential should be tried."""


def _connect(ip, port, username, password=None, pkey=None):
    """Open a fresh SSH connection. Closes the client on failure."""
    client = _new_client()
    try:
        client.connect(
            ip, port=port, username=username, password=password, pkey=pkey,
            timeout=SSH_CONNECT_TIMEOUT, banner_timeout=SSH_BANNER_TIMEOUT,
            auth_timeout=SSH_AUTH_TIMEOUT, look_for_keys=False, allow_agent=False,
        )
        return client
    except paramiko.BadHostKeyException as e:
        client.close()
        raise HostKeyError(
            f"Host key verification FAILED for {ip}:{port}: the server presented a different "
            f"{e.key.get_name()} key than the one recorded in known_hosts (possible "
            "man-in-the-middle). Connection refused.") from e
    except paramiko.SSHException as e:
        client.close()
        if 'not found in known_hosts' in str(e):
            raise HostKeyError(
                f"Host key for {ip}:{port} is not in known_hosts and SSH_HOST_KEY_POLICY=reject. "
                "Connection refused.") from e
        raise
    except BaseException:
        client.close()
        raise


def load_private_key(key_data):
    """Load a private key, trying multiple key types (RSA, Ed25519, ECDSA, DSA)"""
    key_classes = [
        getattr(paramiko, "RSAKey", None),
        getattr(paramiko, "Ed25519Key", None),
        getattr(paramiko, "ECDSAKey", None),
        getattr(paramiko, "DSSKey", None),
    ]
    for key_class in key_classes:
        if key_class is None:
            continue
        try:
            return key_class.from_private_key(file_obj=io.StringIO(key_data))
        except (paramiko.SSHException, ValueError):
            continue
    raise paramiko.SSHException("Unable to parse private key - unsupported key type")


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------

def _wait_readable(chan, timeout):
    """Wait until the channel may have data, without busy-looping."""
    try:
        select.select([chan], [], [], timeout)
    except (TypeError, ValueError, OSError):
        time.sleep(min(timeout, 0.05))


def run_command(client, command, timeout=None, stdin_data=None, max_bytes=None):
    """
    Run one command on an open SSH connection, without a PTY.

    stdout and stderr are read concurrently until EOF, each capped at
    max_bytes (the rest is discarded and a marker appended). When the
    deadline passes the channel is closed and exit_status is -1.

    Returns a dict: {exit_status, stdout, stderr, timed_out}.
    """
    timeout = timeout or SSH_COMMAND_TIMEOUT
    max_bytes = max_bytes or MAX_OUTPUT_BYTES

    transport = client.get_transport()
    if transport is None or not transport.is_active():
        raise paramiko.SSHException("SSH transport is not available")

    chan = transport.open_session(timeout=SSH_CONNECT_TIMEOUT)
    out, err = bytearray(), bytearray()
    truncated = {'out': False, 'err': False}

    def keep(buf, data, which):
        room = max_bytes - len(buf)
        if room > 0:
            buf.extend(data[:room])
        if len(data) > max(room, 0):
            truncated[which] = True

    def drain():
        while chan.recv_ready():
            data = chan.recv(32768)
            if not data:
                break
            keep(out, data, 'out')
        while chan.recv_stderr_ready():
            data = chan.recv_stderr(32768)
            if not data:
                break
            keep(err, data, 'err')

    timed_out = False
    try:
        chan.settimeout(5.0)
        chan.exec_command(command)
        if stdin_data:
            chan.sendall(stdin_data.encode() if isinstance(stdin_data, str) else stdin_data)
        chan.shutdown_write()

        deadline = time.monotonic() + timeout
        while not chan.exit_status_ready():
            drain()
            if time.monotonic() >= deadline:
                timed_out = True
                break
            if chan.closed:
                break
            _wait_readable(chan, 0.2)

        if not timed_out:
            # Drain whatever arrives between the exit status and EOF.
            grace = min(deadline, time.monotonic() + 2.0)
            while not (chan.eof_received or chan.closed) and time.monotonic() < grace:
                drain()
                _wait_readable(chan, 0.1)
            drain()
    finally:
        exit_status = chan.recv_exit_status() if (chan.exit_status_ready() and not timed_out) else -1
        chan.close()

    stdout = out.decode('utf-8', errors='replace')
    stderr = err.decode('utf-8', errors='replace')
    if truncated['out']:
        stdout += f"\n[output truncated at {max_bytes} bytes]"
    if truncated['err']:
        stderr += f"\n[output truncated at {max_bytes} bytes]"
    if timed_out:
        stderr += ("\n" if stderr else "") + f"Command timed out after {timeout} seconds"
    return {'exit_status': exit_status, 'stdout': stdout, 'stderr': stderr, 'timed_out': timed_out}


def _sudo_wrap(command):
    """Rewrite a leading 'sudo ' to read the password from stdin without a prompt."""
    return "sudo -S -p '' " + command[len('sudo '):].lstrip()


def check_sudo(client, sudo_password=None):
    """
    Determine sudo access.

    Returns (has_sudo, needs_password). Passwordless sudo is detected with
    'sudo -n true'; otherwise the password is tried with "sudo -S -p '' true".
    """
    res = run_command(client, "sudo -n true", timeout=SSH_INFO_COMMAND_TIMEOUT)
    if res['exit_status'] == 0:
        return True, False
    if not sudo_password:
        return False, False
    res = run_command(client, "sudo -S -p '' true", timeout=SSH_INFO_COMMAND_TIMEOUT,
                      stdin_data=sudo_password + "\n")
    return res['exit_status'] == 0, True


def collect_server_info(ssh_client, detailed=False):
    """Collect server information using SSH client

    Args:
        ssh_client: Paramiko SSH client
        detailed: Whether to collect detailed information (more commands, deeper analysis)

    Returns:
        Dictionary containing server information
    """
    def run(cmd):
        # Mask before parsing so key=value secrets are caught in context
        return mask_command_output(
            run_command(ssh_client, cmd, timeout=SSH_INFO_COMMAND_TIMEOUT)['stdout']).strip()

    server_info = {}
    try:
        server_info['hostname'] = run("hostname -f")

        os_info = {}
        for line in run("cat /etc/os-release").split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                os_info[key] = value.strip('"')
        server_info['os'] = os_info

        server_info['kernel'] = run("uname -r")

        cpu_info = {}
        for line in run("lscpu").split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                cpu_info[key.strip()] = value.strip()
        server_info['cpu'] = cpu_info

        memory_lines = run("free -m").split('\n')
        if len(memory_lines) >= 2:
            memory_parts = memory_lines[1].split()
            if len(memory_parts) >= 4:
                server_info['memory'] = {
                    'total': f"{memory_parts[1]} MB",
                    'used': f"{memory_parts[2]} MB",
                    'free': f"{memory_parts[3]} MB"
                }

        server_info['disk'] = run("df -h").split('\n')

        try:
            server_info['network'] = json.loads(run("ip -j addr"))
        except json.JSONDecodeError:
            server_info['network'] = run("ip addr").split('\n')

        server_info['uptime'] = run("uptime -p")

        if detailed:
            server_info['dns_config'] = run("cat /etc/resolv.conf").split('\n')
            server_info['running_services'] = run(
                "systemctl list-units --type=service --state=running").split('\n')
            server_info['installed_packages'] = run("dpkg-query -l | head -100").split('\n')
            server_info['network_connections'] = run("ss -tuln").split('\n')
            server_info['ethernet_cards'] = run("lshw -class network -short").split('\n')
            server_info['user_accounts'] = run(
                "cat /etc/passwd | grep -v nologin | grep -v false").split('\n')
            server_info['load_average'] = run("cat /proc/loadavg")
            server_info['default_gateway'] = run("ip route | grep default")
            server_info['firewall_rules'] = run("iptables -L -n").split('\n')
            virtualization = run("hostnamectl | grep Virtualization")
            server_info['virtualization'] = virtualization if virtualization else "Not detected"

        return server_info
    except Exception as e:
        logger.error("Error collecting server info: %s", mask_sensitive_data(str(e)))
        return {"error": mask_sensitive_data(str(e))}


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------

def _decrypt_field(value, label, errors):
    if not value:
        return None
    try:
        return decrypt_data(value)
    except DecryptionError:
        errors.append(f"{label} could not be decrypted (encryption key changed?)")
        return None


def _credential_to_dict(cred):
    """Copy a CredentialSet (attached to a session) into a plain dict."""
    errors = []
    data = {
        'id': cred.id,
        'username': cred.username,
        'auth_type': cred.auth_type,
        'priority': cred.priority or 0,
        'password': _decrypt_field(cred.password_encrypted, 'password', errors),
        'private_key': _decrypt_field(cred.private_key_encrypted, 'private key', errors),
        'sudo_password': _decrypt_field(cred.sudo_password_encrypted, 'sudo password', errors),
    }
    data['error'] = "; ".join(errors) if errors else None
    return data


def load_credential_sets(credential_set_ids):
    """Load credential sets by id into plain dicts, sorted by priority (highest first).

    Must be called inside an app context.
    """
    if not credential_set_ids:
        return []
    ids = [int(i) for i in credential_set_ids]
    creds = CredentialSet.query.filter(CredentialSet.id.in_(ids)).all()
    found = {c.id for c in creds}
    for missing in sorted(set(ids) - found):
        logger.warning("Credential set %s no longer exists", missing)
    dicts = [_credential_to_dict(c) for c in creds]
    return sorted(dicts, key=lambda c: c['priority'], reverse=True)


def _attempt_list(username, password, private_key, credentials):
    attempts = list(credentials or [])
    if username and (password or private_key):
        attempts.append({
            'id': None, 'username': username,
            'auth_type': 'key' if private_key else 'password',
            'password': password, 'private_key': private_key,
            'sudo_password': None, 'priority': None, 'error': None,
        })
    return attempts


def _try_connect(ip, port, attempts, auth_errors):
    """Try each credential with a fresh client. Returns (client, credential) or (None, None)."""
    for cred in attempts:
        user = cred.get('username') or ''
        label = f"user {user}" + (f" (credential set {cred['id']})" if cred.get('id') else "")
        auth_type = cred.get('auth_type') or 'password'

        if cred.get('error') and not (cred.get('password') if auth_type == 'password' else cred.get('private_key')):
            auth_errors.append(f"Skipped {label}: {cred['error']}")
            continue
        if not user:
            auth_errors.append(f"Skipped {label}: no username")
            continue

        try:
            if auth_type == 'key':
                if not cred.get('private_key'):
                    auth_errors.append(f"Skipped {label}: no private key available")
                    continue
                pkey = load_private_key(cred['private_key'])
                client = _connect(ip, port, user, pkey=pkey)
            else:
                if not cred.get('password'):
                    auth_errors.append(f"Skipped {label}: no password available")
                    continue
                client = _connect(ip, port, user, password=cred['password'])
            return client, cred
        except HostKeyError:
            raise
        except paramiko.AuthenticationException as e:
            auth_errors.append(f"Authentication failed for {label}: {e}")
        except (socket.timeout, TimeoutError):
            auth_errors.append(f"Connection to {ip}:{port} timed out")
            break
        except (paramiko.ssh_exception.NoValidConnectionsError, ConnectionError, socket.gaierror) as e:
            auth_errors.append(f"Connection error: {e}")
            break
        except paramiko.SSHException as e:
            auth_errors.append(f"SSH error for {label}: {e}")
        except Exception as e:
            auth_errors.append(f"Connection error for {label}: {e}")
    return None, None


# ---------------------------------------------------------------------------
# Per-host scan
# ---------------------------------------------------------------------------

def _scan_host(ip, port, attempts, sudo_password, commands, collect_info, collect_detailed_info):
    """Do all network I/O for one host. Returns a dict of ScanResult fields."""
    fields = {'status_code': 'failed', 'ssh_status': False, 'sudo_status': False,
              'command_status': False, 'command_output': None, 'server_info': None,
              'error_message': None}
    auth_errors = []
    client = None
    secrets = []

    def scrub(text):
        if not text:
            return text
        for secret in secrets:
            text = redact_literal(text, secret)
        return mask_command_output(text)

    try:
        client, cred = _try_connect(ip, port, attempts, auth_errors)
        if client is None:
            fields['error_message'] = scrub(
                "Authentication failed with all credentials: " + "; ".join(auth_errors)
                if auth_errors else "No usable credentials were provided")
            return fields

        fields['ssh_status'] = True
        if cred.get('password'):
            secrets.append(cred['password'])
        sudo_pw = cred.get('sudo_password') or sudo_password
        if sudo_pw:
            secrets.append(sudo_pw)

        if commands:
            needs_password = False
            try:
                fields['sudo_status'], needs_password = check_sudo(client, sudo_pw)
            except Exception as e:
                logger.warning("Sudo check failed for %s: %s", ip, scrub(str(e)))

            _, validation = validate_commands_list(commands)
            command_output = []
            all_ok = True
            for cmd, (is_safe, reason) in zip(commands, validation):
                if not is_safe:
                    command_output.append({
                        'command': cmd, 'exit_status': -2, 'stdout': '',
                        'stderr': f"Command rejected due to security concerns: {reason}",
                        'success': False, 'security_blocked': True,
                    })
                    all_ok = False
                    continue
                try:
                    if cmd.startswith('sudo ') and sudo_pw and needs_password:
                        res = run_command(client, _sudo_wrap(cmd), stdin_data=sudo_pw + "\n")
                    else:
                        res = run_command(client, cmd)
                    entry = {
                        'command': cmd,
                        'exit_status': res['exit_status'],
                        'stdout': scrub(res['stdout']),
                        'stderr': scrub(res['stderr']),
                        'success': res['exit_status'] == 0,
                        'security_blocked': False,
                    }
                except Exception as e:
                    entry = {'command': cmd, 'exit_status': -1, 'stdout': '',
                             'stderr': scrub(str(e)), 'success': False, 'security_blocked': False}
                command_output.append(entry)
                if not entry['success']:
                    all_ok = False
            fields['command_status'] = all_ok
            fields['command_output'] = json.dumps(command_output)

        if collect_info:
            info = collect_server_info(client, detailed=collect_detailed_info)

            def clean(data):
                if isinstance(data, dict):
                    return {k: clean(v) for k, v in data.items()}
                if isinstance(data, list):
                    return [clean(v) for v in data]
                if isinstance(data, str):
                    return scrub(data)
                return data
            fields['server_info'] = json.dumps(clean(info))

        fields['status_code'] = 'success'
    except HostKeyError as e:
        fields['error_message'] = str(e)
    except socket.timeout:
        fields['error_message'] = "Connection timed out"
    except socket.error as e:
        fields['error_message'] = f"Socket error: {scrub(str(e))}"
    except Exception as e:
        fields['error_message'] = f"Error: {scrub(str(e))}"
    finally:
        if client is not None:
            client.close()
    return fields


def execute_ssh_commands(ip, username, password=None, private_key=None, sudo_password=None,
                         commands=None, collect_info=False, collect_detailed_info=False,
                         scan_session_id=None, credential_sets=None, port=22,
                         credential_set_ids=None):
    """
    Scan one host: connect, run commands, collect info, and store a ScanResult.

    Args:
        credential_sets: optional list of plain credential dicts (keys: id,
            username, auth_type, password, private_key, sudo_password,
            priority, error), tried before username/password/private_key.
        credential_set_ids: optional list of CredentialSet ids; they are
            loaded and decrypted here, inside this thread's app context.

    Returns a dict with the stored result fields (including 'status_code').
    """
    start_time = time.time()
    port = int(port or 22)

    with app.app_context():
        result = ScanResult(scan_session_id=scan_session_id, ip_address=ip, status_code='pending')
        db.session.add(result)
        db.session.commit()
        result_id = result.id

        credentials = []
        load_error = None
        try:
            if credential_set_ids:
                credentials.extend(load_credential_sets(credential_set_ids))
        except Exception as e:
            load_error = f"Could not load credential sets: {mask_sensitive_data(str(e))}"
            logger.error(load_error)
        for cred in credential_sets or []:
            credentials.append(cred if isinstance(cred, dict) else _credential_to_dict(cred))
        credentials.sort(key=lambda c: c.get('priority') or 0, reverse=True)

    # Network I/O happens outside the app context so no DB connection is held.
    try:
        fields = _scan_host(ip, port, _attempt_list(username, password, private_key, credentials),
                            sudo_password, commands, collect_info, collect_detailed_info)
    except Exception as e:  # defensive: _scan_host already catches errors
        fields = {'status_code': 'failed', 'error_message': f"Error: {mask_sensitive_data(str(e))}"}
    if load_error and fields.get('status_code') != 'success':
        fields['error_message'] = load_error + ("; " + fields['error_message'] if fields.get('error_message') else "")
    fields['execution_time'] = time.time() - start_time

    with app.app_context():
        result = db.session.get(ScanResult, result_id)
        for key, value in fields.items():
            setattr(result, key, value)
        db.session.commit()

    fields['ip_address'] = ip
    return fields


def start_scan_session(scan_session_id, ip_addresses, username, password=None, private_key=None,
                       commands=None, collect_server_info=False, collect_detailed_info=False,
                       sudo_password=None, credential_set_ids=None, concurrency=10, port=22):
    """
    Start a scan in a background thread and return the started threading.Thread.

    Works from a request or from the scheduler thread: the worker pushes its
    own app context. The session's final status is always set in a finally
    block: 'completed' if any host succeeded (or there were no IPs), else
    'failed'.
    """
    try:
        concurrency = int(concurrency)
    except (TypeError, ValueError):
        concurrency = 10
    concurrency = max(1, min(concurrency, MAX_CONCURRENCY))
    ips = list(ip_addresses or [])
    cred_ids = [int(i) for i in credential_set_ids] if credential_set_ids else None
    do_collect = bool(collect_server_info)

    def scan_worker():
        any_success = False
        crashed = False
        try:
            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                ip_iter = iter(ips)
                pending = set()
                max_pending = concurrency * 2

                def submit_more():
                    while len(pending) < max_pending:
                        ip = next(ip_iter, None)
                        if ip is None:
                            return
                        pending.add(executor.submit(
                            execute_ssh_commands, ip, username, password, private_key,
                            sudo_password, commands, do_collect, collect_detailed_info,
                            scan_session_id, None, port, cred_ids))

                submit_more()
                while pending:
                    done, _ = wait(pending, return_when=FIRST_COMPLETED)
                    for future in done:
                        pending.discard(future)
                        try:
                            res = future.result()
                            if res and res.get('status_code') == 'success':
                                any_success = True
                        except Exception as e:
                            logger.error("Host scan error: %s", mask_sensitive_data(str(e)))
                    submit_more()
        except Exception as e:
            crashed = True
            logger.exception("Scan session %s crashed: %s", scan_session_id, mask_sensitive_data(str(e)))
        finally:
            status = 'completed' if (not crashed and (any_success or not ips)) else 'failed'
            try:
                with app.app_context():
                    scan_session = db.session.get(ScanSession, scan_session_id)
                    if scan_session:
                        scan_session.status = status
                        scan_session.completed_at = datetime.utcnow()
                        db.session.commit()
            except Exception as e:
                logger.error("Could not update scan session %s status: %s", scan_session_id, e)

    scan_thread = threading.Thread(target=scan_worker, name=f"scan-{scan_session_id}", daemon=True)
    scan_thread.start()
    return scan_thread
