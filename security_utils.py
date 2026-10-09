"""
Security utility functions for command filtering and sensitive data masking.

IMPORTANT: the denylist checks in this module are a best-effort guardrail that
catches common mistakes and obviously destructive commands. A denylist over
shell commands can always be bypassed (interpreters such as python -c, encoded
payloads, scripts already on the host, ...), so it is NOT a security boundary.

For a real control set COMMAND_SANITIZATION=allowlist: only command lines that
appear verbatim in an admin-managed command template may run. Combine it with
least-privilege accounts and a sudoers allowlist on the target hosts.
"""
import os
import re
import shlex
import logging
import posixpath

logger = logging.getLogger(__name__)

# Block devices that dd/shred/wipefs must never write to
_BLOCK_DEVICE_RE = re.compile(r'^/dev/(sd|hd|nvme|vd|xvd|mmcblk)\w*$')

# Programs that power the machine off or reboot it (matched as argv[0])
_POWER_COMMANDS = {'shutdown', 'reboot', 'halt', 'poweroff', 'kexec'}

# systemctl / loginctl verbs that change the power state or drop to a rescue target
_POWER_VERBS = {'reboot', 'poweroff', 'halt', 'kexec', 'suspend', 'hibernate', 'hybrid-sleep',
                'suspend-then-hibernate', 'rescue', 'emergency', 'isolate', 'soft-reboot',
                'default', 'exit'}

# Paths that a recursive rm must never target (compared after normalization)
_PROTECTED_RM_TARGETS = {'/', '/*', '~', '~/*', '$HOME', '$HOME/*', '${HOME}', '${HOME}/*'}

# Files whose contents are password hashes
_SHADOW_FILES = {'/etc/shadow', '/etc/gshadow', '/etc/shadow-', '/etc/gshadow-'}

MODES = ('enabled', 'disabled', 'allowlist')

# Restricted programs (matched against argv[0], only in enabled mode)
RESTRICTED_COMMANDS = {
    'su', 'iptables', 'ip6tables', 'nft', 'firewall-cmd', 'ufw',
    'chmod', 'chown', 'chgrp',
    'visudo', 'fdisk', 'parted', 'sfdisk', 'gdisk',
    'systemctl', 'service',
    'useradd', 'usermod', 'userdel', 'adduser', 'deluser', 'passwd', 'chpasswd',
    'groupadd', 'groupmod', 'groupdel',
    'ssh-keygen', 'cryptsetup',
    'tcpdump', 'tshark',
}

# Shell metacharacters that are refused in enabled mode
_SHELL_OPERATORS = [
    ('\n', 'newline characters'),
    ('\r', 'carriage return characters'),
    ('&&', "'&&'"),
    ('||', "'||'"),
    (';', "';'"),
    ('&', "'&'"),
    ('|', "'|'"),
    ('>', "'>'"),
    ('<', "'<'"),
    ('`', 'backticks'),
    ('$(', "'$('"),
    ('${', "'${'"),
]

_FORK_BOMB_RE = re.compile(r'([\w:.]+)\s*\(\s*\)\s*\{[^}]*?\1\s*\|\s*\1')
_PIPE_TO_SHELL_RE = re.compile(
    r'\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(\S*/)?(ba|da|z|k)?sh\b')

# Patterns for sensitive data that should be masked in logs and outputs.
# Patterns with a capture group mask only group 1; patterns without one mask
# the whole match.
SENSITIVE_DATA_PATTERNS = [
    # Password patterns
    r'(?i)(?<![A-Za-z0-9])(?:password|passwd|pwd|pass)\s*[=:]\s*([^\s;]+)',

    # API key and token patterns
    r'(?i)(?<![A-Za-z0-9])api[-_]?key\s*[=:]\s*([^\s;]+)',
    r'(?i)(?<![A-Za-z0-9])auth[-_]?token\s*[=:]\s*([^\s;]+)',
    r'(?i)(?<![A-Za-z0-9])access[-_]?token\s*[=:]\s*([^\s;]+)',
    r'(?i)(?<![A-Za-z0-9])secret[-_]?key\s*[=:]\s*([^\s;]+)',

    # PEM private keys of any type (RSA, EC, OPENSSH, PKCS#8, ENCRYPTED, ...)
    r'(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----',

    # Credentials in URLs and database connection strings
    r'(?i)\b(?:https?|ftp|mongodb(?:\+srv)?|mysql|postgres|postgresql|redis)://[^:/@\s]+:([^@\s]+)@',

    # Encrypted values that might be sensitive
    r'(?i)(?<![A-Za-z0-9])encrypted_(?:password|key|token)\s*[=:]\s*([^\s;]+)',
]

_PEM_REPLACEMENT = "-----BEGIN PRIVATE KEY-----***REDACTED***-----END PRIVATE KEY-----"

_COMPILED_SENSITIVE = [re.compile(p) for p in SENSITIVE_DATA_PATTERNS]


def sanitization_mode():
    """Return the COMMAND_SANITIZATION mode: 'enabled' (default), 'disabled' or 'allowlist'."""
    mode = (os.environ.get('COMMAND_SANITIZATION') or 'enabled').strip().lower()
    if mode not in MODES:
        logger.warning("Unknown COMMAND_SANITIZATION %r, using 'enabled'", mode)
        mode = 'enabled'
    return mode


def _is_sanitization_enabled():
    """True when shell operators and restricted programs are blocked (enabled mode)."""
    return sanitization_mode() == 'enabled'


def is_allowlist_mode():
    return sanitization_mode() == 'allowlist'


def _normalize_path(arg):
    """Collapse '.', '..' and repeated slashes so '/etc/../etc//shadow' == '/etc/shadow'."""
    if not arg:
        return arg
    trailing_glob = arg.endswith('/*')
    base = arg[:-2] if trailing_glob else arg
    if base.startswith('/'):
        base = posixpath.normpath(base)
        if base.startswith('//'):
            base = '/' + base.lstrip('/')
    elif base.startswith(('~', '$HOME', '${HOME}')):
        head, _, rest = base.partition('/')
        base = head if not rest else head + '/' + posixpath.normpath(rest)
        if base.endswith('/.'):
            base = base[:-2]
    if trailing_glob:
        return '/*' if base == '/' else base + '/*'
    return base


def _tokenize(command):
    """Split a command into tokens. Returns (tokens, shlex_ok)."""
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=';&|<>()')
        lexer.whitespace_split = True
        lexer.commenters = ''
        return list(lexer), True
    except ValueError:
        return command.split(), False


def _split_simple_commands(tokens):
    """Split a token list into simple commands at shell operators."""
    commands, current = [], []
    for tok in tokens:
        if tok and all(c in ';&|()' for c in tok):
            if current:
                commands.append(current)
            current = []
        else:
            current.append(tok)
    if current:
        commands.append(current)
    return commands


def _strip_prefixes(argv):
    """Remove leading sudo/env/nohup/time wrappers and VAR=value assignments.

    Returns (argv_without_prefix, sudo_flags) where sudo_flags is the list of
    options given to sudo.
    """
    argv = list(argv)
    sudo_flags = []
    changed = True
    while argv and changed:
        changed = False
        head = os.path.basename(argv[0])
        if re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', argv[0]):
            argv.pop(0)
            changed = True
        elif head in ('sudo', 'doas', 'pkexec'):
            argv.pop(0)
            while argv and argv[0].startswith('-'):
                flag = argv.pop(0)
                sudo_flags.append(flag)
                # options that take a value
                if flag in ('-u', '-g', '-p', '-C', '-h', '-r', '-t', '-U', '-D', '-R', '-T') and argv:
                    argv.pop(0)
            changed = True
        elif head in ('env', 'nohup', 'time', 'nice', 'ionice', 'command', 'exec', 'busybox'):
            argv.pop(0)
            while argv and argv[0].startswith('-'):
                argv.pop(0)
            changed = True
    return argv, sudo_flags


_SHELLS = {'sh', 'bash', 'dash', 'zsh', 'ksh', 'ash', 'busybox'}


def _check_script(script, depth):
    """Apply the always-blocked checks to a script passed to `sh -c` and similar."""
    if depth > 3:
        return "Deeply nested shell invocations are blocked"
    if _FORK_BOMB_RE.search(script):
        return "Fork bombs are blocked"
    if _PIPE_TO_SHELL_RE.search(script):
        return "Piping curl/wget output into a shell is blocked"
    tokens, _ = _tokenize(script.replace('\r', '\n').replace('\n', ' ; '))
    for argv in _split_simple_commands(tokens):
        reason = _check_dangerous_argv(argv, depth + 1)
        if reason:
            return reason
    return None


def _check_dangerous_argv(argv, depth=0):
    """Return an error message if a simple command is always-blocked."""
    original = list(argv)
    argv, sudo_flags = _strip_prefixes(argv)
    prefix = original[:len(original) - len(argv)]
    sudo_used = any(os.path.basename(t) in ('sudo', 'doas', 'pkexec') for t in prefix)

    for flag in sudo_flags:
        if flag in ('-i', '-s', '--login', '--shell') or (
                flag.startswith('-') and not flag.startswith('--') and
                any(c in flag[1:] for c in 'is')):
            return "Interactive sudo shells (sudo -i / sudo -s) are blocked"

    if not argv:
        return None

    prog = os.path.basename(argv[0]).lower()
    args = argv[1:]

    for a in args:
        candidate = a.split('=', 1)[1] if a.startswith(('if=', 'of=')) else a
        if '/' in candidate and _normalize_path(candidate) in _SHADOW_FILES:
            return "Access to password hash files (/etc/shadow, /etc/gshadow) is blocked"

    # Look inside `bash -c "..."` style wrappers
    if prog in _SHELLS:
        for i, a in enumerate(args):
            if a.startswith('-') and not a.startswith('--') and 'c' in a[1:] and i + 1 < len(args):
                return _check_script(args[i + 1], depth)
        if sudo_used:
            return "Starting a root shell through sudo is blocked"
        return None

    if prog in _POWER_COMMANDS:
        return f"Power-state command '{prog}' is blocked"
    if prog in ('init', 'telinit') and any(a in ('0', '6') for a in args):
        return f"'{prog} {' '.join(args)}' (shutdown/reboot) is blocked"

    if prog.startswith('mkfs'):
        return "Filesystem creation (mkfs) is blocked"

    if prog == 'rm':
        recursive = False
        no_preserve = False
        targets = []
        end_opts = False
        for a in args:
            if not end_opts and a == '--':
                end_opts = True
            elif not end_opts and a.startswith('--'):
                if a == '--recursive':
                    recursive = True
                elif a == '--no-preserve-root':
                    no_preserve = True
            elif not end_opts and a.startswith('-') and len(a) > 1:
                if 'r' in a[1:] or 'R' in a[1:]:
                    recursive = True
            else:
                targets.append(a)
        if no_preserve:
            return "rm --no-preserve-root is blocked"
        if recursive:
            for t in targets:
                normalized = _normalize_path(t.rstrip('/') or '/')
                if normalized in _PROTECTED_RM_TARGETS or _normalize_path(t) in _PROTECTED_RM_TARGETS:
                    return f"Recursive removal of '{t}' is blocked"
        return None

    if prog == 'find':
        if '-delete' in args and any(_normalize_path(a) in ('/', '/*') for a in args if a.startswith('/')):
            return "find / -delete is blocked"
        return None

    if prog in ('systemctl', 'loginctl') and any(a in _POWER_VERBS for a in args):
        verb = next(a for a in args if a in _POWER_VERBS)
        return f"'{prog} {verb}' (power state / rescue target) is blocked"

    if prog == 'dd':
        for a in args:
            if a.startswith('of=') and _BLOCK_DEVICE_RE.match(a[3:]):
                return f"dd writing to block device {a[3:]} is blocked"
        return None

    if prog in ('shred', 'wipefs'):
        for a in args:
            if _BLOCK_DEVICE_RE.match(a):
                return f"{prog} on block device {a} is blocked"
        return None

    return None


def sanitize_command(command, allowed_commands=None):
    """
    Check whether a command may be run on the scanned hosts.

    Always blocked (in every mode): recursive rm of /, /* or ~ (also via
    '/.', '//' etc.), find / -delete, mkfs*, dd/shred/wipefs writes
    to block devices, fork bombs, curl/wget piped into a shell,
    shutdown/reboot/halt/poweroff, systemctl/loginctl power verbs,
    init/telinit 0|6, sudo -i, sudo -s, sudo su, sudo <shell>, and access to
    /etc/shadow or /etc/gshadow. These checks are a best-effort guardrail.

    enabled mode (the default): shell operators (; && || & | > < backticks
    $( ${ and newlines) and restricted programs (systemctl, chmod, useradd,
    ...) are blocked as well.

    allowlist mode: the command must also match, verbatim (after trimming), a
    line of an admin-managed command template. allowed_commands is that set;
    when it is None in allowlist mode every command is refused (fail closed).

    Args:
        command: The command string to check
        allowed_commands: set of approved command lines (allowlist mode only)

    Returns:
        (bool, str): (is_safe, command_or_error_message)
    """
    if not command or not isinstance(command, str) or not command.strip():
        return (False, "Invalid command")

    mode = sanitization_mode()
    enabled = mode == 'enabled'

    if mode == 'allowlist' and command.strip() not in (allowed_commands or ()):
        logger.warning("Blocked command (not in an approved template): %s",
                       mask_sensitive_data(command).replace('\r', '\\r').replace('\n', '\\n'))
        return (False, "Command is not in an approved command template "
                       "(COMMAND_SANITIZATION=allowlist)")
    safe_log = mask_sensitive_data(command).replace('\r', '\\r').replace('\n', '\\n')

    def block(reason):
        logger.warning("Blocked command (%s): %s", reason, safe_log)
        return (False, reason)

    # Raw-text checks that do not depend on tokenization
    if _FORK_BOMB_RE.search(command):
        return block("Fork bombs are blocked")
    if _PIPE_TO_SHELL_RE.search(command):
        return block("Piping curl/wget output into a shell is blocked")

    # Newlines separate commands in a shell; treat them like ';' for analysis.
    tokens, shlex_ok = _tokenize(command.replace('\r', '\n').replace('\n', ' ; '))

    if enabled:
        if not shlex_ok:
            return block("Command has unbalanced quotes")
        for op, label in _SHELL_OPERATORS:
            if op in command:
                return block(f"Shell operator {label} is not allowed")

    simple_commands = _split_simple_commands(tokens)
    for argv in simple_commands:
        reason = _check_dangerous_argv(argv)
        if reason:
            return block(reason)
        stripped, sudo_flags = _strip_prefixes(argv)
        if stripped and os.path.basename(stripped[0]).lower() == 'su' and \
                any(os.path.basename(t) == 'sudo' for t in argv):
            return block("sudo su is blocked")

    if enabled:
        for argv in simple_commands:
            stripped, _ = _strip_prefixes(argv)
            if stripped:
                prog = os.path.basename(stripped[0]).lower()
                if prog in RESTRICTED_COMMANDS:
                    return block(f"Restricted command '{prog}' is not allowed while "
                                 f"COMMAND_SANITIZATION is enabled")

    return (True, command)


def validate_commands_list(commands, allowed_commands=None):
    """
    Validate a list of commands, checking each for safety.

    Returns:
        (bool, list): (all_safe, [(is_safe, command_or_error), ...])
    """
    if not commands:
        return (True, [])

    results = []
    all_safe = True
    for cmd in commands:
        is_safe, result = sanitize_command(cmd, allowed_commands)
        results.append((is_safe, result))
        if not is_safe:
            all_safe = False
    return (all_safe, results)


def redact_literal(text, secret, replacement="***REDACTED***"):
    """Replace every occurrence of a literal secret string in text."""
    if not text or not secret or not isinstance(text, str) or not isinstance(secret, str):
        return text
    return text.replace(secret, replacement)


def mask_sensitive_data(data, replacement="***REDACTED***"):
    """
    Mask sensitive data in a string to prevent exposure in logs or outputs.

    Only the matched value (capture group 1) is replaced, using match offsets,
    so identical text elsewhere in the string is left alone.
    """
    if not data or not isinstance(data, str):
        return data

    def _sub(match):
        if match.re.groups >= 1 and match.group(1) is not None:
            start, end = match.span(1)
            m_start = match.start(0)
            whole = match.group(0)
            return whole[:start - m_start] + replacement + whole[end - m_start:]
        if 'PRIVATE KEY' in match.re.pattern:
            return _PEM_REPLACEMENT
        return replacement

    masked = data
    for regex in _COMPILED_SENSITIVE:
        masked = regex.sub(_sub, masked)
    return masked


def mask_command_output(output):
    """Mask sensitive information (passwords, tokens, private keys) in command output."""
    if not output:
        return output
    return mask_sensitive_data(output)
