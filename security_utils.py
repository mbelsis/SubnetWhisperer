"""
Security utility functions for command filtering and sensitive data masking.

IMPORTANT: the command filter in this module is a best-effort guardrail that
catches common mistakes and obviously destructive commands. It is NOT a
security boundary: anyone allowed to run commands on a host can run whatever
that account is allowed to run. Use least-privilege accounts on the targets.
"""
import os
import re
import shlex
import logging

logger = logging.getLogger(__name__)

# Block devices that dd/shred/wipefs must never write to
_BLOCK_DEVICE_RE = re.compile(r'^/dev/(sd|hd|nvme|vd|xvd|mmcblk)\w*$')

# Programs that power the machine off or reboot it (matched as argv[0])
_POWER_COMMANDS = {'shutdown', 'reboot', 'halt', 'poweroff'}

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


def _is_sanitization_enabled():
    """Check if command sanitization is enabled via environment variable."""
    return os.environ.get('COMMAND_SANITIZATION', 'enabled').lower() != 'disabled'


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
        elif head == 'sudo':
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
    argv, sudo_flags = _strip_prefixes(argv)

    for flag in sudo_flags:
        if flag in ('-i', '-s', '--login', '--shell') or (
                flag.startswith('-') and not flag.startswith('--') and
                any(c in flag[1:] for c in 'is')):
            return "Interactive sudo shells (sudo -i / sudo -s) are blocked"

    if not argv:
        return None

    prog = os.path.basename(argv[0]).lower()
    args = argv[1:]

    # Look inside `bash -c "..."` style wrappers
    if prog in _SHELLS:
        for i, a in enumerate(args):
            if a.startswith('-') and not a.startswith('--') and 'c' in a[1:] and i + 1 < len(args):
                return _check_script(args[i + 1], depth)
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
                if t in ('/', '/*', '//', '~', '~/', '~/*', '$HOME', '$HOME/', '$HOME/*'):
                    return f"Recursive removal of '{t}' is blocked"
        return None

    if prog == 'find':
        if '-delete' in args and any(a in ('/', '//', '/*') for a in args):
            return "find / -delete is blocked"
        return None

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

    for a in args:
        if a == '/etc/shadow' or a.startswith('/etc/shadow'):
            return "Access to /etc/shadow is blocked"
        if a == '/etc/gshadow':
            return "Access to /etc/gshadow is blocked"

    return None


def sanitize_command(command):
    """
    Check whether a command may be run on the scanned hosts.

    This is a best-effort guardrail, not a security boundary.

    Always blocked (in every mode): recursive rm of /, /* or ~, find / -delete,
    mkfs*, dd/shred/wipefs writes to block devices, fork bombs, curl/wget piped
    into a shell, shutdown/reboot/halt/poweroff, init/telinit 0|6, sudo -i,
    sudo -s, sudo su, and access to /etc/shadow.

    In enabled mode (COMMAND_SANITIZATION is not "disabled", the default) shell
    operators (; && || & | > < backticks $( ${ and newlines) and restricted
    programs (systemctl, chmod, useradd, ...) are blocked as well.

    Args:
        command: The command string to check

    Returns:
        (bool, str): (is_safe, command_or_error_message)
    """
    if not command or not isinstance(command, str) or not command.strip():
        return (False, "Invalid command")

    enabled = _is_sanitization_enabled()
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


def validate_commands_list(commands):
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
        is_safe, result = sanitize_command(cmd)
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
