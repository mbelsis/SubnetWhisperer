"""
Security utility functions for command sanitization, validation, and sensitive data masking
"""
import re
import logging
import base64
import hashlib

# Configure logging
logger = logging.getLogger(__name__)

# List of dangerous commands that should be blocked
DANGEROUS_COMMANDS = [
    'rm -rf /', 'rm -rf /*', 'rm -rf ~', 'rm -rf .', 'rm -rf *',  # Destructive file operations
    'mkfs', 'dd if=/dev/zero',                                     # Disk formatting
    '> /dev/sda', '/dev/null > /dev/sda',                          # Disk corruption
    'mv /* /dev/null', 'cat /dev/zero > ',                         # Destructive moves
    'fork bomb', ':(){ :|:& };:',                                  # Fork bombs
    'wget | bash', 'curl | bash',                                  # Arbitrary execution
    'echo .* | xargs rm',                                          # Hidden file removal
    'shutdown', 'reboot', 'halt', 'poweroff',                      # System power commands
    'passwd', 'adduser', 'deluser',                                # User management without explicit allowance
    'chmod -R 777 /',                                              # Insecure permissions
    'chown -R',                                                    # Recursive ownership change
    '/etc/shadow', '/etc/passwd',                                  # Sensitive file access 
    'iptables -F', 'ufw disable',                                  # Firewall disabling
]

# Regex patterns for dangerous command components
DANGEROUS_PATTERNS = [
    r'^\s*rm\s+-rf\s+[/~]',                     # rm -rf targeting root, home
    r'^\s*dd\s+.*\s+of=/dev/[sh]d[a-z]',        # dd writing to disk devices
    r'>\s*/dev/[sh]d[a-z]',                     # Redirecting to disk devices
    r'.*[;&|]\s*rm\s+-rf\s+/',                  # Chained destructive commands
    r';rm\s+',                                  # Semicolon followed by rm
    r'\|\s*rm\s+',                              # Pipe to rm
    r'>\s*/etc/',                               # Redirecting to system config
    r'^\s*sudo\s+su\s+',                        # Privilege escalation
    r'[;&|]\s*sudo\s+su',                       # Chained privilege escalation
    r'[;&|]\s*reboot',                          # Chained reboot
    r'[;&|]\s*shutdown',                        # Chained shutdown
    r'init\s+[06]',                             # Init calls for shutdown/reboot
    r':\(\)\s*{\s*:\s*\|\s*:\s*&\s*}\s*;\s*:',  # Fork bomb
    r'wget\s+.*\s*\|\s*bash',                   # Downloading and executing
    r'curl\s+.*\s*\|\s*bash',                   # Downloading and executing
    r'wget\s+.*\s*\|\s*sh',                     # Downloading and executing with sh
    r'curl\s+.*\s*\|\s*sh',                     # Downloading and executing with sh
    r'nc\s+.*\s+-e\s+',                         # Netcat execution
    r'base64\s+.*\s*\|\s*bash',                 # Base64 decode and execute
    r'[\s;&|](sudo\s+)?rm\s+.*\s+--no-preserve-root',  # Remove with no preserve root
    r'[\s;&|]sudo\s+.*-i',                      # Interactive sudo (could allow shell)
    r'[;<>&|]\s*\[\w+\]\(\)\s*{\s*.*\s*}\s*',   # Function definition in command chain
]

# Commands that require extra scrutiny (e.g., admin approval)
RESTRICTED_COMMANDS = [
    'sudo ', 'su ', 'iptables', 'firewall-cmd',
    'chmod ', 'chown ', 'chgrp ',
    'visudo', 'fdisk', 'parted',
    'systemctl', 'service ', 'systemd-',
    'useradd', 'usermod', 'userdel',
    'groupadd', 'groupmod', 'groupdel',
    'ssh-keygen', 'cryptsetup',
    'tcpdump', 'wireshark-cli'
]

# Patterns for sensitive data that should be masked in logs and outputs
SENSITIVE_DATA_PATTERNS = [
    # Password patterns
    r'(?i)password\s*[=:]\s*([^\s]+)',
    r'(?i)pwd\s*[=:]\s*([^\s]+)',
    r'(?i)passwd\s*[=:]\s*([^\s]+)',
    r'(?i)pass\s*[=:]\s*([^\s]+)',
    r'(?:(?i)PASSWORD|PWD|PASSWD|PASS)=([^\s;]+)',
    
    # API key and token patterns
    r'(?i)api[-_]?key\s*[=:]\s*([^\s]+)',
    r'(?i)auth[-_]?token\s*[=:]\s*([^\s]+)',
    r'(?i)access[-_]?token\s*[=:]\s*([^\s]+)',
    r'(?i)secret[-_]?key\s*[=:]\s*([^\s]+)',
    r'(?:(?i)API_?KEY|AUTH_?TOKEN|ACCESS_?TOKEN|SECRET_?KEY)=([^\s;]+)',
    
    # SSH private key markers
    r'(?s)-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----.*?-----END (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
    
    # Credentials in URLs
    r'(?i)(?:https?|ftp)://[^:]+:([^@]+)@',
    
    # Database connection strings
    r'(?i)(?:mongodb|mysql|postgres|postgresql|redis):\/\/[^:]+:([^@]+)@',
    
    # Encrypted or base64 encoded values that might be sensitive
    r'(?i)encrypted_(?:password|key|token)\s*[=:]\s*([^\s]+)',
    
    # Certificate and key files
    r'(?i)(?:cert|certificate|key)[-_]?file\s*[=:]\s*([^\s]+\.(?:pem|key|cert|crt))',
]

def sanitize_command(command):
    """
    Sanitize a command by removing dangerous elements.
    Replace potentially dangerous shell control characters.
    
    Args:
        command: The command string to sanitize
        
    Returns:
        (bool, str): Tuple containing (is_safe, sanitized_command_or_error_message)
    """
    if not command or not isinstance(command, str):
        return (False, "Invalid command")
        
    # Convert to lowercase for case-insensitive checks
    cmd_lower = command.lower()
    
    # Check for exact dangerous commands
    for dangerous_cmd in DANGEROUS_COMMANDS:
        if dangerous_cmd in cmd_lower:
            logger.warning(f"Blocked dangerous command: {command}")
            return (False, f"Command contains blocked pattern: {dangerous_cmd}")
    
    # Check for dangerous patterns
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            logger.warning(f"Blocked command matching dangerous pattern: {command}")
            return (False, f"Command contains dangerous pattern matching: {pattern}")
    
    # Check for shell command chaining/injection
    if ';' in command or '&&' in command or '||' in command:
        logger.warning(f"Blocked command with shell operators: {command}")
        return (False, "Command chaining using ';', '&&', or '||' is not allowed")
    
    # Check for redirection and piping
    if '>' in command or '|' in command:
        logger.warning(f"Blocked command with redirection/piping: {command}")
        return (False, "Redirection (>) and piping (|) are not allowed")
    
    # Check for backticks or $() for command substitution
    if '`' in command or '$(' in command:
        logger.warning(f"Blocked command with substitution: {command}")
        return (False, "Command substitution using backticks or $() is not allowed")
    
    # Check for restricted commands that require extra scrutiny
    for restricted_cmd in RESTRICTED_COMMANDS:
        if restricted_cmd in cmd_lower:
            logger.warning(f"Command requires approval: {command}")
            return (False, f"Command contains restricted pattern requiring approval: {restricted_cmd}")
    
    # If it's made it here, the command is considered safe
    return (True, command)

def validate_commands_list(commands):
    """
    Validate a list of commands, checking each for safety.
    
    Args:
        commands: List of command strings to validate
        
    Returns:
        (bool, list): Tuple containing (all_safe, list_of_results)
                     where results are (is_safe, command_or_error) tuples
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

def get_safe_commands(commands):
    """
    Filter a list of commands and return only the safe ones.
    
    Args:
        commands: List of command strings to filter
        
    Returns:
        List of safe commands
    """
    if not commands:
        return []
        
    safe_commands = []
    
    for cmd in commands:
        is_safe, result = sanitize_command(cmd)
        if is_safe:
            safe_commands.append(cmd)
            
    return safe_commands

def mask_sensitive_data(data, replacement="***REDACTED***"):
    """
    Mask sensitive data in a string to prevent exposure in logs or outputs.
    
    Args:
        data: String that might contain sensitive information
        replacement: String to use for masking sensitive data
        
    Returns:
        String with sensitive data masked
    """
    if not data or not isinstance(data, str):
        return data
        
    masked_data = data
    
    # Process each pattern to find and mask sensitive information
    for pattern in SENSITIVE_DATA_PATTERNS:
        # Special handling for SSH private keys - mask the entire key
        if "PRIVATE KEY" in pattern:
            masked_data = re.sub(
                pattern, 
                "-----BEGIN PRIVATE KEY-----***REDACTED***-----END PRIVATE KEY-----", 
                masked_data, 
                flags=re.IGNORECASE|re.DOTALL
            )
        else:
            # For other patterns, preserve the identifier but mask the value
            matches = re.finditer(pattern, masked_data)
            for match in matches:
                try:
                    # Try to get the capture group (the actual sensitive value)
                    if len(match.groups()) > 0:
                        full_match = match.group(0)
                        sensitive_part = match.group(1)
                        
                        # Replace only the sensitive part, keeping the identifier
                        masked_data = masked_data.replace(
                            full_match, 
                            full_match.replace(sensitive_part, replacement)
                        )
                except IndexError:
                    # If no capture group, mask the entire match
                    masked_data = masked_data.replace(match.group(0), replacement)
    
    return masked_data

def mask_command_output(output, mask_patterns=None):
    """
    Process command output to mask any sensitive information.
    
    Args:
        output: Command output string to process
        mask_patterns: Optional additional patterns to mask beyond the defaults
        
    Returns:
        Sanitized output with sensitive information masked
    """
    if not output:
        return output
        
    # Use default patterns if none provided
    patterns_to_use = SENSITIVE_DATA_PATTERNS
    if mask_patterns:
        patterns_to_use = patterns_to_use + mask_patterns
        
    # Mask sensitive data in output
    masked_output = mask_sensitive_data(output)
    
    # Check for specific sensitive files that might be in output
    sensitive_files = [
        '/etc/shadow', '/etc/passwd', '/etc/ssh/', 
        '~/.ssh/id_', '/etc/ssl/private/', '*.key',
        '*.pem', '*.crt', '*.cer', '*.p12', '*.pfx'
    ]
    
    # Create patterns for file paths
    for file_pattern in sensitive_files:
        # Convert glob pattern to regex
        regex_pattern = file_pattern.replace('.', r'\.').replace('*', r'[^/\s]*')
        
        # Find file contents that might follow the file pattern
        file_content_pattern = f"({regex_pattern})[^\n]*\n(.*(?:\n.*)*?)(?:\n\n|\Z)"
        matches = re.finditer(file_content_pattern, masked_output, re.MULTILINE)
        
        for match in matches:
            try:
                # Keep the filename but mask the potential file contents
                if len(match.groups()) > 1:
                    filename = match.group(1)
                    file_content = match.group(2)
                    
                    # Only mask if it appears to be sensitive content
                    if re.search(r'[a-zA-Z0-9+/]{20,}={0,2}', file_content) or \
                       re.search(r'BEGIN .* KEY|END .* KEY|BEGIN CERTIFICATE|END CERTIFICATE', file_content):
                        replacement = f"{filename}\n***REDACTED SENSITIVE FILE CONTENT***"
                        masked_output = masked_output.replace(match.group(0), replacement)
            except IndexError:
                pass
    
    return masked_output

def hash_sensitive(data, hash_method="sha256"):
    """
    Hash sensitive data instead of plaintext storage.
    This is useful for auditing or tracking without exposing actual values.
    
    Args:
        data: String data to hash
        hash_method: Hash algorithm to use (sha256, md5, etc.)
        
    Returns:
        Hashed string in hexadecimal
    """
    if not data:
        return None
        
    if isinstance(data, str):
        data = data.encode()
        
    if hash_method.lower() == "sha256":
        return hashlib.sha256(data).hexdigest()
    elif hash_method.lower() == "md5":
        return hashlib.md5(data).hexdigest()
    elif hash_method.lower() == "sha1":
        return hashlib.sha1(data).hexdigest()
    else:
        # Default to SHA-256
        return hashlib.sha256(data).hexdigest()

def generate_fingerprint(data):
    """
    Generate a unique fingerprint for sensitive data.
    This allows tracking or comparison without exposing the data.
    
    Args:
        data: String data to fingerprint
        
    Returns:
        Short fingerprint string
    """
    if not data:
        return None
        
    # First get a full hash
    full_hash = hash_sensitive(data)
    
    # Return only a portion as the fingerprint for brevity
    # Handle case where hash_sensitive returns None
    if full_hash:
        return full_hash[:12]
    else:
        return None