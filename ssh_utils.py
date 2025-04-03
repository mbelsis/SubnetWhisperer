import paramiko
import socket
import threading
import time
import logging
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from app import db
from models import ScanResult, ScanSession
from encryption_utils import encrypt_data, decrypt_data

# Configure logging
logger = logging.getLogger(__name__)

def collect_server_info(ssh_client, detailed=False):
    """Collect server information using SSH client
    
    Args:
        ssh_client: Paramiko SSH client
        detailed: Whether to collect detailed information (more commands, deeper analysis)
    
    Returns:
        Dictionary containing server information
    """
    server_info = {}
    
    try:
        # Hostname information
        stdin, stdout, stderr = ssh_client.exec_command("hostname -f")
        server_info['hostname'] = stdout.read().decode().strip()
        
        # OS information
        stdin, stdout, stderr = ssh_client.exec_command("cat /etc/os-release")
        os_data = stdout.read().decode().strip()
        os_info = {}
        for line in os_data.split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                os_info[key] = value.strip('"')
        server_info['os'] = os_info
        
        # Kernel information
        stdin, stdout, stderr = ssh_client.exec_command("uname -r")
        server_info['kernel'] = stdout.read().decode().strip()
        
        # Hardware information
        stdin, stdout, stderr = ssh_client.exec_command("lscpu")
        cpu_info = {}
        for line in stdout.read().decode().strip().split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                cpu_info[key.strip()] = value.strip()
        server_info['cpu'] = cpu_info
        
        # Memory information
        stdin, stdout, stderr = ssh_client.exec_command("free -m")
        memory_lines = stdout.read().decode().strip().split('\n')
        if len(memory_lines) >= 2:
            memory_parts = memory_lines[1].split()
            server_info['memory'] = {
                'total': f"{memory_parts[1]} MB",
                'used': f"{memory_parts[2]} MB",
                'free': f"{memory_parts[3]} MB"
            }
        
        # Disk information
        stdin, stdout, stderr = ssh_client.exec_command("df -h")
        disk_info = stdout.read().decode().strip().split('\n')
        server_info['disk'] = disk_info
        
        # Network interfaces
        stdin, stdout, stderr = ssh_client.exec_command("ip -j addr")
        try:
            network_info = json.loads(stdout.read().decode().strip())
            server_info['network'] = network_info
        except json.JSONDecodeError:
            # Fallback if json output not available
            stdin, stdout, stderr = ssh_client.exec_command("ip addr")
            server_info['network'] = stdout.read().decode().strip().split('\n')
        
        # Uptime
        stdin, stdout, stderr = ssh_client.exec_command("uptime -p")
        server_info['uptime'] = stdout.read().decode().strip()
        
        # Only collect detailed information if requested
        if detailed:
            # DNS configuration
            stdin, stdout, stderr = ssh_client.exec_command("cat /etc/resolv.conf")
            dns_info = stdout.read().decode().strip().split('\n')
            server_info['dns_config'] = dns_info
            
            # Running services
            stdin, stdout, stderr = ssh_client.exec_command("systemctl list-units --type=service --state=running")
            services = stdout.read().decode().strip().split('\n')
            server_info['running_services'] = services
            
            # Installed packages (limit to 100 to avoid huge data transfer)
            stdin, stdout, stderr = ssh_client.exec_command("dpkg-query -l | head -100")
            packages_info = stdout.read().decode().strip().split('\n')
            server_info['installed_packages'] = packages_info
            
            # Active network connections
            stdin, stdout, stderr = ssh_client.exec_command("ss -tuln")
            network_connections = stdout.read().decode().strip().split('\n')
            server_info['network_connections'] = network_connections
            
            # Ethernet card information
            stdin, stdout, stderr = ssh_client.exec_command("lshw -class network -short")
            ethernet_info = stdout.read().decode().strip().split('\n')
            server_info['ethernet_cards'] = ethernet_info
            
            # User accounts
            stdin, stdout, stderr = ssh_client.exec_command("cat /etc/passwd | grep -v nologin | grep -v false")
            user_accounts = stdout.read().decode().strip().split('\n')
            server_info['user_accounts'] = user_accounts
            
            # System load
            stdin, stdout, stderr = ssh_client.exec_command("cat /proc/loadavg")
            load_avg = stdout.read().decode().strip()
            server_info['load_average'] = load_avg
            
            # Default gateway
            stdin, stdout, stderr = ssh_client.exec_command("ip route | grep default")
            default_route = stdout.read().decode().strip()
            server_info['default_gateway'] = default_route
            
            # Host-based firewall status
            stdin, stdout, stderr = ssh_client.exec_command("iptables -L -n")
            firewall_rules = stdout.read().decode().strip().split('\n')
            server_info['firewall_rules'] = firewall_rules
            
            # Check if the server is a VM
            stdin, stdout, stderr = ssh_client.exec_command("hostnamectl | grep Virtualization")
            virtualization = stdout.read().decode().strip()
            server_info['virtualization'] = virtualization if virtualization else "Not detected"
        
        return server_info
    except Exception as e:
        logger.error(f"Error collecting server info: {str(e)}")
        return {"error": str(e)}

def execute_ssh_commands(ip, username, password=None, private_key=None, sudo_password=None, 
                       commands=None, collect_info=False, collect_detailed_info=False, scan_session_id=None,
                       credential_sets=None):
    """
    Execute SSH commands on a remote host and return results.
    
    Args:
        ip: IP address of target host
        username: SSH username
        password: SSH password (if using password auth)
        private_key: SSH private key content (if using key auth)
        sudo_password: Password for sudo commands
        commands: List of commands to execute
        collect_info: Whether to collect server information
        collect_detailed_info: Whether to collect detailed server information
        scan_session_id: ID of the scan session
        credential_sets: List of credential sets to try (overrides username/password/private_key if provided)
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    # Initialize result object
    result = ScanResult(
        scan_session_id=scan_session_id,
        ip_address=ip,
        status_code='pending'
    )
    db.session.add(result)
    db.session.commit()
    
    start_time = time.time()
    connection_successful = False
    auth_errors = []
    used_credentials = None
    
    try:
        # If credential sets are provided, try them in order of priority
        if credential_sets:
            # Sort credential sets by priority (higher priority first)
            sorted_credentials = sorted(credential_sets, key=lambda x: x.priority, reverse=True)
            
            for cred in sorted_credentials:
                try:
                    logger.info(f"Trying credentials for user {cred.username} (auth type: {cred.auth_type})")
                    
                    if cred.auth_type == 'key' and cred.private_key_encrypted:
                        # Use private key authentication
                        import io
                        # Decrypt private key (would need to implement decryption function)
                        private_key_data = decrypt_data(cred.private_key_encrypted)
                        key_file = paramiko.RSAKey.from_private_key(file_obj=io.StringIO(private_key_data))
                        client.connect(ip, username=cred.username, pkey=key_file, timeout=10)
                        used_credentials = cred
                        connection_successful = True
                        break
                    elif cred.auth_type == 'password' and cred.password_encrypted:
                        # Use password authentication
                        # Decrypt password (would need to implement decryption function)
                        password_data = decrypt_data(cred.password_encrypted)
                        client.connect(ip, username=cred.username, password=password_data, timeout=10)
                        used_credentials = cred
                        connection_successful = True
                        break
                except (paramiko.AuthenticationException, paramiko.SSHException) as e:
                    auth_errors.append(f"Authentication failed for user {cred.username}: {str(e)}")
                    continue
                except Exception as e:
                    auth_errors.append(f"Connection error for user {cred.username}: {str(e)}")
                    continue
        
        # If no credential sets or all credential sets failed, try with the provided credentials
        if not connection_successful:
            try:
                if private_key:
                    # Use private key authentication
                    import io
                    key_file = paramiko.RSAKey.from_private_key(file_obj=io.StringIO(private_key))
                    client.connect(ip, username=username, pkey=key_file, timeout=10)
                    connection_successful = True
                else:
                    # Use password authentication
                    client.connect(ip, username=username, password=password, timeout=10)
                    connection_successful = True
            except (paramiko.AuthenticationException, paramiko.SSHException) as e:
                auth_errors.append(f"Authentication failed for user {username}: {str(e)}")
            except Exception as e:
                auth_errors.append(f"Connection error for user {username}: {str(e)}")
        
        # If connection was successful
        if connection_successful:
            # Update SSH status
            result.ssh_status = True
            
            # Test sudo access if commands are provided
            if commands:
                sudo_password_to_use = None
                
                # Determine which sudo password to use
                if used_credentials and used_credentials.sudo_password_encrypted:
                    sudo_password_to_use = decrypt_data(used_credentials.sudo_password_encrypted)
                elif sudo_password:
                    sudo_password_to_use = sudo_password
                
                try:
                    # Try a simple sudo command to check permissions
                    if sudo_password_to_use:
                        # Try with password
                        transport = client.get_transport()
                        if transport is None:
                            logger.error("Transport is None, cannot open session")
                            result.sudo_status = False
                            return result
                            
                        channel = transport.open_session()
                        channel.get_pty()
                        channel.exec_command("sudo -S -p '' echo success")
                        channel.sendall((sudo_password_to_use + '\n').encode())
                        output = channel.recv(1024).decode('utf-8')
                        result.sudo_status = 'success' in output
                    else:
                        # Try passwordless sudo
                        stdin, stdout, stderr = client.exec_command("sudo -n true", timeout=5)
                        exit_status = stdout.channel.recv_exit_status()
                        result.sudo_status = (exit_status == 0)
                except Exception as e:
                    logger.warning(f"Sudo check failed for {ip}: {str(e)}")
                    result.sudo_status = False
                
                # Execute commands
                command_output = []
                all_commands_succeeded = True
                
                for cmd in commands:
                    try:
                        if cmd.startswith('sudo ') and sudo_password_to_use:
                            # Use sudo with password for commands that need it
                            transport = client.get_transport()
                            if transport is None:
                                logger.error("Transport is None, cannot open session")
                                raise Exception("SSH transport is not available")
                                
                            channel = transport.open_session()
                            channel.get_pty()
                            channel.exec_command(cmd)
                            channel.sendall((sudo_password_to_use + '\n').encode())
                            stdout_data = ''
                            stderr_data = ''
                            
                            while not channel.exit_status_ready():
                                if channel.recv_ready():
                                    stdout_data += channel.recv(1024).decode('utf-8', errors='replace')
                                if channel.recv_stderr_ready():
                                    stderr_data += channel.recv_stderr(1024).decode('utf-8', errors='replace')
                            
                            exit_status = channel.recv_exit_status()
                        else:
                            # Regular command execution
                            stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
                            exit_status = stdout.channel.recv_exit_status()
                            stdout_data = stdout.read().decode('utf-8', errors='replace')
                            stderr_data = stderr.read().decode('utf-8', errors='replace')
                        
                        cmd_result = {
                            'command': cmd,
                            'exit_status': exit_status,
                            'stdout': stdout_data,
                            'stderr': stderr_data,
                            'success': (exit_status == 0)
                        }
                        
                        command_output.append(cmd_result)
                        if exit_status != 0:
                            all_commands_succeeded = False
                    except Exception as e:
                        command_output.append({
                            'command': cmd,
                            'exit_status': -1,
                            'stdout': '',
                            'stderr': str(e),
                            'success': False
                        })
                        all_commands_succeeded = False
                
                result.command_status = all_commands_succeeded
                result.command_output = json.dumps(command_output)
            
            # Collect server information if requested
            if collect_info:
                server_info = collect_server_info(client, detailed=collect_detailed_info)
                result.server_info = json.dumps(server_info)
            
            # Set overall status to success
            result.status_code = 'success'
        else:
            # If connection failed with all credentials
            result.status_code = 'failed'
            result.error_message = "Authentication failed with all credentials: " + "; ".join(auth_errors)
    
    except socket.timeout:
        result.status_code = 'failed'
        result.error_message = "Connection timed out"
    except socket.error as e:
        result.status_code = 'failed'
        result.error_message = f"Socket error: {str(e)}"
    except Exception as e:
        result.status_code = 'failed'
        result.error_message = f"Error: {str(e)}"
    finally:
        # Close the SSH connection
        if client:
            client.close()
        
        # Calculate execution time
        result.execution_time = time.time() - start_time
        
        # Update the result in the database
        db.session.commit()
    
    return result

def start_scan_session(scan_session_id, ip_addresses, username, password=None, private_key=None, 
                     commands=None, collect_server_info=False, collect_detailed_info=False, 
                     sudo_password=None, credential_sets=None, concurrency=10):
    """Start a scan session with multiple threads"""
    def scan_worker():
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            scan_args = [
                (ip, username, password, private_key, sudo_password, commands, collect_server_info, 
                 collect_detailed_info, scan_session_id, credential_sets) 
                for ip in ip_addresses
            ]
            
            # Submit all tasks to thread pool
            futures = [
                executor.submit(execute_ssh_commands, *args) 
                for args in scan_args
            ]
            
            # Wait for all tasks to complete
            for future in futures:
                try:
                    future.result()  # This will raise any exceptions from the task
                except Exception as e:
                    logger.error(f"Thread execution error: {str(e)}")
            
            # Update scan session status to completed
            with db.app.app_context():
                scan_session = ScanSession.query.get(scan_session_id)
                if scan_session:
                    scan_session.status = 'completed'
                    scan_session.completed_at = datetime.utcnow()
                    db.session.commit()
    
    # Start the scan in a background thread
    scan_thread = threading.Thread(target=scan_worker)
    scan_thread.daemon = True
    scan_thread.start()
    
    return scan_thread
