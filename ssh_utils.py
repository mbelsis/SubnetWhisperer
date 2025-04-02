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

# Configure logging
logger = logging.getLogger(__name__)

def collect_server_info(ssh_client):
    """Collect advanced server information using SSH client"""
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
        
        return server_info
    except Exception as e:
        logger.error(f"Error collecting server info: {str(e)}")
        return {"error": str(e)}

def execute_ssh_commands(ip, username, password=None, private_key=None, commands=None, collect_info=False, scan_session_id=None):
    """Execute SSH commands on a remote host and return results"""
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
    
    try:
        # Connect to server
        if private_key:
            # Use private key authentication
            import io
            key_file = paramiko.RSAKey.from_private_key(file_obj=io.StringIO(private_key))
            client.connect(ip, username=username, pkey=key_file, timeout=10)
        else:
            # Use password authentication
            client.connect(ip, username=username, password=password, timeout=10)
        
        # Update SSH status
        result.ssh_status = True
        
        # Test sudo access if commands are provided
        if commands:
            try:
                # Try a simple sudo command to check permissions
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
            server_info = collect_server_info(client)
            result.server_info = json.dumps(server_info)
        
        # Set overall status to success
        result.status_code = 'success'
    
    except (paramiko.AuthenticationException, paramiko.SSHException) as e:
        result.status_code = 'failed'
        result.error_message = f"SSH authentication failed: {str(e)}"
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

def start_scan_session(scan_session_id, ip_addresses, username, password, private_key, commands, collect_server_info, concurrency=10):
    """Start a scan session with multiple threads"""
    def scan_worker():
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            scan_args = [
                (ip, username, password, private_key, commands, collect_server_info, scan_session_id) 
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
