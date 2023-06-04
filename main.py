import socket
import threading
import re

def validate_ip(ip):
    # Validate if the IP address is in the correct format
    ip_regex = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if not re.match(ip_regex, ip):
        raise ValueError("Invalid IP address format")

def validate_port(port):
    # Validate if the port is within a valid range
    if not (0 <= port <= 65535):
        raise ValueError("Invalid port range")

def scan_ports(target, start_port, end_port):
    validate_ip(target)
    validate_port(start_port)
    validate_port(end_port)

    print(f"Scanning ports {start_port} to {end_port} on {target}...\n")

    # Create a lock for thread synchronization
    lock = threading.Lock()

    # Loop through the range of ports
    for port in range(start_port, end_port + 1):
        # Create a socket object
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)  # Set timeout to 1 second

            try:
                # Attempt to connect to the target IP and port
                result = sock.connect_ex((target, port))

                # Check if the port is open
                if result == 0:
                    lock.acquire()  # Acquire the lock before printing
                    print(f"Port {port} is open")
                    lock.release()  # Release the lock after printing

            except socket.error:
                # Handle socket errors gracefully
                lock.acquire()  # Acquire the lock before printing
                print(f"Error occurred while scanning port {port}")
                lock.release()  # Release the lock after printing

# Define the target IP and port range
target_ip = "192.168.0.1"
start_port = 1
end_port = 100

# Call the scan_ports function
scan_ports(target_ip, start_port, end_port)
