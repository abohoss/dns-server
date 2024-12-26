import socket
from dns_utils import log, parse_query

ROOT_DNS_DATABASE = {
    "com": {"ip": "127.0.0.1", "port": 5351},
    "org": {"ip": "127.0.0.1", "port": 5351},
}

def start_root_dns_server(ip="127.0.0.1", port=53):
    """Start the root DNS server."""
    try:
        # Setting up the socket for the root DNS server
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((ip, port))
        log(f"Root DNS server started on {ip}:{port}")
    except Exception as e:
        log(f"Error starting root DNS server: {e}")
        return

    while True:
        try:
            data, addr = sock.recvfrom(512)  # Receiving DNS query data
            transaction_id, domain, qtype = parse_query(data)
            tld = domain.split(".")[-1]  # Extract top-level domain (e.g., "com")

            log(f"Root server received query: {domain}, type: {qtype}")
            
            # Check if TLD is present in the ROOT_DNS_DATABASE
            if tld in ROOT_DNS_DATABASE:
                second_level = ROOT_DNS_DATABASE[tld]
                try:
                    forward_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    forward_socket.settimeout(10)  # Set a timeout on the forward socket
                    forward_socket.sendto(data, (second_level["ip"], second_level["port"]))
                    log(f"Forwarding query to second-level server: {second_level['ip']}:{second_level['port']}")
                    response, _ = forward_socket.recvfrom(512)
                    sock.sendto(response, addr)  # Send the response back to the client
                    log(f"Forwarded response back to {addr}")
                except socket.timeout:
                    log("Request timeout when forwarding to second-level server.")
                except Exception as e:
                    log(f"Error while forwarding request to second-level server: {e}")
            else:
                # Send NXDOMAIN response if TLD is not found in the ROOT_DNS_DATABASE
                log(f"TLD {tld} not found in root DNS database. Returning NXDOMAIN.")
                response = transaction_id + b"\x81\x83" + b"\x00\x01\x00\x00\x00\x00\x00\x00"
                sock.sendto(response, addr)

        except socket.timeout:
            log("Request timeout. No data received from the client.")
        except Exception as e:
            log(f"Error handling request: {e}")

if __name__ == "__main__":
    start_root_dns_server()
