import socket
from dns_utils import log, parse_query

SECOND_DNS_DATABASE = {
    "google": {"ip": "127.0.0.1", "port": 5355},
    "facebook": {"ip": "127.0.0.1", "port": 5355},
}

def start_second_dns_server(ip="127.0.0.1", port=5351):
    """Start the second-level DNS server."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((ip, port))
        log(f"Second-level DNS server started on {ip}:{port}")
    except Exception as e:
        log(f"Error starting second-level DNS server: {e}")
        return

    while True:
        try:
            data, addr = sock.recvfrom(512)
            transaction_id, domain, qtype = parse_query(data)
            sld = domain.split(".")[-2]  # Extract second-level domain (e.g., "google")

            log(f"Second server received query: {domain}, type: {qtype}")
            if sld in SECOND_DNS_DATABASE:
                third_level = SECOND_DNS_DATABASE[sld]
                try:
                    forward_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    forward_socket.settimeout(10)  # Set a timeout on the forward socket
                    forward_socket.sendto(data, (third_level["ip"], third_level["port"]))
                    response, _ = forward_socket.recvfrom(512)
                    sock.sendto(response, addr)
                except socket.timeout:
                    log("Request timeout when forwarding to third-level server.")
                except Exception as e:
                    log(f"Error while forwarding request to third-level server: {e}")
            else:
                # NXDOMAIN if second-level domain is not found
                response = transaction_id + b"\x81\x83" + b"\x00\x01\x00\x00\x00\x00\x00\x00"
                sock.sendto(response, addr)
        except socket.timeout:
            log("Request timeout. No response received.")
        except Exception as e:
            log(f"Error handling request: {e}")

if __name__ == "__main__":
    start_second_dns_server()
