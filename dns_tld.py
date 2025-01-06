import socket
import re
from dns_utils import log, parse_query, build_response

SECOND_DNS_DATABASE = {
    "google": {"ip": "127.0.0.1", "port": 8053},
    "facebook": {"ip": "127.0.0.1", "port": 8053},
    "in-addr" : {"ip": "127.0.0.1", "port": 8053},
    "wikipedia" : {"ip": "127.0.0.1", "port": 8053},
    "example" : {"ip": "127.0.0.1", "port": 8053},
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
            regex = r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<=\w)(\.[A-Za-z0-9-]{1,63})*$"
            
            # Use re.match() to check if the domain matches the regex
            if not re.match(regex, domain):
                response = build_response(transaction_id, "", 1, error_code=1)  # Format Error
            elif sld in SECOND_DNS_DATABASE:
                third_level = SECOND_DNS_DATABASE[sld]
                try:
                    forward_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    forward_socket.settimeout(10)  # Set a timeout on the forward socket
                    forward_socket.sendto(data, (third_level["ip"], third_level["port"]))
                    log(f"Forwarding query to third-level server: {third_level['ip']}:{third_level['port']}")
                    response, _ = forward_socket.recvfrom(512)
                    sock.sendto(response, addr)
                except socket.timeout:
                    log("Request timeout when forwarding to third-level server.")
                except Exception as e:
                    log(f"Error while forwarding request to third-level server: {e}")
                    response = build_response(transaction_id, "", 1, error_code=2)  # Server Failure
                    
            else:
                # NXDOMAIN if second-level domain is not found
                response = build_response(transaction_id, domain, qtype, error_code=3)
                
        except socket.timeout:
            log("Request timeout. No response received.")
        except Exception as e:
            log(f"Internal server error: {e}")
            response = build_response(transaction_id, "", 1, error_code=2)  # Server Failure
        finally:
            sock.sendto(response, addr)
            log(f"Forwarded response back to root server")

if __name__ == "__main__":
    start_second_dns_server()
    
