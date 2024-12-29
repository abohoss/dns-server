import socket
import re
from dns_utils import build_response, log, parse_query

ROOT_DNS_DATABASE = {
    "com": {"ip": "127.0.0.1", "port": 5351},
    "org": {"ip": "127.0.0.1", "port": 5351},
    "arpa": {"ip": "127.0.0.1", "port": 5351},
}
cache = {}
def start_root_dns_server(ip="127.0.0.1", port=53):

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
                # Regular expression for matching a valid domain
            regex = r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<=\w)(\.[A-Za-z0-9-]{1,63})*$"
            
            # Use re.match() to check if the domain matches the regex
            if not re.match(regex, domain):
                response = build_response(transaction_id, "", 1, error_code=1)  # Format Error
                
            elif (domain, qtype) in cache:
                response = cache[(domain, qtype)]
                log("Response from cache")
            # Check if TLD is present in the ROOT_DNS_DATABASE
            elif tld in ROOT_DNS_DATABASE:
                second_level = ROOT_DNS_DATABASE[tld]
                try:
                    forward_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    forward_socket.settimeout(10)  # Set a timeout on the forward socket
                    forward_socket.sendto(data, (second_level["ip"], second_level["port"]))
                    log(f"Forwarding query to second-level server: {second_level['ip']}:{second_level['port']}")
                    response, _ = forward_socket.recvfrom(512)
                    cache[(domain, qtype)] = response
                    
                except socket.timeout:
                    log("Request timeout when forwarding to second-level server.")
                except Exception as e:
                    log(f"Error while forwarding request to second-level server: {e}")
                    response = build_response(transaction_id, "", 1, error_code=2)  # Server Failure
                    
                    
            else:
                # Send NXDOMAIN response if TLD is not found in the ROOT_DNS_DATABASE
                log(f"TLD {tld} not found in root DNS database. Returning NXDOMAIN.")
                response = build_response(transaction_id, domain, qtype, error_code=3)    
                      
        except socket.timeout:
            log("Request timeout. No response received.")
            response = build_response(transaction_id, "", 1, error_code=2)  # Server Failure
            
        except Exception as e:
            log(f"Internal server error: {e}")
            response = build_response(transaction_id, "", 1, error_code=2)  # Server Failure
            
        finally:
            sock.sendto(response, addr)
            log(f"Forwarded response back to {addr}")

if __name__ == "__main__":
    start_root_dns_server()
