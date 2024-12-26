import socket
from dns_utils import log, parse_query, find_record, build_response

THIRD_DNS_DATABASE = {
     "example.com": {
        "A": [{"ttl": 300, "value": "192.0.2.1"}],
    },
    "google.com": {
        "A": [{"ttl": 300, "value": "142.250.190.46"}],
        "AAAA": [{"ttl": 300, "value": "2607:f8b0:4005:805::200e"}],
        "MX": [{"ttl": 300, "value": "mail.google.com", "preference": 10}],
         "NS": [{"ttl": 300, "value": "ns1.google.com"}],
    },
    "facebook.com": {
        "A": [{"ttl": 300, "value": "157.240.221.35"}],
    },
}

def start_third_dns_server(ip="127.0.0.1", port=5355):
    """Start the third-level DNS server."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((ip, port))
        log(f"Third-level DNS server started on {ip}:{port}")
    except Exception as e:
        log(f"Error starting third-level DNS server: {e}")
        return

    while True:
        try:
            data, addr = sock.recvfrom(512)
            transaction_id, domain, qtype = parse_query(data)
            records = find_record(domain, qtype, THIRD_DNS_DATABASE)

            log(f"Third server received query: {domain}, type: {qtype}")
            if records:
                response = build_response(transaction_id, domain, qtype, records)
            else:
                # NXDOMAIN if no records found
                response = transaction_id + b"\x81\x83" + b"\x00\x01\x00\x00\x00\x00\x00\x00"
            
            sock.sendto(response, addr)
        except socket.timeout:
            log("Request timeout. No response received.")
        except Exception as e:
            log(f"Error handling request: {e}")

if __name__ == "__main__":
    start_third_dns_server()
