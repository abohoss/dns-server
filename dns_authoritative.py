import socket
import re
from dns_utils import log, parse_query, find_record, build_response

THIRD_DNS_DATABASE = {
    "example.com": {
        "A": [{"ttl": 300, "value": "192.0.2.1"}],
        "AAAA": [{"ttl": 300, "value": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"}],
        "MX": [{"ttl": 300, "value": "mail.example.com", "preference": 10}],
        "NS": [{"ttl": 300, "value": "ns1.example.com"}, {"ttl": 300, "value": "ns2.example.com"}],
        "CNAME": [{"ttl": 300, "value": "alias.example.com"}],
    },
    "google.com": {
        "A": [{"ttl": 300, "value": "142.250.190.46"}],
        "AAAA": [{"ttl": 300, "value": "2607:f8b0:4005:805::200e"}],
        "MX": [{"ttl": 300, "value": "alt1.aspmx.l.google.com", "preference": 5}],
        "NS": [{"ttl": 300, "value": "ns1.google.com"}, {"ttl": 300, "value": "ns2.google.com"}],
        "CNAME": [{"ttl": 300, "value": "google-alias.example.com"}],
    },
    "facebook.com": {
        "A": [{"ttl": 300, "value": "157.240.221.35"}],
        "AAAA": [{"ttl": 300, "value": "2a03:2880:f12c:83:face:b00c:0:25de"}],
        "MX": [{"ttl": 300, "value": "mail.facebook.com", "preference": 10}],
        "NS": [{"ttl": 300, "value": "ns1.facebook.com"}, {"ttl": 300, "value": "ns2.facebook.com"}],
        "CNAME": [{"ttl": 300, "value": "fb-alias.example.com"}],
    },
    "1.0.0.127.in-addr.arpa": {
        "PTR": [{"ttl": 300, "value": "localhost"}],
    },
    "wikipedia.org": {
    "A": [{"ttl": 300, "value": "91.198.174.192"}],
    "AAAA": [{"ttl": 300, "value": "2620:0:862:ed1a::1"}],
    "MX": [{"ttl": 300, "value": "mx1001.wikimedia.org", "preference": 10}],
    "NS": [
        {"ttl": 300, "value": "ns0.wikimedia.org"},
        {"ttl": 300, "value": "ns1.wikimedia.org"},
        {"ttl": 300, "value": "ns2.wikimedia.org"}
    ],
    "CNAME": [{"ttl": 300, "value": "wiki-alias.example.com"}],
    },

}

def start_third_dns_server(ip="127.0.0.1", port=8053):
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
            regex = r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<=\w)(\.[A-Za-z0-9-]{1,63})*$"
            

            if not re.match(regex, domain):
                response = build_response(transaction_id, "", 1, error_code=1)  # Format Error
            if records:
                response = build_response(transaction_id, domain, qtype, records)
            else:
                response = build_response(transaction_id, domain, qtype, error_code=4)  # NOT IMPLEMENTED
        except socket.timeout:
            log("Request timeout. No response received.")
        except Exception as e:
            log(f"Internal server error: {e}")
            response = build_response(transaction_id, "", 1, error_code=2)  # Server Failure
        finally:
            sock.sendto(response, addr)
            log(f"Forwarded response back to TLD server")

if __name__ == "__main__":
    start_third_dns_server()
