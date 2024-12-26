import socket

def send_dns_query(domain, server_ip="127.0.0.1", server_port=5350):
    query = b"\x00\x01"  # Sample transaction ID
    query += b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # Query header for a simple A record lookup
    query += b"\x07example\x03com\x00"  # Domain to query (example.com)
    query += b"\x00\x01"  # Query type A
    query += b"\x00\x01"  # Query class IN

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, (server_ip, server_port))
    
    try:
        response, _ = sock.recvfrom(512)
        print("Response received:", response)
    except socket.timeout:
        print("Timeout occurred while waiting for DNS response.")
    finally:
        sock.close()

send_dns_query("google.com")
