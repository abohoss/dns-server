import struct
import socket
import datetime

RECORD_TYPES = {
    1: "A",
    28: "AAAA",
    15: "MX",
    2:"NS",
    12: "PTR",
    5 : "CNAME",
}

def log(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("dns_server.log", "a") as log_file:
        log_file.write(f"{timestamp} - {message}\n")
    print(f"{timestamp} - {message}")


def parse_query(data):
    transaction_id = data[:2]
    qname_end = data.find(b"\x00", 12)
    qname = data[12:qname_end]
    qtype, _ = struct.unpack(">HH", data[qname_end + 1:qname_end + 5])
    domain_parts = []

    while qname:
        length = qname[0]
        domain_parts.append(qname[1:length + 1].decode())
        qname = qname[length + 1:]

    domain = ".".join(domain_parts)
    return transaction_id, domain, qtype


def find_record(domain, record_type, database):
    if domain in database:
        return database[domain].get(RECORD_TYPES.get(record_type, "UNKNOWN"))
    return None



def build_response(transaction_id, domain, record_type, records=None, error_code=0):


    response = transaction_id

    # Standard response flags:
    # QR (1 bit) = Response, Opcode (4 bits) = Query, AA (1 bit) = Not Authoritative,
    # TC (1 bit) = Not Truncated, RD (1 bit) = Recursion Desired (as per query),
    # RA (1 bit) = Recursion Available (0), Z (3 bits) = Reserved, RCODE (4 bits) = Error Code
    flags = 0x8000 | (error_code & 0xF)  # QR=1, AA=0, RA=0, RCODE=error_code
    flags |= 0x0400 
    response += struct.pack(">H", flags)

    # DNS Packet Counts:
    # 1 Question, Number of Answer Records (if no error), 0 Authority, 0 Additional
    qdcount = 1
    ancount = len(records) if records and error_code == 0 else 0
    response += struct.pack(">HHHH", qdcount, ancount, 0, 0)

    def encode_domain_name(domain_str):
        """
        Convert domain name to DNS wire format.
        """
        encoded = b""
        for part in domain_str.rstrip('.').split('.'):
            encoded += struct.pack("B", len(part)) + part.encode('ascii')
        encoded += b"\x00"  # Null terminator
        return encoded

    # Add the query section
    response += encode_domain_name(domain)
    response += struct.pack(">HH", record_type, 1)  # QTYPE and QCLASS

    # If no error and there are records, add the answer section
    if error_code == 0 and records:
        for record in records:
            response += b"\xc0\x0c"  # Name pointer to question section
            response += struct.pack(">HHI", record_type, 1, record.get("ttl", 300))  # TYPE, CLASS, TTL
            if record_type == 1:  # A record
                ip_bytes = socket.inet_aton(record["value"])
                response += struct.pack(">H", len(ip_bytes)) + ip_bytes
            elif record_type == 28:  # AAAA record
                ip_bytes = socket.inet_pton(socket.AF_INET6, record["value"])
                response += struct.pack(">H", len(ip_bytes)) + ip_bytes
            elif record_type == 15:  # MX record
                preference = record.get("preference", 10)
                mx_encoded = encode_domain_name(record["value"])
                response += struct.pack(">H", 2 + len(mx_encoded))
                response += struct.pack(">H", preference) + mx_encoded
            elif record_type == 5:  # CNAME
                cname_encoded = encode_domain_name(record["value"])
                response += struct.pack(">H", len(cname_encoded)) + cname_encoded
            elif record_type == 2:  # NS record
                ns_encoded = encode_domain_name(record["value"])
                response += struct.pack(">H", len(ns_encoded)) + ns_encoded
            elif record_type == 12:  # PTR record (Reverse DNS)
                try:
                    # Encode the domain name for the PTR record
                    ptr_domain = record["value"]
                    ptr_encoded = encode_domain_name(ptr_domain)
                    
                    # Add length of encoded domain
                    response += struct.pack(">H", len(ptr_encoded))
                    response += ptr_encoded
                except KeyError:
                    raise ValueError("PTR record requires a 'value' field with a domain name")
    return response

def get_ttl(response):
    # Skip the header section (first 12 bytes)
    header = response[:12]
    response = response[12:]
    
    # Read counts from header
    qdcount = struct.unpack(">H", header[4:6])[0]  # Question count
    ancount = struct.unpack(">H", header[6:8])[0]  # Answer count
    
    current_pos = 0
    
    def skip_name(response, current_pos):
        """Helper function to skip over a domain name, handling compression"""
        while True:
            length = response[current_pos]
            
            # Check for compression (first two bits set)
            if length & 0xC0 == 0xC0:
                # Compression used - skip two bytes
                return current_pos + 2
            
            if length == 0:
                # Zero length = root label, we're done
                return current_pos + 1
                
            # Regular label, skip length + label
            current_pos += 1 + length
    
    # Skip the query section
    pos = 0
    for _ in range(qdcount):
        # Skip domain name
        pos = skip_name(response, pos)
        # Skip QTYPE and QCLASS (4 bytes)
        pos += 4
    
    # Process answer section
    ttl = None
    for _ in range(ancount):
        # Skip name
        pos = skip_name(response, pos)
        
        # Read TYPE and CLASS (4 bytes)
        pos += 4
        
        # Read TTL (4 bytes)
        ttl = struct.unpack(">I", response[pos:pos+4])[0]
        pos += 4
        
        # Read RDLENGTH
        rdlength = struct.unpack(">H", response[pos:pos+2])[0]
        pos += 2
        
        # Skip RDATA
        pos += rdlength
        
        # We've found our first TTL, so we can return it
        return ttl
    
    return ttl