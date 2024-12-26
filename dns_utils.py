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


# def build_response(transaction_id, domain, record_type, records):
#     """
#     Build a complete DNS response packet with enhanced record type support.
    
#     Args:
#         transaction_id (bytes): The original query's transaction ID
#         domain (str): The domain name being queried
#         record_type (int): DNS record type (1=A, 28=AAAA, 12=PTR, etc.)
#         records (list): List of record dictionaries to include in response
    
#     Returns:
#         bytes: Fully constructed DNS response packet
#     """
#     # Use the original transaction ID
#     response = transaction_id
    
#     # Standard response flags: 
#     # 0x81 0x80 = Standard Query Response, No Error
#     response += b"\x81\x80"
    
#     # DNS Packet Counts:
#     # 1 Question, Number of Answer Records, 0 Authority, 0 Additional
#     response += struct.pack(">HHHH", 1, len(records), 0, 0)
    
#     def encode_domain_name(domain_str):
#         """
#         Convert domain name to DNS wire format.
        
#         Converts a domain like 'example.com' to bytes representing:
#         - Length of each part
#         - Bytes of each part
#         - Null terminator
#         """
#         encoded = b""
#         for part in domain_str.rstrip('.').split('.'):
#             # Length of part followed by part bytes
#             encoded += struct.pack("B", len(part)) + part.encode('ascii')
#         encoded += b"\x00"  # Null terminator
#         return encoded
    
#     # Add encoded domain name to question section
#     response += encode_domain_name(domain)
    
#     # Add query type and class (record_type, IN class)
#     response += struct.pack(">HH", record_type, 1)
    
#     # Answer Section
#     for record in records:
#         # Domain name pointer (0xC0 0x0C points to earlier domain name)
#         response += b"\xc0\x0c"
        
#         # Record type, class, TTL
#         response += struct.pack(">HHI", record_type, 1, record.get("ttl", 300))
        
#         # Encode record value based on type
#         if record_type == 1:  # A record (IPv4)
#             try:
#                 # Convert IPv4 to 4-byte representation
#                 ip_bytes = socket.inet_aton(record["value"])
#                 # Add length of IP (4 bytes)
#                 response += struct.pack(">H", 4)
#                 response += ip_bytes
#             except OSError:
#                 raise ValueError(f"Invalid IPv4 address: {record['value']}")
        
#         elif record_type == 28:  # AAAA record (IPv6)
#             try:
#                 # Convert IPv6 to 16-byte representation
#                 ip_bytes = socket.inet_pton(socket.AF_INET6, record["value"])
#                 # Add length of IP (16 bytes)
#                 response += struct.pack(">H", 16)
#                 response += ip_bytes
#             except OSError:
#                 raise ValueError(f"Invalid IPv6 address: {record['value']}")
        
#         elif record_type == 12:  # PTR record (Reverse DNS)
#             try:
#                 # Encode the domain name for the PTR record
#                 ptr_domain = record["value"]
#                 ptr_encoded = encode_domain_name(ptr_domain)
                
#                 # Add length of encoded domain
#                 response += struct.pack(">H", len(ptr_encoded))
#                 response += ptr_encoded
#             except KeyError:
#                 raise ValueError("PTR record requires a 'value' field with a domain name")
#         elif record_type == 15:  # MX record (Mail Exchanger)
#             try:
#                 # MX record requires preference value and mail server domain
#                 preference = record.get("preference", 10)
#                 mx_domain = record["value"]
                
#                 # Encode mail server domain name
#                 mx_encoded = encode_domain_name(mx_domain)
                
#                 # Calculate total record length (preference(2) + domain length)
#                 record_length = 2 + len(mx_encoded)
                
#                 # Add record length
#                 response += struct.pack(">H", record_length)
                
#                 # Add preference (2 bytes)
#                 response += struct.pack(">H", preference)
                
#                 # Add encoded domain
#                 response += mx_encoded
#             except KeyError:
#                 raise ValueError("MX record requires a 'value' field with a mail server domain")
            
#         elif record_type == 5:
#             try:
#                 cname_domain = record["value"]
#                 cname_encoded = encode_domain_name(cname_domain)
                
#                 # Add length of encoded domain
#                 response += struct.pack(">H", len(cname_encoded))
#                 response += cname_encoded
#             except KeyError:
#                 raise ValueError("CNAME record requires a 'value' field with a target domain name")
        
#         elif record_type == 2:  # NS record (Name Server)
#             try:
#                 # NS record is a domain name of a name server
#                 ns_domain = record["value"]
                
#                 # Encode name server domain name
#                 ns_encoded = encode_domain_name(ns_domain)
                
#                 # Add length of encoded domain
#                 response += struct.pack(">H", len(ns_encoded))
#                 response += ns_encoded
#             except KeyError:
#                 raise ValueError("NS record requires a 'value' field with a name server domain")     
        
#         else:
#             raise ValueError(f"Unsupported record type: {record_type}")
    
#     return response
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

