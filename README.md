# dns-server
steps to run our DNS server:
Installation:
1- clone the github repo: https://github.com/abohoss/dns-server.git

# Project Name

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)  

The DNS server features a modular architecture that emphasizes efficient query handling, response construction, and cache management. 

---

## Table of Contents

- [About](#about)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage Instructions](#usage)



---

## About

Our dns server incorporates key functionalities, including encoding and decoding DNS messages, error handling, and support for common record types such as A, AAAA, CNAME, and PTR. In addition, the implementation includes caching mechanisms to optimize performance by reducing redundant queries to higher-level DNS servers and decreasing latency for clients.

---

## Installation

Step-by-step instructions:

```bash 
# Clone the repository
git clone https://github.com/abohoss/dns-server.git

# Navigate to the project directory
cd DNS-SERVER

``` 
2- change the path to the 3 python servers to their complete paths in the script.bat file in the directory on your machine
3- double tap the script file to run it on your server
4- open cmd on any machine on your local network and query the dns server using nslookup and the ip address 127.0.0.0.1 (eg: nslookup google.com 127.0.0.1)
```bash 
nslookup google.com 127.0.0.1

```
the output:
```markdown
![Screenshot](C:/Users/Ahmed%20hosam/Pictures/Screenshots/Screenshot%202024-12-30%20021233.png)
```
---
## Configuration
Our servers all work on ip addresss: 127.0.0.1 
where the root server works on port: 53
the tld server works on port: 5351
the authoritative server works on port: 8053
you can see the available using netstat command on windows
`` ```bash ``
netstat -an
`` ``` ``
and you can change these ports and ip address of servers from the declaration of the function in each server file (files are named after their corresponding servers)
```python
def start_root_dns_server(ip="127.0.0.1", port=53):
```
and similarly for the other servers

---
## Usage Instructions
if you want to add a new record to the dns server or update an existing record, you should go to the tld server and the authoritative server to add it to their database
in authoritative_server:
```python
    "example.com": {
        "A": [{"ttl": 300, "value": "192.0.2.1"}],
        "AAAA": [{"ttl": 300, "value": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"}],
        "MX": [{"ttl": 300, "value": "mail.example.com", "preference": 10}],
        "NS": [{"ttl": 300, "value": "ns1.example.com"}, {"ttl": 300, "value": "ns2.example.com"}],
        "CNAME": [{"ttl": 300, "value": "alias.example.com"}],
    },
```

in tld_server:
```python
    "example" : {"ip": "127.0.0.1", "port": 8053}
```


