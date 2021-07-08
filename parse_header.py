import re

def extract_all_ip_address(head_list):
    # Find all IP addresses in sub lists
    ip_addresses = [re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", str(line)) for line in head_list]
    # Removing all empty sub lists
    ip_addresses = list(filter(None, ip_addresses))
    # Flattening list of lists
    ip_addresses = [ip for ips in ip_addresses for ip in ips]
    # Checking list length
    if len(ip_addresses) == 0:
        ip_addresses = ["No IP addresses found"]
    ip_addresses = list(set(ip_addresses))
    return ip_addresses
  
def extract_url(head_list):
    # Find all fully qualified domains in sublists using regular expressions
    full_domain = [re.findall("((www\.|http://|https://)(www\.)*.*?(?=(www\.|http://|https://|$)))", str(line)) for line in head_list]
    full_domain = list(filter(None, full_domain))
    full_domain = [domain for domains in full_domain for domain in domains]
    if len(full_domain) == 0:
        full_domain = ["No URLs found"]
    return full_domain
  
def extract_top_level_domain(head_list):
    # Find all top level domains in sublists using regular expressions
    top_level = [re.findall(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}', str(line)) for line in head_list]
    top_level = list(filter(None, top_level))
    top_level = [domain for domains in top_level for domain in domains]
    if len(top_level) == 0:
        top_level = ["No top level domains found"]
    return top_level
  
def extract_email_address(head_list):
    # Find all email addresses in lists using regular expressions
    email = [re.findall(r'[\w\.-]+@[\w\.-]+', str(head_list))]
    email = list(filter(None, email))
    email = [address for addresses in email for address in addresses]
    if len(email) == 0:
        email = ["No email addresses found"]
    return email
  
def extract_reply_to_field(head_list):
    # Find all reply to fields in lists using regular expressions
    reply = [field for field in head_list if "Reply" in field]
    reply = list(filter(None, reply))
    reply = [field for fields in reply for field in fields]
    if len(reply) == 0:
        reply = ["No email addresses found"]
    return reply
  
def parse_external_ip(ip):
    # Find all external IPs in list of parsed internal and external IPs
    internal = ['10.', '172.', '192.', '127.']
    external = [external_ip for external_ip in ip if external_ip[:3] != internal[0]
                and external_ip[:4] != internal[1] and external_ip[:4] != internal[2] and external_ip[:4] != internal[3]]
    return external
