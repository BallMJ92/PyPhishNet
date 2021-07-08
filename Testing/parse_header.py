import re, os, subprocess

def extract_all_ip_address(headList):
    #Find all IP addresses in sublists
    ipAddresses = [re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", str(i)) for i in headList]
    
    #Removing all empty sublists
    ipAddresses = list(filter(None, ipAddresses))
    #Flattening list of lists
    ipAddresses = [i for y in ipAddresses for i in y]
    #Checking list length
    if len(ipAddresses) == 0:
        ipAddresses = ["No IP addresses found"]
    ipAddresses = list(set(ipAddresses))
    return ipAddresses
  
def extract_url(headList):
    #Find all fully qualified domains in sublists using regular expressions
    fullDomain = [re.findall("((www\.|http://|https://)(www\.)*.*?(?=(www\.|http://|https://|$)))", str(i)) for i in headList]
    fullDomain = list(filter(None, fullDomain))
    fullDomain = [i for y in fullDomain for i in y]
    if len(fullDomain) == 0:
        fullDomain = ["No URLs found"]
    return fullDomain
  
def extract_top_level_domain(headList):
    #Find all top level domains in sublists using regular expressions
    topLevel = [re.findall(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}', str(i)) for i in headList]
    topLevel = list(filter(None, topLevel))    
    topLevel = [i for y in topLevel for i in y]
    if len(topLevel) == 0:
        topLevel = ["No top level domains found"]
    return topLevel
  
def extract_email_address(headList):
    email = [re.findall(r'[\w\.-]+@[\w\.-]+', str(i)) for i in headList]
    email = list(filter(None, email))
    email = [i for y in email for i in y]
    if len(email) == 0:
        email = ["No email addresses found"]
    return email
  
def extract_reply_to_field(headList):
    reply = [i for i in headList if "Reply" in i]
    reply = list(filter(None, reply))
    reply = [i for y in reply for i in y]
    if len(reply) == 0:
        reply = ["No email addresses found"]
    return reply
  
def parse_external_ip(ip):
    internal = ['10.', '172.', '192.', '127.']
    
    external = [i for i in ip if i[:3]!=internal[0]
         and i[:4]!=internal[1] and i[:4]!=internal[2] and i[:4]!=internal[3]]
    return external
