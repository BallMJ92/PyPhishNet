import vt, socket, pydnsbl, requests, re, time

def virus_total_reputation_search(domains):
    virus_total_reputation = []
    #Iterating over domain values
    for key, value in domains.items():
        #Scanning domain values on Virus Total
        vtr = virus_total_scan(domains[key])
        #Iterating over Virus Total dict of dicts output
        for key, value in vtr.items():
            for rep, result in value.items():
                #Append only result of scan to virus_total_reputation list
                if rep == 'result':
                    virus_total_reputation.append(result)
                else:
                    pass
        
    return virus_total_reputation
  
def virus_total_scan(domain):
    """
    virus_total_url_scan scans given urls against Virus Total reputational
    database and returns results from all scanners
    """
    #Virus total API key
    client = vt.Client("PASTE_API_KEY_HERE")
    #Analysing given url and returning a dict
    analysis = client.scan_url(domain,wait_for_completion=True)
    client.close()
    print("Virus Total scan complete for %s" % (domain))
    
    return analysis.results
  
def ip_domain_resolve(ip):
    """
    socket.gethostbyaddr returns tuple including both domain and ip address
    example: ('mx199.a.outbound.createsend.com', [], ['203.55.21.199'])
    domain is at index 0
    ip_domain_resolve returns a dict with key (ip) and value (domain) pairs 
    """
    
    domains = {}
    for i in ip:
        domain = socket.gethostbyaddr(str(i))
        domains[str(i)] = str(domain[0])
    print("%s domains resolved" % (len(domains)))
    
    return domains
  
def talos_reputation_search(ip_domain_list):
    reputation = []
    #Interrogating Talos and appending received reputational data dictionary to list
    for i in ip_domain_list:
        talos_data = get_talos_data(i)
        #Extracting only weighted reputation key from received dictionary
        wrs = talos_data.get("weighted_reputation_score", 'unknown')
        reputation.append(wrs)       
        time.sleep(1)
    #Extracting only weighted_reputation_score key from all dictionaries in reputation list
    #reputation(item for item in reputation if item["weighted_reputation_score"])
    print("Gathering Cisco Talos results...")
    
    return reputation
        
def get_talos_data(search_string, search_by='ip'):
        """
        get_talos_data function submits requests to the different Cisco Talos databases, retrieves database output
        and assigns output to a disctionary key as its value. Dictionary key\value can be found in data dictionary
        """
        session = requests.Session()
        #requesting information from individual Cisco Talos reputational databases
        r_talos_blacklist = requests.get('https://www.talosintelligence.com/sb_api/blacklist_lookup',
                headers={
                    'Referer':'https://talosintelligence.com/reputation_center/lookup?search=%s'%search_string,
                    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36'
                    },
                params = {'query_type':'ipaddr', 'query_entry':search_string}).json()
        r_details = requests.get('https://talosintelligence.com/sb_api/query_lookup',
            headers={
                'Referer':'https://talosintelligence.com/reputation_center/lookup?search=%s'%search_string,
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36'
                },
            params = {
                'query':'/api/v2/details/ip/',
                'query_entry':search_string
                }).json()
        r_wscore = requests.get('https://talosintelligence.com/sb_api/remote_lookup',
                headers={
                    'Referer':'https://talosintelligence.com/reputation_center/lookup?search=%s'%search_string,
                    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36'
                    },
                params = {'hostname':'SDS', 'query_string':'/score/wbrs/json?url=%s' % search_string}).json()
        r_talos_blacklist = requests.get('https://www.talosintelligence.com/sb_api/blacklist_lookup',
                headers={
                    'Referer':'https://talosintelligence.com/reputation_center/lookup?search=%s'%search_string,
                    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36'
                    },
                params = {'query_type':'ipaddr', 'query_entry':search_string}).json()
        """
        #Requires further testing
        talos_blacklisted = {'status':False}
        if 'classifications' in r_talos_blacklist['entry']:
            talos_blacklisted['status'] = True
            talos_blacklisted['classifications'] = ", ".join(r_talos_blacklist['entry']['classifications'])
            talos_blacklisted['first_seen'] = r_talos_blacklist['entry']['first_seen'] + "UTC"
            talos_blacklisted['expiration'] = r_talos_blacklist['entry']['expiration'] + "UTC"
        """
        """
        data dictionary holds all the retrieved reputational information from Talos. If additional reputational
        information is required amend talos_reputation_search function and add key to a new variable using
        wrs variable as a reference
        """
        data = {
            'address':search_string,
            'hostname':r_details['hostname'] if 'hostname' in r_details else "nodata",
            'volume_change':r_details['daychange'] if 'daychange' in r_details else "nodata",
            'lastday_volume':r_details['daily_mag'] if 'daily_mag' in r_details else "nodata",
            'month_volume':r_details['monthly_mag'] if 'monthly_mag' in r_details else "nodata",
            'email_reputation':r_details['email_score_name'] if 'email_score_name' in r_details else "nodata",
            'web_reputation':r_details['web_score_name'] if 'web_score_name' in r_details else "nodata",
            'weighted_reputation_score':r_wscore['response'],
            #'talos_blacklisted':"Yes" if talos_blacklisted['status'] else "No"
            #'weighted_reputation_score':r_wscore[0]['response']['wbrs']['score'],
            #'volumes':zip(*r_volume['data'])
        }
        return data
def pydnsbl_scan(ip):
    #pydnsbl_scan iterates over a list of given ip addresses and returns blacklist information
    ip_check = pydnsbl.DNSBLIpChecker()
    reputation = []
    for i in ip:
        x = ip_check.check(str(i))
        reputation.append(str(x))
    print("Gathering PYDNSBL results...")
    return reputation
  
def classification(talos_rep, pydnsbl_rep, virustotal_rep):
    #classification function determines overall classification by analysing all reputational data
    rep_counter = int(0)
    final_class = ""
    
    #Checking pydnsbl reputation and updating rep_counter for classification
    for i in pydnsbl_rep:
        if "BLACKLISTED" in i:
            rep_counter+=1
    #Checking Talos reputation and updating rep_counter for classification
    """
    Cisco Talos new threat levels are: Trusted, Favorable, Neutral, Questionable, Untrusted
    Cisco Talos new threat levels and descriptions can be found here:
    https://talosintelligence.com/reputation_center/support#faq3
    """
    for i in talos_rep:
        for j in i:
            if j.lower() == 'questionable':
                rep_counter = rep_counter+1
            elif j.lower() == 'untrusted':
                rep_counter = rep_counter+2
    for i in virustotal_rep:
        if j.lower() == 'malware':
            rep_counter+=4
        elif j.lower() == 'phishing':
            rep_counter+=2
        elif j.lower() == 'malicious':
            rep_counter+=2
        elif j.lower() == 'suspicious':
            rep_counter+=1
        elif j.lower() == 'spam':
            rep_counter+=1
    
    #Determining final header classification using final rep_counter value
    if rep_counter >=4:
        final_class = "PHISHING"
    elif 1 <= rep_counter <= 3:
        final_class = "SPAM/PHISHING"
    elif rep_counter == 0:
        final_class = "LEGITIMATE/SPAM"
    else:
        final_class = "UNABLE TO CLASSIFY. PLEASE CHECK DATA"
        
    return final_class
