import vt, socket, pydnsbl, requests, time

def virus_total_reputation_search(domains):
    virus_total_reputation = []
    try:
        # Iterating over domain values
        for key, value in domains.items():
            # Scanning domain values on Virus Total
            vtr = virus_total_scan(domains[key])
            # Iterating over Virus Total dict of dicts output
            for key, value in vtr.items():
                for rep, result in value.items():
                    # Append only result of scan to virus_total_reputation list
                    if rep == 'result':
                        virus_total_reputation.append(result)
                    else:
                        pass
    except (OSError):
        pass
    except:
        pass
    return virus_total_reputation
  
def virus_total_scan(domain):
    """
    virus_total_url_scan scans given urls against Virus Total reputation
    database and returns results from all scanners
    Get the API key by creating an account with Virus Total
    """
    # Virus total API key
    client = vt.Client("VIRUS_TOTAL_API_KEY_HERE")
    # Analysing given url and returning a dict
    try:
        analysis = client.scan_url(domain, wait_for_completion=True)
    except:
        pass
    client.close()
    return analysis.results
  
def ip_domain_resolve(ip):
    """
    socket.gethostbyaddr returns tuple including both domain and ip address
    example: ('mx199.a.outbound.createsend.com', [], ['203.55.21.199'])
    domain is at index 0
    ip_domain_resolve returns a dict with key (ip) and value (domain) pairs
    """
    domains = {}
    try:
        for item in ip:
            domain = socket.gethostbyaddr(str(item))
            domains[str(item)] = str(domain[0])
    except (socket.gaierror, socket.herror):
        pass
    except:
        pass
    return domains
  
def talos_reputation_search(ip_domain_list):
    reputation = []
    # Interrogating Talos and appending received reputation data dictionary to list
    try:
        for item in ip_domain_list:
            talos_data = get_talos_data(item)
            # Extracting only weighted reputation key from received dictionary
            weighted_reputation_score = talos_data.get("weighted_reputation_score", 'unknown')
            reputation.append(weighted_reputation_score)
            time.sleep(1)
    except:
        pass
    # Extracting only weighted_reputation_score key from all dictionaries in reputation list
    # reputation(item for item in reputation if item["weighted_reputation_score"])
    return reputation
  
def get_talos_data(search_string, search_by='ip'):
    """
    get_talos_data function submits requests to the different Cisco Talos databases, retrieves database output
    and assigns output to a dictionary key as its value. Dictionary key\value can be found in data dictionary
    """
    session = requests.Session()
    # requesting information from individual Cisco Talos reputation databases
    try:
        r_talos_blacklist = requests.get('https://www.talosintelligence.com/sb_api/blacklist_lookup',
                                         headers={
                                             'Referer': 'https://talosintelligence.com/reputation_center/lookup?search=%s' % search_string,
                                             'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36'
                                         },
                                         params={'query_type': 'ipaddr', 'query_entry': search_string}).json()
        r_details = requests.get('https://talosintelligence.com/sb_api/query_lookup',
                                 headers={
                                     'Referer': 'https://talosintelligence.com/reputation_center/lookup?search=%s' % search_string,
                                     'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36'
                                 },
                                 params={
                                     'query': '/api/v2/details/ip/',
                                     'query_entry': search_string
                                 }).json()
        r_wscore = requests.get('https://talosintelligence.com/sb_api/remote_lookup',
                                headers={
                                    'Referer': 'https://talosintelligence.com/reputation_center/lookup?search=%s' % search_string,
                                    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36'
                                },
                                params={'hostname': 'SDS',
                                        'query_string': '/score/wbrs/json?url=%s' % search_string}).json()
        r_talos_blacklist = requests.get('https://www.talosintelligence.com/sb_api/blacklist_lookup',
                                         headers={
                                             'Referer': 'https://talosintelligence.com/reputation_center/lookup?search=%s' % search_string,
                                             'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36'
                                         },
                                         params={'query_type': 'ipaddr', 'query_entry': search_string}).json()
        """
        data dictionary holds all the retrieved reputation information from Talos. If additional reputation
        information is required amend talos_reputation_search function and add key to a new variable using
        wrs variable as a reference
        """
        data = {
            'address': search_string,
            'hostname': r_details['hostname'] if 'hostname' in r_details else "nodata",
            'volume_change': r_details['daychange'] if 'daychange' in r_details else "nodata",
            'lastday_volume': r_details['daily_mag'] if 'daily_mag' in r_details else "nodata",
            'month_volume': r_details['monthly_mag'] if 'monthly_mag' in r_details else "nodata",
            'email_reputation': r_details['email_score_name'] if 'email_score_name' in r_details else "nodata",
            'web_reputation': r_details['web_score_name'] if 'web_score_name' in r_details else "nodata",
            'weighted_reputation_score': r_wscore['response'],
            # 'talos_blacklisted':"Yes" if talos_blacklisted['status'] else "No"
            # 'weighted_reputation_score':r_wscore[0]['response']['wbrs']['score'],
            # 'volumes':zip(*r_volume['data'])
        }
    except:
        pass
    return data
  
def pydnsbl_scan(ip):
    # pydnsbl_scan iterates over a list of given ip addresses and returns blacklist information
    ip_check = pydnsbl.DNSBLIpChecker()
    reputation = []
    try:
        for item in ip:
            ip_classification = ip_check.check(str(item))
            reputation.append(str(ip_classification))
    except ValueError:
        return "Unable to run PYDNSBL scan"
    except:
        pass
    return reputation
  
def classification(talos_rep, pydnsbl_rep, virustotal_rep):
    # classification function determines overall classification by analysing all reputation data
    rep_counter = int(0)
    final_class = ""
    try:
        # Checking pydnsbl reputation and updating rep_counter for classification
        for reputation in pydnsbl_rep:
            if "BLACKLISTED" in reputation:
                rep_counter += 1
        # Checking Talos reputation and updating rep_counter for classification
        """
        Cisco Talos new threat levels are: Trusted, Favorable, Neutral, Questionable, Untrusted
        Cisco Talos new threat levels and descriptions can be found here:
        https://talosintelligence.com/reputation_center/support#faq3
        """
        for reputation in talos_rep:
            for item in reputation:
                if item.lower() == 'questionable':
                    rep_counter = rep_counter + 1
                elif item.lower() == 'untrusted':
                    rep_counter = rep_counter + 2
        for reputation in virustotal_rep:
            if reputation.lower() == 'malware':
                rep_counter += 4
            elif reputation.lower() == 'phishing':
                rep_counter += 2
            elif reputation.lower() == 'malicious':
                rep_counter += 2
            elif reputation.lower() == 'suspicious':
                rep_counter += 1
            elif reputation.lower() == 'spam':
                rep_counter += 1
    except:
        pass
      
    # Determining final header classification using final rep_counter value. The below threshold values can be tuned as required
    if rep_counter >= 3:
        final_class = "PHISHING"
    elif 1 <= rep_counter <= 2:
        final_class = "SPAM/PHISHING"
    elif rep_counter == 0:
        final_class = "LEGITIMATE/SPAM"
    else:
        final_class = "UNABLE TO CLASSIFY. PLEASE CHECK DATA"
    return final_class
