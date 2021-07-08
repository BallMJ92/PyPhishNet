
```
import reputation, parse_header, analyse_body, os, time
class Automated_Classifier:
    def __init__(self):
        # Change variable constructor to the text file which holds the header information
        self.header_file = "header.txt"
        #self.body_file = "body.txt"
        self.export_file = "classification_"
        self.output_data = []
        self.phishing = "Thanks for raising this to us.\nThis has been confirmed as a Phishing Email.\nNo further Action is Required.\nKind Regards,\nInfoSec"
        self.spam = "Thanks for raising this to us.\nThis has been confirmed as a Spam Email.\nNo further Action is Required.\nKind Regards,\nInfoSec"
        self.legitimate = "Thanks for raising this to us.\nThis has been confirmed as a Legitimate Email.\nPlease speak to the sender directly to confirm if an action is required.\nKind Regards,\nInfoSec"
    # Function to open header text file and extract information to list
    def open_file(self, head_file):
        x = []
        # Appending header line to list
        with open(head_file, "r") as head:
            for i in head:
                x.append(i)
        # stripping specific characters from elements in list
        x = [i.strip("\n' '") for i in x]
        # removing empty elements in list
        x = [i.strip() for i in x if i != '']
        return x
    def save_file(self, fname, data):
        with open(fname, "w") as f:
            f.write(data)
            f.close()
    def main(self):
        """
        Program functions as follows:
        1. open header file
        2. Append each line to list
        3. Iterate over header list and extract required information
        (e.g. all urls, domain names, ip addresses, email addresses etc.)
        4. resolve domains from any parsed external ip addresses
        5. Using parsed information, check reputation using imported functions
        from reputation.py file
        6. Based on reputation information, determine classification
        e.g. >2 blacklisted domains or ip addresses then classify as Spam/Phishing
        """
        files = [f for f in os.listdir('.') if os.path.isfile(f)]
        files = [i for i in files if str('.txt') in i]
        files = [i for i in files if str('classification_') not in i and str('Human Intervention Required.txt') not in i]
        print(files)
        for i in range(0, len(files)):            
            header = self.open_file(files[i])
            #body = self.open_file(self.body_file)
            # Extracting data from header to determine reputation
            try:
                ip_addresses = parse_header.extract_all_ip_address(header)
            except (AttributeError, IndexError):
                ip_addresses = ["No data retrieved"]
                
            # Extracting any URLs present in header
            try:
                url = parse_header.extract_url(header)
            except (AttributeError, IndexError):
                url = ["No data retrieved"]
            # Extracting any External IP addresses in extracted IP list
            try:
                external_ip = parse_header.parse_external_ip(ip_addresses)
            except (AttributeError, IndexError):
                external_ip = ["No data retrieved"]
            # Resolving domains associated with external IPs
            try:
                if len(external_ip) >= 1:
                    resolved_domains = reputation.ip_domain_resolve(external_ip)
                else:
                    resolved_domains = ["No data retrieved"]
            except (AttributeError, IndexError):
                resolved_domains = ["No data retrieved"]
            # Interrogating and retrieving reputation data from Virus_Total
            try:
                virus_total_reputation = reputation.virus_total_reputation_search(resolved_domains)
            except (AttributeError, IndexError):
                virus_total_reputation = ["No data retrieved"]
            # Interrogating and retrieving reputation data from Cisco Talos
            try:
                cisco_talos_reputation = reputation.talos_reputation_search(external_ip)
            except (AttributeError, IndexError):
                cisco_talos_reputation = ["No data retrieved"]
            # Interrogating and retrieving reputation data from pydnsbl
            try:
                pydnsbl_reputation = reputation.pydnsbl_scan(external_ip)
            except (AttributeError, IndexError):
                pydnsbl_reputation = ["No data retrieved"]
            # Classifying header based on retrieved reputation data from Virus Total, Cisco Talos and PYDNSBL
            classify = reputation.classification(cisco_talos_reputation, pydnsbl_reputation, virus_total_reputation)
            try:
                if classify == "PHISHING":               
                    self.save_file(self.export_file+str(files[i]), self.phishing)
                elif classify == "SPAM/PHISHING":
                    self.save_file(self.export_file+str(files[i]), self.spam)
                elif classify == "LEGITIMATE/SPAM":
                    self.save_file(self.export_file+str(files[i]), self.legitimate)
                elif classify == "UNABLE TO CLASSIFY. PLEASE CHECK DATA":
                    with open('Human Intervention Required.txt', 'a') as file:
                        file.write(files[i])
                else:
                    pass
            except:
                pass
            time.sleep(2)
            
if __name__ == "__main__":
    ac = Automated_Classifier()
    ac.main()
```
