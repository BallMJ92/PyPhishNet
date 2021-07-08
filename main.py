import reputation, parse_header, analyse_body, os, time, sys
class Automated_Classifier:
    def __init__(self):
        # Change variable constructor to the text file which holds the header information
        # self.header_file = "header.txt"
        # self.body_file = "body.txt"
        self.export_file = "classification_"
        self.output_data = []
        self.phishing = "PHISHING"
        self.spam = "SPAM"
        self.legitimate = "LEGITIMATE"
        # ClassificationError 1 - Unable to classify, human intervention required
        self.error1 = "ClassificationError 1"
        # ClassificationError 2 - Classification failed
        self.error2 = "ClassificationError 1"
        
    # Function to open header text file and extract information to list
    def open_file(self, head_file):
        header_data = []
        # Appending header line to list
        with open(head_file, "r", encoding="utf-16") as head:
            for line in head:
                header_data.append(line)
        # stripping specific characters from elements in list
        header_data = [item.strip("\n' '") for item in header_data]
        # removing empty elements in list
        header_data = [item.strip() for item in header_data if item != '']
        return header_data
    def save_file(self, file_name, data):
        with open(file_name, "w") as file:
            file.write(data)
            file.close()
    def main(self):
        """
        files = [file for file in os.listdir('.') if os.path.isfile(file)]
        files = [name for name in files if str('.txt') in name]
        files = [keyword for keyword in files if
                 str('classification_') not in keyword and str('Human Intervention Required.txt') not in keyword]
        for incident in range(0, len(files)):
            header = self.open_file(files[incident])
            # body = self.open_file(self.body_file)
        """
        header = sys.argv[1:]
        # Extracting data from header to determine reputation
        try:
            ip_addresses = parse_header.extract_all_ip_address(header)
        except (AttributeError, IndexError):
            ip_addresses = ["No data retrieved"]
        except:
            pass
        # Extracting any URLs present in header
        try:
            url = parse_header.extract_url(header)
        except (AttributeError, IndexError):
            url = ["No data retrieved"]
        except:
            pass
        # Extracting any External IP addresses in extracted IP list
        try:
            external_ip = parse_header.parse_external_ip(ip_addresses)
        except (AttributeError, IndexError):
            external_ip = ["No data retrieved"]
        except:
            pass
        # Resolving domains associated with external IPs
        try:
            if len(external_ip) >= 1:
                resolved_domains = reputation.ip_domain_resolve(external_ip)
            else:
                resolved_domains = ["No data retrieved"]
        except (AttributeError, IndexError):
            resolved_domains = ["No data retrieved"]
        except:
            pass
        # Extracting any email addresses
        try:
            email_addresses = parse_header.extract_email_address(header)
        except(AttributeError, IndexError):
            email_addresses = ["No data retrieved"]
        # Interrogating and retrieving reputation data from Virus_Total
        try:
            virus_total_reputation = reputation.virus_total_reputation_search(resolved_domains)
        except:
            virus_total_reputation = ["No data retrieved"]
        # Interrogating and retrieving reputation data from Cisco Talos
        try:
            cisco_talos_reputation = reputation.talos_reputation_search(external_ip)
        except (AttributeError, IndexError, OSError):
            cisco_talos_reputation = ["No data retrieved"]
        except:
            pass
        # Interrogating and retrieving reputation data from pydnsbl
        try:
            pydnsbl_reputation = reputation.pydnsbl_scan(external_ip)
        except (AttributeError, IndexError):
            pydnsbl_reputation = ["No data retrieved"]
        except:
            pass
        # Classifying header based on retrieved reputation data from Virus Total, Cisco Talos and PYDNSBL
        classify = reputation.classification(cisco_talos_reputation, pydnsbl_reputation, virus_total_reputation)
        try:
            if classify == "PHISHING":
                # Saves file in same directory. Delete if no longer required
                self.save_file(self.export_file + str(files[incident]), self.phishing)
                # Return classification
                return self.phishing
            elif classify == "SPAM/PHISHING":
                self.save_file(self.export_file + str(files[incident]), self.spam)
                return self.spam
            elif classify == "LEGITIMATE/SPAM":
                # Check to determine if all email addresses in header are internal
                if len(email_addresses) == len([email for email in email_addresses if "@gazprom-mt.com" in email]):
                    #Check to determine if all IPs are internal
                    if len(ip_addresses) == len([ip for ip in ip_addresses if "10." in ip[0:2]]):
                        self.save_file(self.export_file + str(files[incident]), self.legitimate)
                        return self.legitimate
                else:
                    self.save_file(self.export_file + str(files[incident]), self.spam)
                    return self.spam
            elif classify == "UNABLE TO CLASSIFY. PLEASE CHECK DATA":
                return self.error1
            else:
                pass
        except:
            
            return self.error2             
        time.sleep(2)
if __name__ == "__main__":
    ac = Automated_Classifier()
    ac.main()
```
