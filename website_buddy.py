import requests, urllib3, json, time, os

def cls():
    os.system('cls' if os.name=='nt' else 'clear')


def threat_check(value_type, check_val):
    
    url = "https://api.threatcheck.silentpush.com/v1/"
    params = {
    "t": value_type,
    "d": "iofa",
    "u": "",
    "q": check_val
    }

    response = requests.get(url, params=params, verify=False)
    if response.status_code == 200:
        data = response.json()
        print(json.dumps(data, indent=4))
    else:
        response.raise_for_status()


def whois_check(domain):
    url = f"https://api.silentpush.com/api/v1/merge-api/explore/domain/whois/{domain}"
    api_key = ""
    headers = {
        "X-API-KEY": api_key
    }
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        data = response.json()
        print(json.dumps(data, indent=4))
    else:
        response.raise_for_status()


def historical_whois(hist_domain):

    url = f"https://www.virustotal.com/api/v3/domains/{hist_domain}/historical_whois?limit=10"

    headers = {
        "accept": "application/json",
        "x-apikey": ""
    }

    response = requests.get(url, headers=headers, verify=False)
    
    if response.status_code == 200:
        data = response.json()
        print(json.dumps(data, indent=4))
    else:
        response.raise_for_status()


def enrich_domain_ip(user_choice_2):
    
    value_to_enrich = input("Provide value for enrichment: ")
    if user_choice_2 == "1":
        url = f"https://api.silentpush.com/api/v1/merge-api/explore/enrich/domain/{value_to_enrich}?explain=0"
    elif user_choice_2 == "2":
        url = f"https://api.silentpush.com/api/v1/merge-api/explore/enrich/ipv4/{value_to_enrich}?explain=0"

    api_key = ""
    headers = {
        "X-API-KEY": api_key
    }
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        data = response.json()
        print(json.dumps(data, indent=4))
    else:
        response.raise_for_status()


def vt_scan(scan_domain):
    url = "https://www.virustotal.com/api/v3/urls"

    payload = { "url": scan_domain }
    headers = {
        "accept": "application/json",
        "x-apikey": "",
    }

    response = requests.post(url, data=payload, headers=headers, verify=False)

    if response.status_code == 200:
        time.sleep(60)
        data = response.json()
        get_url_report(json.dumps(data["data"]["id"]))
    else:
        response.raise_for_status()


def get_url_report(url_id):

    url = f"https://www.virustotal.com/api/v3/analyses/{str(url_id).replace("\"","")}"

    headers = {
        "accept": "application/json",
        "x-apikey": ""
    }

    response = requests.get(url, headers=headers, verify=False)

    if response.status_code == 200:
        data = response.json()

        malicious_stats = data["data"]["attributes"]["stats"]
        
        malicious_results = {key: value for key, value in data["data"]["attributes"]['results'].items() if value['category'] in ['malicious', 'suspicious']}

        print(json.dumps(malicious_stats, indent=4))
        print(json.dumps(malicious_results, indent=4))
    else:
        response.raise_for_status()


def get_relations(relations_domain):

    url_padns = f"https://www.virustotal.com/api/v3/domains/{relations_domain}/resolutions?limit=10"
    url_siblings = f"https://www.virustotal.com/api/v3/domains/{relations_domain}/siblings?limit=10"
    url_subdomains = f"https://www.virustotal.com/api/v3/domains/{relations_domain}/subdomains?limit=10"
    headers = {
        "accept": "application/json",
        "x-apikey": ""
    }

    response_padns = requests.get(url_padns, headers=headers, verify=False)
    response_siblings = requests.get(url_siblings, headers=headers, verify=False)
    response_subdomains = requests.get(url_subdomains, headers=headers, verify=False)

    if response_padns.status_code == 200:
        data_padns = response_padns.json()

        print("PADNS\n", json.dumps(data_padns, indent=4))
    else:
        response_padns.raise_for_status()

    if response_siblings.status_code == 200:
        data_siblings = response_siblings.json()
        print("Siblings\n")
        for sibling in data_siblings['data']:
            if sibling['attributes']['last_analysis_stats']['malicious'] == 0:
                print(json.dumps(sibling['id'], indent=4))
                print(json.dumps(sibling['attributes']['last_analysis_stats'], indent=4))
            else:
                print("Malicious Warning")
                print(json.dumps(sibling, indent=4))
    else:
        response_siblings.raise_for_status()

    if response_subdomains.status_code == 200:
        data_subdomains = response_subdomains.json()
        print("Subdomains\n")
        for subdomain in data_subdomains['data']:
            if subdomain['attributes']['last_analysis_stats']['malicious'] == 0:
                print(json.dumps(subdomain['id'], indent=4))
                print(json.dumps(subdomain['attributes']['last_analysis_stats'], indent=4))
            else:
                print("Malicious Warning")
                print(json.dumps(subdomain, indent=4))
        
    else:
        response_padns.raise_for_status()


def mx_search(mx_domain_ip):
    url = f"https://api.silentpush.com/api/v1/merge-api/explore/padns/lookup/query/mx/{mx_domain_ip}"
    api_key = ""
    headers = {
        "X-API-KEY": api_key
    }
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        data = response.json()
        print(json.dumps(data, indent=4))
    else:
        response.raise_for_status()


def main():

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    while True:
        print("Please choose an option by typing the number:\n1.Feed check [Silent Push]\n2.WHOIS check [Silent Push]\n3.Historical WHOIS [VT]\n4.Domain\\IP enrichment [Silent Push]\n5.VT Scan URL\\IP [VT]\n6.Passive DNS\\Siblings\\Subdomains Domain [VT]\n7. MX search [Silent Push]\n8.Exit...\n9. Clear screen")
        user_choice = input()
        if user_choice == "1":
            check_val = input("Provide value that need to be checked. It should be just domain, hostname or IP addr: ")
            value_type = input("Please choose if it is a domain/hostname [name] or IP [ip]: ")

            threat_check(value_type, check_val)

        elif user_choice == "2":
            domain = input("Provide domain: ")

            whois_check(domain)

        elif user_choice == "3":
            hist_domain = input("Provide domain: ")

            historical_whois(hist_domain)

        elif user_choice == "4":
            print("Choose by typing the number:\n1.Domain\n2.IP")
            user_choice_2 = input()

            if user_choice_2 == "1":
                enrich_domain_ip(user_choice_2)

            elif user_choice_2 == "2":
                enrich_domain_ip(user_choice_2)

        elif user_choice == "5":
            scan_domain = input("Provide domain/URL/IP to scan: ")

            vt_scan(scan_domain)
        
        elif user_choice == "6":
            relations_domain = input("Provide domain for relations details. IP/URL is not supported: ")

            get_relations(relations_domain)
        
        elif user_choice == "7":
            mx_domain_ip = input("Provide domain/IP for MX search: ")
            
            mx_search(mx_domain_ip)

        elif user_choice == "8":
            print("Good bye!")
            break
        elif user_choice == "9":
            cls()
        else:
            continue

if __name__ == "__main__":
    main()
