import requests
import csv

API_KEY_ABUSEIPDB = "" #Add the ABUSEIPDB API KEY HERE
API_KEY_VIRUSTOTAL = "" #Add the VT API KEY HERE

def print_python_icon():
    icon = [
        '       ____        ',
        '      / __ \___  __',
        '     / /_/ / _ \/ /',
        '    / _, _/  __/ / ',
        '   /_/ |_|\___/_/  ',
        '                   ',
        ' Automate IP Reputation from AbuseIPDB & VT                  ',
        '                   '
    ]

    for line in icon:
        print(line)

print_python_icon()



def get_ip_information(ip):
    url_abuseipdb = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&verbose"
    headers_abuseipdb = {
        "Key": API_KEY_ABUSEIPDB,
        "Accept": "application/json"
    }
    response_abuseipdb = requests.get(url_abuseipdb, headers=headers_abuseipdb)
    data_abuseipdb = response_abuseipdb.json()

    if "data" in data_abuseipdb:
        ip_data = data_abuseipdb["data"]
        is_malicious_abuseipdb = ip_data.get("isWhitelisted", False) or ip_data.get("abuseConfidenceScore", 0) >= 80
        abuseipdb_confidence = ip_data.get("abuseConfidenceScore", 0)
        isp = ip_data.get("isp", "N/A")
        domain = ip_data.get("domain", "N/A")
        country = ip_data.get("countryName", "N/A")
        city = ip_data.get("city", "N/A")
    else:
        return None, None, None, None, None, None, None, None

    url_virustotal = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers_virustotal = {
        "x-apikey": API_KEY_VIRUSTOTAL,
        "Accept": "application/json"
    }
    response_virustotal = requests.get(url_virustotal, headers=headers_virustotal)
    data_virustotal = response_virustotal.json()

    if "data" in data_virustotal:
        attributes = data_virustotal["data"].get("attributes", {})
        is_malicious_virustotal = attributes.get("last_analysis_stats", {}).get("malicious", 0) > 0
        engines_detected = len([result for result in attributes.get("last_analysis_results", {}).values() if result.get("category") == "malicious"])
        is_malicious_abuseipdb = is_malicious_abuseipdb or is_malicious_virustotal

    return is_malicious_abuseipdb, is_malicious_virustotal, abuseipdb_confidence, engines_detected, isp, domain, country, city

def main():
    input_csv_file = "sample.csv"  # Replace with your CSV file path
    output_csv_file = "result.csv"  # Replace with desired output CSV file path

    with open(input_csv_file, "r") as file:
        reader = csv.reader(file)
        rows = []
        for row in reader:
            ip = row[0]
            is_malicious_abuseipdb, is_malicious_virustotal, abuseipdb_confidence, engines_detected, isp, domain, country, city = get_ip_information(ip)
            if is_malicious_abuseipdb is None:
                reputation_abuseipdb = "Failed to retrieve"
            else:
                reputation_abuseipdb = "Malicious" if is_malicious_abuseipdb else "Not malicious"
            
            if is_malicious_virustotal is None:
                reputation_virustotal = "Failed to retrieve"
            else:
                reputation_virustotal = "Malicious" if is_malicious_virustotal else "Not malicious"
                
            rows.append([ip, reputation_abuseipdb, reputation_virustotal, abuseipdb_confidence, engines_detected, isp, domain, country, city])

    with open(output_csv_file, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "AbuseIPDB Reputation", "VirusTotal Reputation", "AbuseIPDB Confidence", "VirusTotal Engines Detected (Malicious)", "ISP", "Domain", "Country", "City"])
        writer.writerows(rows)

    print(f"[*]IP reputation information saved in: {output_csv_file}")

if __name__ == "__main__":
    main()
