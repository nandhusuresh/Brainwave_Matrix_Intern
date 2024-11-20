
import re
import requests
from urllib.parse import urlparse

# Phishing Keywords to Check
PHISHING_KEYWORDS = [
    "login", "secure", "account", "verify", "update", "bank", "signin", "free", "offer", "prize"
]

# Your VirusTotal API Key
API_KEY = "cbc04c2c35f378e75181d821da8e4a85a3ea0c1c270472771ae4ec6109d26e2c"

# Function to check URL for phishing patterns
def check_phishing(url):
    result = {
        "url": url,
        "suspicious_keywords": [],
        "is_ip_address": False,
        "too_many_subdomains": False,
        "reputation_check": "Not Checked",
        "is_suspicious": False
    }

    try:
        # Normalize the URL
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Check for suspicious keywords in URL
        for keyword in PHISHING_KEYWORDS:
            if keyword in url.lower():
                result["suspicious_keywords"].append(keyword)

        # Check if the domain is an IP address
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
            result["is_ip_address"] = True

        # Check for too many subdomains
        subdomains = domain.split(".")
        if len(subdomains) > 3:
            result["too_many_subdomains"] = True

        # Check reputation using VirusTotal API
        vt_url = f"https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": API_KEY}
        
        # Encode URL in VirusTotal format
        url_id = requests.utils.quote(url, safe='')
        vt_check_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
        response = requests.get(vt_check_url, headers=headers)
        if response.status_code == 200:
            vt_data = response.json()
            reputation = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if reputation.get("malicious", 0) > 0:
                result["reputation_check"] = "Malicious"
            else:
                result["reputation_check"] = "Clean"

        # Determine overall suspicion
        if result["suspicious_keywords"] or result["is_ip_address"] or result["too_many_subdomains"] or result["reputation_check"] == "Malicious":
            result["is_suspicious"] = True

    except Exception as e:
        result["error"] = str(e)

    return result

# Main Function
if __name__ == "__main__":
    url_to_check = input("Enter the URL to scan: ")
    report = check_phishing(url_to_check)

    print("\nPhishing Scan Report:")
    print(f"URL: {report['url']}")
    print(f"Suspicious Keywords: {', '.join(report['suspicious_keywords']) if report['suspicious_keywords'] else 'None'}")
    print(f"Is IP Address: {'Yes' if report['is_ip_address'] else 'No'}")
    print(f"Too Many Subdomains: {'Yes' if report['too_many_subdomains'] else 'No'}")
    print(f"Reputation Check: {report['reputation_check']}")
    print(f"Is Suspicious: {'Yes' if report['is_suspicious'] else 'No'}")
