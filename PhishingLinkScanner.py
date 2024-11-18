import tkinter as tk
from tkinter import messagebox
import re
import tldextract
import requests
from urllib.parse import urlparse

# List of identified phishing potential malicious patterns
SUSPICIOUS_KEYWORDS = ['login', 'verify', 'update', 'secure', 'bank', 'account', 'paypal']

def extract_domain(url):
    """ 
    Retrieves the domain from an address of a URL. 
    """
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    return domain

def detect_suspicious_url(url):
    """ 
    The basic browsing check queries the application if any exist in the URL to look for suspicious links. 
    """
    # Check for suspicious keywords in the URL
    if any(keyword in url.lower() for keyword in SUSPICIOUS_KEYWORDS):
        return True, "Suspicious keywords detected"

    # Check for too many hyphenated words, subdomains, or query parameters
    if url.count('-') > 2 or url.count('.') > 4:
        return True, "Unusual URL structure"

    # Detect situations where IP addresses are used instead of domains
    if re.match(r"http[s]?://\d{1,3}(\.\d{1,3}){3}", url):
        return True, "IP address detected in URL"
    
    return False, "No immediate threat detected"

def query_virustotal(api_key, url):
    """ 
    Sends the URL to VirusTotal for evaluation of its reputation. The VirusTotal API key is required. 
    """
    vt_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": api_key}
    data = {"url": url}
    
    response = requests.post(vt_url, headers=headers, data=data)
    if response.status_code == 200:
        result = response.json()
        positives = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
        if positives > 0:
            return True, f"VirusTotal has a positive detection rate of {positives}."
        else:
            return False, "VirusTotal detects no threats"
    else:
        return None, "Failed to query VirusTotal"

# Define the GUI application class
class PhishingLinkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing Link Scanner")
        self.root.geometry("400x300")
        
        # URL entry field
        self.url_label = tk.Label(root, text="Enter URL to scan:")
        self.url_label.pack(pady=10)
        self.url_entry = tk.Entry(root, width=40)
        self.url_entry.pack(pady=5)

        # Scan button
        self.scan_button = tk.Button(root, text="Scan URL", fg="blue", command=self.scan_url)
        self.scan_button.pack(pady=10)

        # Output area
        self.result_text = tk.Label(root, text="", wraplength=500)
        self.result_text.pack(pady=10)

    def scan_url(self):
        # Get URL from input
        url = self.url_entry.get().strip()

        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL to scan.")
            return

        # Perform the basic checks of URL for detecting suspicious behavior
        suspicious, reason = detect_suspicious_url(url)
        result_message = f"[Basic Check] Suspicious: {suspicious}, Reason: {reason}\n"
        
        # Optional: Ask to query VirusTotal (requires API key)
        use_virustotal = messagebox.askyesno("VirusTotal Check", "Do you want to query VirusTotal for a deeper analysis?")
        
        if use_virustotal:
            api_key = "YOUR_VIRUSTOTAL_API_KEY"  # Replace with your VirusTotal API key
            vt_suspicious, vt_reason = query_virustotal(api_key, url)
            
            if vt_suspicious is None:
                result_message += "[VirusTotal] Query failed."
            else:
                result_message += f"[VirusTotal] Suspicious: {vt_suspicious}, Reason: {vt_reason}"

        # Display the result in the label
        self.result_text.config(text=result_message)

# Create the application window and run the app
root = tk.Tk()
app = PhishingLinkScannerApp(root)
root.mainloop()
