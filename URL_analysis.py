import tkinter as tk
from tkinter import ttk, scrolledtext
import socket
import whois
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import hashlib
import tldextract
import dns.resolver
import yaml
import subprocess
import threading
import nmap

VIRUSTOTAL_API_KEY = " 723826fff779d223819f26d60b5d09e1e21dc81de26e4efe5aaf880efbcd7a8d "

def get_whois_info(url):
    try:
        return whois.whois(url)
    except Exception as e:
        return None

def collect_urls_from_page(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, "html.parser")
            urls = set()
            for anchor in soup.find_all("a", href=True):
                absolute_url = urljoin(url, anchor["href"])
                urls.add(absolute_url)
            return urls
        else:
            return set()
    except requests.exceptions.RequestException:
        return set()

def scan_phishing_and_malicious(url):
    try:
        # Check the URL with VirusTotal
        virustotal_result = check_virustotal(url)
        if virustotal_result == "Malicious":
            return "Phishing/Malicious"
        elif virustotal_result == "Error":
            return "Not able to define"
        else:
            return "Safe"
        
    except Exception:
        return "Error"

def generate_url_hash(url):
    sha256_hash = hashlib.sha256(url.encode()).hexdigest()
    return sha256_hash

def check_virustotal(url):
    try:
        api_url = f"https://www.virustotal.com/api/v3/urls/{generate_url_hash(url)}"
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        response = requests.get(api_url, headers=headers)
        if response.status_code == 200:
            json_response = response.json()
            if 'malicious' in json_response['data']['attributes']['last_analysis_stats']:
                return "Malicious"
            else:
                return "Safe"
        else:
            return "Error"
    except requests.exceptions.RequestException:
        return "Error"

def perform_dns_resolution(url):
    try:
        ext = tldextract.extract(url)
        domain = ext.registered_domain

        if not domain:
            return None

        answer = dns.resolver.resolve(domain, "A")
        ip_address = answer[0].address
        cname = str(answer.response.canonical_name)[:-1]
        mx_records = [str(mx.exchange) for mx in dns.resolver.resolve(domain, "MX")]
        txt_records = [str(txt) for txt in dns.resolver.resolve(domain, "TXT")]
        urls = collect_urls_from_page(url)

        return {
            "Domain": domain,
            "IP Address": ip_address,
            "CNAME": cname,
            "MX Records": mx_records,
            "TXT Records": txt_records,
            "Outgoing Links": urls,
        }
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        return None

def scan_nmap(url):
    nm = nmap.PortScanner()
    try:
        ext = tldextract.extract(url)
        domain = ext.registered_domain
        ip_address = socket.gethostbyname(domain)
        nm.scan(ip_address, arguments="-T4 -p80,443,3306,25,22,53,21,993,143")
        open_ports = []

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    open_ports.append(port)

        return open_ports
    except socket.gaierror:
        return []

def analyze_url_from_input(url_entry, final_tab):
    url = url_entry.get()
    scan_result = scan_phishing_and_malicious(url)
    url_hash = generate_url_hash(url)
    virustotal_result = check_virustotal(url)
    whois_info = get_whois_info(url)
    dns_info = perform_dns_resolution(url)
    nmap_result = scan_nmap(url)

    analysis_results = {
        "URL": url,
        "Scan Result": scan_result,
        "URL Hash": url_hash,
        "VirusTotal Result": virustotal_result,
        "WHOIS Info": whois_info,
        "DNS Info": dns_info,
        "Nmap Scan Result": nmap_result,
        "Headers": {
            "Content-Type": requests.head(url).headers.get("content-type"),
            "Server": requests.head(url).headers.get("server"),
        },

    }

    display_results(analysis_results, final_tab)

def display_results(results, final_tab):
    final_tab.config(state='normal')  
    final_tab.delete(1.0, tk.END) 
    final_tab.insert(tk.END, "\nURL Forensics Results\n\n")

    final_tab.insert(tk.END, "\nBasic Analysis:\n\n")
    for key, value in results.items():
        if key not in ("DNS Info", "Nmap Scan Result"):
            final_tab.insert(tk.END, f"{key}: {value}\n")
    final_tab.insert(tk.END, "\n")

    final_tab.insert(tk.END, "\nWHOIS Information:\n\n")
    whois_info = results.get("WHOIS Info", {})
    if whois_info:
        for key, value in whois_info.items():
            final_tab.insert(tk.END, f"{key}: {value}\n")
    else:
        final_tab.insert(tk.END, "\nWHOIS information not available.\n\n")
    final_tab.insert(tk.END, "\n")

    final_tab.insert(tk.END, "\nDNS Information:\n\n")
    dns_info = results.get("DNS Info", {})
    if dns_info:
        for key, value in dns_info.items():
            final_tab.insert(tk.END, f"{key}: {value}\n")
        final_tab.insert(tk.END, "\n")

        final_tab.insert(tk.END, "\nOutgoing Links:\n\n")
        outgoing_links = dns_info.get("Outgoing Links", [])
        for link in outgoing_links:
            final_tab.insert(tk.END, f"- {link}\n")
        final_tab.insert(tk.END, "\n")
    else:
        final_tab.insert(tk.END, "\nDNS information not available.\n")
        final_tab.insert(tk.END, "\n")

    final_tab.insert(tk.END, "\nNmap Scan Result:\n\n")
    nmap_result = results.get("Nmap Scan Result", [])
    if nmap_result:
        final_tab.insert(tk.END, "{:<8} {:<12} {:<10}\n".format("Port", "Status", "Service"))
        final_tab.insert(tk.END, "-"*35 + "\n")
        for port in nmap_result:
            status = "Open" if port in nmap_result else "Closed"
            service_name = socket.getservbyport(port, "tcp")
            final_tab.insert(tk.END, "{:<8} {:<12} {:<10}\n".format(port, status, service_name))
    else:
        final_tab.insert(tk.END, "No open ports found.\n")

    final_tab.insert(tk.END, "\n\nHeaders:\n\n")
    headers = results.get("Headers", {})
    for key, value in headers.items():
        final_tab.insert(tk.END, f"{key}: {value}\n")

    final_tab.insert(tk.END, "\n@kavin")

    final_tab.config(state='disabled')  # Disable editing the ScrolledText

def switch_to_final_tab(notebook, final_tab):
    notebook.select(final_tab)

def run_url_analysis(url_entry, final_tab, notebook):
    threading.Thread(target=analyze_url_from_input, args=(url_entry, final_tab)).start()

def create_main_window():
    root = tk.Tk()
    root.title("URL Forensics Tool")
    root.geometry("1000x800")  # Adjusted window size

    style = ttk.Style()
    style.configure("TButton", foreground="white", background="#0078D4", font=("Helvetica", 12, "bold"))
    style.configure("TLabel", font=("Helvetica", 14))
    style.configure("TFrame", background="#F5F5F5")
    style.configure("TNotebook", background="#F5F5F5")
    style.configure("TNotebook.Tab", background="#0078D4", font=("Helvetica", 12, "bold"), padding=[10, 5])

    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True)

    analysis_tab = ttk.Frame(notebook)
    notebook.add(analysis_tab, text="Analysis")

    title_label = ttk.Label(analysis_tab, text="URL Forensics", font=("Helvetica", 24, "bold"), padding=20)
    title_label.pack()

    url_label = ttk.Label(analysis_tab, text="Enter the URL:")
    url_label.pack(pady=10)

    url_entry = ttk.Entry(analysis_tab, width=60, font=("Helvetica", 14))
    url_entry.pack(pady=10)

    analyze_button = ttk.Button(analysis_tab, text="Analyze URL", command=lambda: run_url_analysis(url_entry, final_tab, notebook))
    analyze_button.pack(pady=20)

    result_label = ttk.Label(analysis_tab, text="Analysis Results:", font=("Helvetica", 18, "bold"))
    result_label.pack()

    result_text = scrolledtext.ScrolledText(analysis_tab, wrap=tk.WORD, state='disabled', height=15, font=("Helvetica", 12))
    result_text.pack(fill=tk.BOTH, expand=True)

    final_tab = scrolledtext.ScrolledText(notebook, wrap=tk.WORD, state='disabled', font=("Helvetica", 12))
    notebook.add(final_tab, text="Final Results")

    copy_button = ttk.Button(final_tab, text="Copy Result", command=lambda: root.clipboard_append(final_tab.get("1.0", tk.END)))
    copy_button.pack(pady=5)

    analyze_button.configure(command=lambda: [switch_to_final_tab(notebook, final_tab), run_url_analysis(url_entry, final_tab, notebook)])

    root.mainloop()

if __name__ == "__main__":
    create_main_window()

