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
import nmap
import threading
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Table

# Define your VIRUSTOTAL_API_KEY here
VIRUSTOTAL_API_KEY = "723826fff779d223819f26d60b5d09e1e21dc81de26e4efe5aaf880efbcd7a8d"

def run_url_analysis(url_entry, final_tab, notebook):
    url = url_entry.get()
    scan_result = scan_phishing_and_malicious(url)
    url_hash = generate_url_hash(url)
    virustotal_result = check_virustotal(url)
    whois_info = get_whois_info(url)
    dns_info = perform_dns_resolution(url)
    open_ports = scan_ports(url)

    analysis_results = {
        "URL": url,
        "Scan Result": scan_result,
        "URL Hash": url_hash,
        "VirusTotal Result": virustotal_result,
        "WHOIS Info": whois_info,
        "DNS Info": dns_info,
        "Open Ports": open_ports,
        "Headers": {
            "Content-Type": requests.head(url).headers.get("content-type"),
            "Server": requests.head(url).headers.get("server"),
        },
    }

    pdf_filename = "url_forensics_report.pdf"
    create_pdf_report(analysis_results, pdf_filename)
    display_results(analysis_results, final_tab)


# Define a dictionary mapping port numbers to their names
port_names = {
    21: "FTP",
    22: "SSH",
    26: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP (TLS)",
    993: "IMAPS",
    995: "POP3S",
}
def create_pdf_report(results, pdf_filename):
    doc = SimpleDocTemplate(pdf_filename, pagesize=letter)
    styles = getSampleStyleSheet()
    Story = []

    Story.append(Paragraph("URL Forensics Results", styles['Title']))
    Story.append(Spacer(1, 12))

    Story.append(Paragraph("Basic Analysis:", styles['Heading1']))
    for key, value in results.items():
        Story.append(Paragraph(f"{key}: {value}", styles['Normal']))
    Story.append(Spacer(1, 12))

    Story.append(Paragraph("WHOIS Information:", styles['Heading1']))
    whois_info = results.get("WHOIS Info", {})
    if whois_info:
        for key, value in whois_info.items():
            Story.append(Paragraph(f"{key}: {value}", styles['Normal']))
    else:
        Story.append(Paragraph("WHOIS information not available.", styles['Normal']))
    Story.append(Spacer(1, 12))

    Story.append(Paragraph("DNS Information:", styles['Heading1']))
    dns_info = results.get("DNS Info", {})
    if dns_info:
        for key, value in dns_info.items():
            Story.append(Paragraph(f"{key}: {value}", styles['Normal']))
        outgoing_links = dns_info.get("Outgoing Links", [])
        if outgoing_links:
            Story.append(Paragraph("Outgoing Links:", styles['Heading2']))
            for link in outgoing_links:
                Story.append(Paragraph(link, styles['Normal']))
    else:
        Story.append(Paragraph("DNS information not available.", styles['Normal']))
    Story.append(Spacer(1, 12))

    Story.append(Paragraph("Open Ports:", styles['Heading1']))
    open_ports = results.get("Open Ports", [])
    if open_ports:
        open_ports_str = ', '.join(map(str, open_ports))
        Story.append(Paragraph(f"Open Ports: {open_ports_str}", styles['Normal']))
    else:
        Story.append(Paragraph("No open ports found.", styles['Normal']))
    Story.append(Spacer(1, 12))

    Story.append(Paragraph("Headers:", styles['Heading1']))
    headers = results.get("Headers", {})
    for key, value in headers.items():
        Story.append(Paragraph(f"{key}: {value}", styles['Normal']))

    doc.build(Story)

# Define functions for URL analysis

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

def scan_ports(url):
    try:
        ext = tldextract.extract(url)
        domain = ext.registered_domain
        ip_address = socket.gethostbyname(domain)
        open_ports = []

        for port in range(1, 1025):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip_address, port))
            sock.close()
            if result == 0:
                open_ports.append(port)

        return open_ports
    except socket.gaierror:
        return []

# Functions for creating and displaying results

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
    dns_info = results.get("\nDNS Info", {})
    if dns_info:
        for key, value in dns_info.items():
            final_tab.insert(tk.END, f"{key}: {value}\n")
        final_tab.insert(tk.END, "\n")

        final_tab.insert(tk.END, "\nOutgoing Links:\n\n")
        outgoing_links = dns_info.get("\nOutgoing Links", [])
        for link in outgoing_links:
            final_tab.insert(tk.END, f"- {link}\n")
        final_tab.insert(tk.END, "\n")
    else:
        final_tab.insert(tk.END, "\nDNS information not available.\n")
        final_tab.insert(tk.END, "\n")

    final_tab.insert(tk.END, "\nOpen Ports:\n\n")
    open_ports = results.get("\nOpen Ports", [])
    if open_ports:
        for port in open_ports:
            port_name = port_names.get(port, "Unknown")
            final_tab.insert(tk.END, f"Port Name: {port_name}, Port Number: {port}\n")
    else:
        final_tab.insert(tk.END, "No open ports found.\n")

    final_tab.insert(tk.END, "\n@kavin")

    final_tab.config(state='disabled')  # Disable editing the ScrolledText

def switch_to_final_tab(notebook, final_tab):
    notebook.select(final_tab)

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

    analyze_button = ttk.Button(analysis_tab, text="Analyze URL", command=lambda: [switch_to_final_tab(notebook, final_tab), run_url_analysis(url_entry, final_tab, notebook)])
    analyze_button.pack(pady=20)

    final_tab = scrolledtext.ScrolledText(notebook, wrap=tk.WORD, state='disabled', font=("Helvetica", 12))
    notebook.add(final_tab, text="Final Results")

    copy_button = ttk.Button(final_tab, text="Copy Result", command=lambda: root.clipboard_append(final_tab.get("1.0", tk.END)))
    copy_button.pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    create_main_window()

