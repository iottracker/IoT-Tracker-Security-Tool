import scapy.all as scapy
import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import nmap
import csv
import re
import os
from reportlab.lib.pagesizes import landscape, A2
import html
from datetime import datetime
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle, Paragraph, SimpleDocTemplate, PageBreak, Spacer
import requests
from bs4 import BeautifulSoup
from reportlab.platypus import Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import ssl
from reportlab.lib.styles import getSampleStyleSheet
from PyPDF2 import PdfReader, PdfWriter
from io import BytesIO


 
common_ports = [
    80, 443, 22, 21, 23, 53, 123, 1883, 8883, 8080,
    5000, 5683, 4433, 5672, 47808, 67, 68, 161, 162,
    5353, 5355, 1900, 554, 1935, 5001, 5002, 8001,
    2049, 6000, 6005, 12345, 3690, 11211, 515, 3000, 8888
]



def scan_network(network):
    print(f"Scanning the network: {network} for devices...")

    arp_request = scapy.ARP(pdst=network)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = []
    for element in answered_list:
        device_info = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc,
        }
        devices.append(device_info)

    return devices


def scan_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        return port if sock.connect_ex((ip, port)) == 0 else None


def scan_ports(ip):
    open_ports = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in common_ports}
        for future in as_completed(futures):
            port = future.result()
            if port is not None:
                open_ports.append(port)

    return open_ports


def get_manufacturer(mac):
    url = f'https://api.macvendors.com/{mac}'
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.text
    except requests.RequestException:
        pass
    return "Unknown Manufacturer"



def analyze_traffic(ip):
    print(f"Starting traffic analysis for {ip}...")
    packets = scapy.sniff(filter=f"host {ip}", count=5)  
    traffic_data = []

    for packet in packets:
        if scapy.IP in packet:
            traffic_info = {
                "timestamp": packet.time,
                "source": packet[scapy.IP].src,
                "destination": packet[scapy.IP].dst,
                "protocol": packet[scapy.IP].proto,
                "length": len(packet)
            }
            traffic_data.append(traffic_info)

    return traffic_data

nm = nmap.PortScanner()

DIRECTORY_WORDLIST = ["admin", "login", "backup", "config", "uploads"]

# Define scan functions
def analyze_http_headers(ip, port=80):
    print(f"Scanning {ip}:{port} for HTTP header issues...")
    name="http headers issues"
    try:
        response = requests.get(f"http://{ip}:{port}", timeout=3)  
        headers = response.headers
        issues = []
        if "Content-Security-Policy" not in headers:
            issues.append("Missing Content-Security-Policy header.")
        if "Strict-Transport-Security" not in headers:
            issues.append("Missing Strict-Transport-Security header.")
        if "X-Frame-Options" not in headers:
            issues.append("Missing X-Frame-Options header.")
        return {'name':name , 'ip': ip, 'port': port, 'issues': issues}
    except Exception as e:
        return {'name':name ,'ip': ip, 'port': port, 'issues': [f"HTTP header analysis failed: {str(e)}"]}


def directory_enumeration(ip, port=80):
    print(f"Scanning {ip} for directory enumeration...")
    name="directory enumeration findings"

    findings = []
    for directory in DIRECTORY_WORDLIST:
        try:
            response = requests.get(f"http://{ip}:{port}/{directory}", timeout=5)
            if response.status_code == 200:
                findings.append(f"Accessible directory found: /{directory}")
        except Exception:
            continue
    return {'name':name,'ip': ip, 'port': port, 'findings': findings}

def test_sql_injection(ip, port=80):
    print(f"Scanning {ip} for sql injection...")
    payloads = ["'", "' OR '1'='1", "' AND 1=1 --"]
    findings = []
    name="sql injection findings"
    try:
        for payload in payloads:
            url = f"http://{ip}:{port}/?id={payload}"
            response = requests.get(url, timeout=5)
            if "error" in response.text.lower() or "sql" in response.text.lower():
                findings.append(f"Potential SQL Injection vulnerability found with payload: {payload}")
    except Exception:
        pass
    return {'name':name,'ip': ip, 'port': port, 'findings': findings}

def test_xss(ip, port=80):
    print(f"testing {ip} xss...")
    payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
    findings = []
    name="xss findings"
    try:
        for payload in payloads:
            url = f"http://{ip}:{port}/?q={payload}"
            response = requests.get(url, timeout=5)
            if payload in response.text:
                findings.append(f"Potential XSS vulnerability found with payload: {payload}")
    except Exception:
        pass
    return {'name':name,'ip': ip, 'port': port, 'findings': findings}

def scan_vulnerabilities(ip):
    print(f"Scanning {ip} for cve's...")
    nm = nmap.PortScanner()
    vulnerabilities = []
    global collected_cve_ids
    collected_cve_ids = [] 

    try:
     nm.scan(hosts=ip, arguments="-T4 --max-retries 1 --script vuln",timeout=300)

     for proto in nm[ip].all_protocols():
            for port in nm[ip][proto]:
                service = nm[ip][proto][port].get('name', 'Unknown')
                script_output = nm[ip][proto][port].get('script', {})

                for script_name, output in script_output.items():
                    cve_ids = re.findall(r'CVE-\d{4}-\d{4,7}', output)
                    collected_cve_ids.extend(cve_ids)  # Populate global list
                    vuln_names = re.findall(r'[A-Za-z0-9\s]+', output)
                    disclosure_dates = re.findall(r'Disclosure date:\s*(\S.+)', output)

                    vulnerabilities.append({
                        'ip': ip,
                        'port': port,
                        'service': service,
                        'cve_ids': cve_ids,
                        'vuln_names': vuln_names,
                        'disclosure_dates': disclosure_dates,
                        'script_name': script_name,
                        'output': output
                    })
    except Exception as e:
        print(f"Error scanning {ip}: {str(e)}")

    return vulnerabilities


def get_cve_details_from_circl_web(cve_id):
    try:
        cve_id = cve_id.upper()
        url = f"https://cve.circl.lu/cve/{cve_id}"
        response = requests.get(url, timeout=10)
        details = {
            'description': 'No description available',
            'disclosure_date': 'Not Available',
            'severity': 'Unknown'
        }

        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract description from Summary section
            summary_div = soup.find('div', class_='col-md-2 fw-bold', string='Summary')
            if summary_div:
                description_div = summary_div.find_next_sibling('div', class_='col')
                if description_div:
                    # Clean up extra characters and whitespace
                    description = description_div.get_text(strip=True)
                    description = re.sub(r'^==\s*%0\s*', '', description)  # Remove leading artifacts
                    details['description'] = description.strip('"').strip()

            # Extract disclosure date
            published_div = soup.find('div', class_='col-md-2 fw-bold', string='Published')
            if published_div:
                date_div = published_div.find_next_sibling('div', class_='col')
                if date_div:
                    details['disclosure_date'] = date_div.get_text(strip=True)

            # Extract CVSS score
            cvss_div = soup.find('div', class_='col-md-2 fw-bold', string='CVSS Score')
            if cvss_div:
                cvss_score = cvss_div.find_next_sibling('div', class_='col')
                if cvss_score:
                    details['severity'] = cvss_score.get_text(strip=True)

        return details
    
    except Exception as e:
        return {
            'description': f"Error: {str(e)}", 
            'disclosure_date': 'Error',
            'severity': 'Unknown'
        }
    
def scan_https_issues(ip, port=443):
    print(f"Scanning {ip}:{port} for HTTPS issues...")
    findings = []
    name="https issues"
    try:
        response = requests.get(f"https://{ip}:{port}", verify=False, timeout=5)
        if response.status_code == 200:
            findings.append("HTTPS server responded successfully.")
        if not response.headers.get("Strict-Transport-Security"):
            findings.append("Missing HSTS header (Strict-Transport-Security).")
    except Exception as e:
        # Don't add connection errors to findings when there's no HTTPS service
        # Connection refused errors indicate no service is running
        if "connection" not in str(e).lower() and "refused" not in str(e).lower():
            findings.append(f"HTTPS issue: {str(e)}")
    return {'name':name,'ip': ip, 'port': port, 'findings': findings}


def scan_services_for_issues(ip):
    print(f"Scanning {ip} for service-specific issues...")
    service_findings = []
    name="service findings"

    try:
        nm.scan(hosts=ip, arguments="-p- -sV")
        for proto in nm[ip].all_protocols():
            for port in nm[ip][proto]:
                service = nm[ip][proto][port].get('name', 'Unknown')

                if service == "https":
                    service_findings.append(scan_https_issues(ip, port))
    except Exception as e:
        print(f"Error scanning services for {ip}: {str(e)}")

    return service_findings
   

# Global variable to store CVE IDs
collected_cve_ids = []


from markupsafe import escape

def generate_html_report(vulnerabilities, findings):
    """Generate comprehensive HTML security report with vulnerabilities and findings"""
    report = []
    
    # Add modern CSS matching the new dashboard style
    report.append('''
    <style>
        /* Root Variables for Consistency */
        :root {
            --primary: #0F4C75;
            --primary-light: #3282B8;
            --primary-dark: #0e3c5c;
            --secondary: #16a085;
            --secondary-dark: #138a72;
            --accent: #1B262C;
            --danger: #e74c3c;
            --warning: #f39c12;
            --success: #27ae60;
            
            /* Neutral colors */
            --background: #f5f7fa;
            --foreground: #2D3748;
            --card: #ffffff;
            --card-foreground: #1A202C;
            --border: #E2E8F0;
            --input: #EDF2F7;
            
            /* Border and Shadow Variables */
            --border-radius: 8px; 
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --shadow-md: 0 6px 12px -2px rgba(0, 0, 0, 0.1), 0 3px 6px -2px rgba(0, 0, 0, 0.05);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
        }
        
        /* Report Container */
        .security-report {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.5;
            color: var(--foreground);
            max-width: 100%;
            margin: 0 auto;
        }
        
        /* Card Styles */
        .report-card {
            background-color: var(--card);
            border-radius: var(--border-radius);
            box-shadow: var(--shadow);
            margin-bottom: 1.5rem;
            overflow: hidden;
            border: 1px solid var(--border);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .report-card:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
        }
        
        .card-header {
            padding: 1rem 1.5rem;
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            color: white;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .card-header i {
            font-size: 1.25rem;
        }
        
        .card-body {
            padding: 1.5rem;
        }
        
        /* Section Headers and Content */
        .section-header {
            background: var(--primary);
            color: white;
            padding: 1rem 1.5rem;
            border-radius: var(--border-radius);
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
            transition: background-color 0.3s ease;
        }
                          .recommendations-container {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.5;
            color: var(--foreground);
            max-width: 100%;
            margin: 0 auto;
        }
        
        /* Card Styles */
        .rec-card {
            background-color: var(--card);
            border-radius: var(--border-radius);
            box-shadow: var(--shadow);
            margin-bottom: 1.5rem;
            overflow: hidden;
            border: 1px solid var(--border);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .rec-card:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
        }
        
        .rec-card-header {
            padding: 1rem 1.5rem;
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            color: white;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .rec-card-header i {
            font-size: 1.25rem;
        }
        
        .rec-card-body {
            padding: 1.5rem;
        }
        
        .section-header:hover {
            background: var(--primary-light);
        }
        
        .section-header h3 {
            margin: 0;
            color: white;
            font-size: 1.1rem;
            font-weight: 600;
        }
        
        .dropdown-arrow {
            transition: transform 0.3s ease;
        }
        
        .section-header.collapsed .dropdown-arrow {
            transform: rotate(-90deg);
        }
        
        .section-content {
            overflow: hidden;
            transition: max-height 0.5s ease-in-out, opacity 0.3s ease-in-out;
            max-height: 2000px;
            opacity: 1;
            background-color: var(--card);
            border-radius: 0 0 var(--border-radius) var(--border-radius);
            border: 1px solid var(--border);
            border-top: none;
            margin-bottom: 1.5rem;
        }
        
        .section-content.collapsed {
            max-height: 0;
            opacity: 0;
            margin-bottom: 0;
            border: none;
        }
        
        /* Terminal Styling */
        .terminal-window {
            background-color: var(--card);
            border-radius: var(--border-radius);
            overflow: hidden;
            margin-bottom: 1rem;
            box-shadow: var(--shadow);
            border: 1px solid var(--border);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .terminal-window:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
        }
        
        .terminal-header {
            background: var(--accent);
            padding: 0.75rem 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .terminal-buttons {
            display: flex;
            gap: 0.35rem;
        }
        
        .terminal-button {
            width: 0.75rem;
            height: 0.75rem;
            border-radius: 50%;
        }
        
        .terminal-button:nth-child(1) {
            background-color: var(--danger);
        }
        
        .terminal-button:nth-child(2) {
            background-color: var(--warning);
        }
        
        .terminal-button:nth-child(3) {
            background-color: var(--success);
        }
        
        .terminal-title {
            margin-left: 0.5rem;
            color: white;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
        }
        
        .terminal-content {
            padding: 1rem;
            background-color: var(--card);
            color: var(--foreground);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            overflow: auto;
        }
        
        .terminal-prompt {
            color: var(--primary-light);
            margin-right: 0.5rem;
            font-weight: bold;
        }
        
        .terminal-command {
            color: var(--primary);
            font-weight: bold;
        }
        
        .terminal-line {
            margin-bottom: 0.5rem;
            display: flex;
            align-items: flex-start;
        }
        
        .terminal-timestamp {
            color: #718096;
            font-size: 0.8rem;
            margin-right: 0.5rem;
        }
        
        .terminal-output {
            margin: 0.5rem 0 1rem 1.5rem;
        }
        
        .terminal-output div {
            margin-bottom: 0.25rem;
            position: relative;
            padding-left: 1rem;
            transition: transform 0.2s ease;
        }
        
        .terminal-output div::before {
            content: '→';
            position: absolute;
            left: 0;
            color: var(--primary-light);
        }
        
        .terminal-output .error {
            color: var(--danger);
        }
        
        .terminal-output .warning {
            color: var(--warning);
        }
        
        .terminal-output .success {
            color: var(--success);
        }
        
        .terminal-output .info {
            color: var(--primary-light);
        }
        
        /* Vulnerability Table */
        .vulnerability-container {
            margin-top: 1rem;
        }
        
        .vulnerability-table {
            width: 100%;
            border-collapse: collapse;
            border-radius: var(--border-radius);
            overflow: hidden;
            margin-bottom: 1rem;
            background-color: var(--card);
            box-shadow: var(--shadow);
        }
        
        .table-header {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr 3fr 1fr;
            background-color: var(--primary-light);
            color: white;
            font-weight: 600;
            padding: 0.75rem 1rem;
        }
        
        .vulnerability-row {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr 3fr 1fr;
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border);
            transition: background-color 0.2s ease;
        }
        
        .vulnerability-row:last-child {
            border-bottom: none;
        }
        
        .vulnerability-row:hover {
            background-color: var(--background);
        }
        
        /* Read More Button */
        .description-container {
            position: relative;
        }
        
        .short-desc, .full-desc {
            margin-bottom: 0.5rem;
        }
        
        .read-more {
            background-color: var(--primary);
            color: white;
            border: none;
            padding: 0.25rem 0.5rem;
            border-radius: var(--border-radius);
            font-size: 0.8rem;
            cursor: pointer;
            transition: background-color 0.2s ease;
        }
        
        .read-more:hover {
            background-color: var(--primary-dark);
        }
        
        /* No Results */
        .no-results {
            padding: 2rem;
            text-align: center;
            background-color: var(--card);
            border-radius: var(--border-radius);
            color: #718096;
            font-style: italic;
        }
        
        /* PDF Button */
        .pdf-button-container {
            display: flex;
            justify-content: flex-end;
            margin-bottom: 1rem;
        }
        
        .pdf-button {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            background-color: var(--primary);
            color: white;
            border: none;
            padding: 0.75rem 1rem;
            border-radius: var(--border-radius);
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
            text-decoration: none;
        }
        
        .pdf-button:hover {
            background-color: var(--primary-dark);
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }
        
        .pdf-button i {
            font-size: 1rem;
        }
        
        /* Dark Theme Support */
        .dark-theme .report-card {
            background-color: var(--dark-card);
            border-color: var(--dark-border);
        }
        
        .dark-theme .card-header {
            background: linear-gradient(135deg, var(--secondary), var(--secondary-dark));
        }
        
        .dark-theme .section-header {
            background: var(--secondary);
        }
        
        .dark-theme .section-header:hover {
            background: var(--secondary-dark);
        }
        
        .dark-theme .section-content {
            background-color: var(--dark-card);
            border-color: var(--dark-border);
        }
        
        .dark-theme .terminal-content {
            background-color: var(--dark-card);
            color: var(--dark-foreground);
        }
        
        .dark-theme .vulnerability-table {
            background-color: var(--dark-card);
        }
        
        .dark-theme .table-header {
            background-color: var(--secondary);
        }
        
        .dark-theme .vulnerability-row {
            border-color: var(--dark-border);
        }
        
        .dark-theme .vulnerability-row:hover {
            background-color: var(--dark-background);
        }
        
        .dark-theme .read-more {
            background-color: var(--secondary);
        }
        
        .dark-theme .read-more:hover {
            background-color: var(--secondary-dark);
        }
        
        .dark-theme .pdf-button {
            background-color: var(--secondary);
        }
        
        .dark-theme .pdf-button:hover {
            background-color: var(--secondary-dark);
        }
    </style>
    ''')
    ip_address = vulnerabilities[0]['ip'] if vulnerabilities else 'Unknown'
    report.append(f'''
    <div class="report-container">        
        <!-- Header Card -->
        <div class="rec-card">
            <div class="rec-card-header">
                <i class="fas fa-bug"></i>
                <span>IoT Vulnerabilities Report</span>
            </div>
            <div class="rec-card-body">
                <h2>Vulnerabilities Report</h2>
                <p><strong>Target IP:</strong> {ip_address}</p>
                <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Based on our security assessment, we've identified the following Vulnerabilities that effected your device.</p>
            </div>
        </div>
    ''')
    # --- Vulnerabilities Section with Dropdown (collapsed by default) ---
    report.append('''
    <div class="section-header collapsed" id="vulnerabilities-header">
        <h3><i class="fas fa-bug"></i> Identified Vulnerabilities</h3>
        <span class="dropdown-arrow">▼</span>
    </div>
    <div class="section-content collapsed" id="vulnerabilities-content">
        <div class="vulnerability-container">
    ''')
    
    if vulnerabilities:
        report.append('''
        <div class="vulnerability-table">
            <div class="table-header">
                <span>IP Address</span>
                <span>Service</span>
                <span>CVE ID</span>
                <span>Description</span>
                <span>Disclosure Date</span>
            </div>
        ''')

        cve_cache = {}  # Cache CVE details to avoid duplicate lookups
        
        for vuln in vulnerabilities:
            # Process CVE IDs with validation and deduplication
            raw_cves = vuln.get('cve_ids', [])
            cve_ids = [c for c in raw_cves if c.startswith('CVE-')]
            cve_ids = list(set(cve_ids))[:5]  # Deduplicate and limit
            
            if not cve_ids:
                continue  # Skip entries without valid CVEs

            # Get CVE details with caching
            cve_details = []
            disclosure_dates = []
            cve_id_display = []
            
            for cve in cve_ids:
                if cve not in cve_cache:
                    cve_cache[cve] = get_cve_details_from_circl_web(cve)
                details = cve_cache[cve]
                
                desc = escape(details.get('description', 'No description available'))
                date = escape(details.get('disclosure_date', 'Not available'))
                
                cve_details.append(f'''
                <div class="cve-entry">
                    <div class="description-container">
                        <div class="short-desc">{desc[:120]}...</div>
                        <div class="full-desc" style="display:none;">{desc}</div>
                        <button class="read-more">Read more</button>
                    </div>
                </div>
                ''')
                disclosure_dates.append(date)
                cve_id_display.append(escape(cve))

            report.append(f'''
            <div class="vulnerability-row">
                <span class="ip-address">{escape(vuln.get('ip', 'N/A'))}</span>
                <span class="service">{escape(vuln.get('service', 'Unknown'))}</span>
                <span class="cve-id">{', '.join(cve_id_display)}</span>
                <span class="descriptions">{''.join(cve_details)}</span>
                <span class="dates">{'<br>'.join(disclosure_dates)}</span>
            </div>
            ''')
        
        report.append('</div>') # Close vulnerability-table
    else:
        report.append('<div class="no-results">No critical vulnerabilities identified</div>')
    
    report.append('</div></div>') # Close vulnerability-container and section-content

    # --- Findings Section with Dropdown (collapsed by default) ---
    report.append('''
    <div class="section-header collapsed" id="findings-header">
        <h3><i class="fas fa-terminal"></i> Security Scan Findings</h3>
        <span class="dropdown-arrow">▼</span>
    </div>
    <div class="section-content collapsed" id="findings-content">
    ''')
    
    if findings:
        # Group findings by type
        finding_groups = {}
        for finding in findings:
            name = finding.get('name', 'Unknown Check')
            if name not in finding_groups:
                finding_groups[name] = []
            finding_groups[name].append(finding)
        
        # Create a terminal window for each finding type
        for name, group in finding_groups.items():
            # Skip empty groups
            if not any(f.get('findings', []) for f in group):
                continue
                
            # Create terminal window
            report.append(f'''
            <div class="terminal-window">
                <div class="terminal-header">
                    <div class="terminal-buttons">
                        <div class="terminal-button"></div>
                        <div class="terminal-button"></div>
                        <div class="terminal-button"></div>
                    </div>
                    <div class="terminal-title">{escape(name)}</div>
                </div>
                <div class="terminal-content">
            ''')
            
            # Add terminal content
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            report.append(f'<div class="terminal-line"><span class="terminal-timestamp">[{timestamp}]</span> <span>Initializing scan...</span></div>')
            
            # Process each finding in the group
            for finding in group:
                ip = finding.get('ip', 'N/A')
                port = finding.get('port', 'N/A')
                items = finding.get('findings', [])
                
                if not items:
                    continue
                
                # Add scan target line
                report.append(f'''
                <div class="terminal-line">
                    <span class="terminal-prompt">$</span>
                    <span class="terminal-command">scan {escape(name.lower().replace(' ', '_'))} --target={escape(ip)} --port={escape(port)}</span>
                </div>
                ''')
                
                # Add findings with appropriate styling
                report.append('<div class="terminal-output">')
                for item in items:
                    severity_class = "info"
                    if "critical" in item.lower() or "failed" in item.lower():
                        severity_class = "error"
                    elif "high" in item.lower() or "vulnerability" in item.lower() or "missing" in item.lower():
                        severity_class = "warning"
                    elif "success" in item.lower() or "secure" in item.lower() or "found" in item.lower():
                        severity_class = "success"
                    
                    report.append(f'<div class="{severity_class}">{escape(item)}</div>')
                report.append('</div>')
            
            # Add scan completion
            report.append('<div class="terminal-line"><span class="success">✓ Scan completed</span></div>')
            
            # Close terminal window
            report.append('</div></div>')
    else:
        report.append('''
        <div class="terminal-window">
            <div class="terminal-header">
                <div class="terminal-buttons">
                    <div class="terminal-button"></div>
                    <div class="terminal-button"></div>
                    <div class="terminal-button"></div>
                </div>
                <div class="terminal-title">Security Scan</div>
            </div>
            <div class="terminal-content">
                <div class="terminal-line">
                    <span class="terminal-prompt">$</span>
                    <span class="terminal-command">run_security_scan</span>
                </div>
                <div class="terminal-output">
                    <div class="info">Initializing security scan...</div>
                </div>
                <div class="terminal-line">
                    <span class="success">✓ Scan completed. No security findings detected.</span>
                </div>
            </div>
        </div>
        ''')
    report.append('</div>') # Close section-content

    # Close the security report container
    report.append('</div>')

    # --- PDF Generation and Interactive Elements JavaScript ---
    report.append('''
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        // Toggle read more/less for vulnerability descriptions
        document.querySelectorAll('.read-more').forEach(button => {
            button.addEventListener('click', (e) => {
                const container = e.target.closest('.description-container');
                const short = container.querySelector('.short-desc');
                const full = container.querySelector('.full-desc');
                
                short.style.display = short.style.display === 'none' ? 'block' : 'none';
                full.style.display = full.style.display === 'none' ? 'block' : 'none';
                e.target.textContent = full.style.display === 'none' ? 'Read more' : 'Show less';
            });
        });

        // Toggle dropdown sections
        document.querySelectorAll('.section-header').forEach(header => {
            header.addEventListener('click', () => {
                const content = document.getElementById(header.id.replace('-header', '-content'));
                header.classList.toggle('collapsed');
                content.classList.toggle('collapsed');
            });
        });
        
        // PDF Download functionality
        document.getElementById('download-pdf-report').addEventListener('click', function() {
            // Create a clone of the report to modify for PDF
            const reportElement = document.querySelector('.security-report');
            const pdfContent = reportElement.cloneNode(true);
            
            // Remove the PDF button from the clone
            const buttonContainer = pdfContent.querySelector('.pdf-button-container');
            if (buttonContainer) {
                buttonContainer.remove();
            }
            
            // Expand all collapsed sections for the PDF
            pdfContent.querySelectorAll('.section-content.collapsed').forEach(section => {
                section.classList.remove('collapsed');
                section.style.maxHeight = 'none';
                section.style.opacity = '1';
            });
            
            pdfContent.querySelectorAll('.section-header.collapsed').forEach(header => {
                header.classList.remove('collapsed');
            });
            
            // Show all full descriptions and hide short descriptions
            pdfContent.querySelectorAll('.short-desc').forEach(el => {
                el.style.display = 'none';
            });
            
            pdfContent.querySelectorAll('.full-desc').forEach(el => {
                el.style.display = 'block';
            });
            
            // Hide read more buttons
            pdfContent.querySelectorAll('.read-more').forEach(el => {
                el.style.display = 'none';
            });
            
            // Generate PDF with appropriate options
            const timestamp = document.getElementById('report-timestamp').textContent.replace(/[: ]/g, '-');
            const targetIp = document.getElementById('target-ip').textContent;
            const filename = `Security-Report-${targetIp}-${timestamp}.pdf`;
            
            const options = {
                margin: [10, 10, 10, 10],
                filename: filename,
                image: { type: 'jpeg', quality: 0.98 },
                html2canvas: { scale: 2, useCORS: true },
                jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' }
            };
            
            // Apply temporary styles for better PDF formatting
            pdfContent.style.padding = '10mm';
            pdfContent.style.backgroundColor = 'white';
            
            // Create a temporary container for the PDF content
            const container = document.createElement('div');
            container.appendChild(pdfContent);
            document.body.appendChild(container);
            container.style.position = 'absolute';
            container.style.left = '-9999px';
            
            // Generate the PDF
            html2pdf().from(pdfContent).set(options).save().then(() => {
                // Remove the temporary container after PDF generation
                document.body.removeChild(container);
            });
        });
    });
    </script>
    ''')

    return '\n'.join(report)


def get_device_details(ip):
    device_info = {
        "ip": ip,
        "name": "Unknown",
        "mac": "Unknown",
        "manufacturer": "Unknown",
        "open_ports": [],
        "latency": "Unknown"  
    }

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    if answered_list:
        device_info["mac"] = answered_list[0][1].hwsrc
        device_info["manufacturer"] = get_manufacturer(device_info["mac"])

    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        device_info["name"] = hostname
    except socket.herror:
        pass  

    return device_info


def write_table(file, headers, rows):
    file.write("<table><tr>")
    for header in headers:
        file.write(f"<th>{html.escape(header)}</th>")
    file.write("</tr>")

    for row in rows:
        file.write("<tr>")
        for cell in row:
            file.write(f"<td>{html.escape(str(cell))}</td>")
        file.write("</tr>")
    file.write("</table>")


def write_table(file, headers, rows):
    """Helper function to write a table to the HTML file."""
    file.write("<table border='1' style='width: 100%; border-collapse: collapse;'>")
    file.write("<tr>" + "".join([f"<th>{header}</th>" for header in headers]) + "</tr>")
    for row in rows:
        file.write("<tr>" + "".join([f"<td>{html.escape(str(cell))}</td>" for cell in row]) + "</tr>")
    file.write("</table>")


# Add to the top with other imports
from urllib.parse import urlparse

VENDOR_CONFIG = [
    {
        "name": "Apache",
        "patterns": [r"apache", r"mod_"],
        "recommendation": "Upgrade to {fixed_version}+",
        "reference": "https://httpd.apache.org/security",
        "notes": {
            "mod_rewrite": "Use 'UnsafeAllow3F' flag for unsafe RewriteRules"
        }
    },
        {
        "name": "LiteSpeed",
        "patterns": [r"LiteSpeed", r"LSWS"],
        "recommendation": "Upgrade to LiteSpeed Web Server 5.0+",
        "reference": "https://www.litespeedtech.com/",
        "notes": {
            "CVE-2010-2333": "Apply security patches for HTTP header injection"
        }
    },
    {
        "name": "PHP",
        "patterns": [r"PHP", r"grab_globals"],
        "recommendation": "Update PHP to 5.2.1+ and sanitize input",
        "reference": "https://www.php.net/",
        "notes": {
            "CVE-2005-3299": "Disable register_globals in php.ini"
        }
    }
    # Add other vendors as needed
]

def get_nvd_data(cve_id):
    """Fetch data from National Vulnerability Database"""
    try:
        response = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
            timeout=15
        )
        response.raise_for_status()
        data = response.json()
        
        if not data.get('vulnerabilities'):
            return {"error": "CVE not found in NVD"}
            
        vuln = data['vulnerabilities'][0]['cve']
        description = vuln['descriptions'][0]['value']
        metrics = vuln.get('metrics', {})
        
        # Process references
        references = list({ref['url'] for ref in vuln.get('references', [])})
        references = [ref for ref in references if urlparse(ref).scheme in ('http', 'https')]
        
        # Extract versions
        affected, fixed = set(), set()
        version_patterns = [
            r'versions? (?:before|prior to) (\d+\.\d+\.\d+)',
            r'(\d+\.\d+\.\d+) and earlier',
            r'fixed in (?:version )?(\d+\.\d+\.\d+)',
            r'upgrade to (\d+\.\d+\.\d+)'
        ]
        
        for pattern in version_patterns:
            matches = re.findall(pattern, description, re.IGNORECASE)
            for match in matches:
                if 'before' in pattern or 'prior' in pattern:
                    affected.add(match)
                else:
                    fixed.add(match)
        
        return {
            "description": description,
            "severity": get_cvss_severity(metrics),
            "references": references,
            "versions": {
                "affected": list(affected),
                "fixed": list(fixed)
            }
        }
        
    except Exception as e:
        return {"error": str(e)}

def get_cvss_severity(metrics):
    """Calculate CVSS severity rating"""
    cvss_v3 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
    cvss_v2 = metrics.get('cvssMetricV2', [{}])[0].get('cvssData', {})
    
    if cvss_v3:
        score = cvss_v3.get('baseScore', 0)
        severity = cvss_v3.get('baseSeverity', 'UNKNOWN')
        return f"{severity} ({score} CVSS v3)"
    
    if cvss_v2:
        score = cvss_v2.get('baseScore', 0)
        severity = 'HIGH' if score >= 7.0 else 'MEDIUM' if score >= 4.0 else 'LOW'
        return f"{severity} ({score} CVSS v2)"
    
    return "UNKNOWN"

def generate_vendor_advice(description):
    """Generate vendor-specific recommendations"""
    advice = []
    desc_lower = description.lower()
    
    for vendor in VENDOR_CONFIG:
        try:
            if any(re.search(pattern, desc_lower) for pattern in vendor['patterns']):
                recommendation = vendor['recommendation']
                versions = re.findall(r'\d+\.\d+\.\d+', description)
                
                if '{fixed_version}' in recommendation:
                    rec_version = versions[0] if versions else 'latest'
                    recommendation = recommendation.format(fixed_version=rec_version)
                
                entry = {
                    "vendor": vendor["name"],
                    "recommendation": recommendation,
                    "reference": vendor["reference"]
                }
                
                if "notes" in vendor:
                    for keyword, note in vendor["notes"].items():
                        if keyword in desc_lower:
                            entry["note"] = note
                            break
                
                advice.append(entry)
        except Exception as e:
            continue
            
    return advice

def generate_recommendations(vulnerabilities, open_ports):
    global collected_cve_ids
    recommendations = []

    # Add modern CSS that matches the new dashboard style
    recommendations.append('''
    <style>
        /* Root Variables for Consistency */
        :root {
            --primary: #0F4C75;
            --primary-light: #3282B8;
            --primary-dark: #0e3c5c;
            --secondary: #16a085;
            --secondary-dark: #138a72;
            --accent: #1B262C;
            --danger: #e74c3c;
            --warning: #f39c12;
            --success: #27ae60;
            
            /* Neutral colors */
            --background: #f5f7fa;
            --foreground: #2D3748;
            --card: #ffffff;
            --card-foreground: #1A202C;
            --border: #E2E8F0;
            --input: #EDF2F7;
            
            /* Border and Shadow Variables */
            --border-radius: 8px; 
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --shadow-md: 0 6px 12px -2px rgba(0, 0, 0, 0.1), 0 3px 6px -2px rgba(0, 0, 0, 0.05);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
        }
        
        /* Container styling */
        .recommendations-container {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.5;
            color: var(--foreground);
            max-width: 100%;
            margin: 0 auto;
        }
        
        /* Card Styles */
        .rec-card {
            background-color: var(--card);
            border-radius: var(--border-radius);
            box-shadow: var(--shadow);
            margin-bottom: 1.5rem;
            overflow: hidden;
            border: 1px solid var(--border);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .rec-card:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
        }
        
        .rec-card-header {
            padding: 1rem 1.5rem;
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            color: white;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .rec-card-header i {
            font-size: 1.25rem;
        }
        
        .rec-card-body {
            padding: 1.5rem;
        }
        
        /* Section header styling */
        .rec-section-header {
            background: var(--primary);
            color: white;
            padding: 1rem 1.5rem;
            border-radius: var(--border-radius);
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
            transition: background-color 0.3s ease;
        }
        
        .rec-section-header:hover {
            background: var(--primary-light);
        }
        
        .rec-section-header h3 {
            margin: 0;
            color: white;
            font-size: 1.1rem;
            font-weight: 600;
        }
        
        .dropdown-arrow {
            transition: transform 0.3s ease;
        }
        
        .rec-section-header.collapsed .dropdown-arrow {
            transform: rotate(-90deg);
        }
        
        .rec-section-content {
            overflow: hidden;
            transition: max-height 0.5s ease-in-out, opacity 0.3s ease-in-out;
            max-height: 2000px;
            opacity: 1;
            background-color: var(--card);
            border-radius: 0 0 var(--border-radius) var(--border-radius);
            border: 1px solid var(--border);
            border-top: none;
            margin-bottom: 1.5rem;
        }
        
        .rec-section-content.collapsed {
            max-height: 0;
            opacity: 0;
            margin-bottom: 0;
            border: none;
        }
        
        /* PDF Button */
        .pdf-button-container {
            display: flex;
            justify-content: flex-end;
            margin-bottom: 1rem;
        }
        
        .pdf-button {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            background-color: var(--primary);
            color: white;
            border: none;
            padding: 0.75rem 1rem;
            border-radius: var(--border-radius);
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
            text-decoration: none;
        }
        
        .pdf-button:hover {
            background-color: var(--primary-dark);
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }
        
        .pdf-button i {
            font-size: 1rem;
        }
        
        /* CVE Block styling */
        .cve-block {
            background-color: var(--card);
            border-radius: var(--border-radius);
            box-shadow: var(--shadow-sm);
            margin-bottom: 1rem;
            padding: 1.5rem;
            border: 1px solid var(--border);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .cve-block:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }
        
        .cve-id {
            display: flex;
            align-items: center;
            font-weight: 600;
            color: var(--primary);
            margin-bottom: 1rem;
            font-size: 1.1rem;
        }
        
        .severity {
            display: inline-flex;
            align-items: center;
            padding: 0.25rem 0.75rem;
            border-radius: 2rem;
            font-size: 0.8rem;
            font-weight: 600;
            color: white;
            margin-left: 1rem;
        }
        
        .high, .critical {
            background-color: var(--danger);
        }
        
        .medium {
            background-color: var(--warning);
        }
        
        .low {
            background-color: var(--success);
        }
        
        .cve-details {
            margin-top: 0.75rem;
        }
        
        .description {
            margin-bottom: 1rem;
            line-height: 1.6;
        }
        
        .versions {
            margin-bottom: 1rem;
            padding: 0.75rem;
            background-color: var(--background);
            border-radius: var(--border-radius);
            border-left: 3px solid var(--primary-light);
        }
        
        /* Action section styling */
        .action-section h4, .reference-section h4 {
            font-size: 1rem;
            color: var(--primary);
            margin-bottom: 0.75rem;
            font-weight: 600;
        }
        
        .action-list, .reference-list {
            list-style-type: none;
            padding-left: 0;
            margin-bottom: 1.5rem;
        }
        
        .vendor-action, .reference-item {
            display: flex;
            align-items: baseline;
            margin-bottom: 0.75rem;
            padding-bottom: 0.75rem;
            border-bottom: 1px dashed var(--border);
        }
        
        .vendor-action:last-child, .reference-item:last-child {
            border-bottom: none;
            margin-bottom: 0;
            padding-bottom: 0;
        }
        
        .vendor-name {
            font-weight: 600;
            color: var(--primary);
            margin-right: 0.5rem;
        }
        
        .action-note {
            margin-top: 0.75rem;
            padding: 0.75rem;
            background-color: rgba(243, 156, 18, 0.1);
            border-left: 3px solid var(--warning);
            border-radius: 0 var(--border-radius) var(--border-radius) 0;
            font-size: 0.9rem;
        }
        
        .special-flag {
            display: inline-flex;
            align-items: center;
            padding: 0.25rem 0.5rem;
            background-color: rgba(39, 174, 96, 0.1);
            border-radius: var(--border-radius);
            font-size: 0.8rem;
            font-weight: 500;
            color: var(--success);
            margin-left: 0.75rem;
        }
        
        /* Code examples */
        .code-example {
            margin-top: 1rem;
            background-color: var(--card);
            border-radius: var(--border-radius);
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--border);
            overflow: hidden;
        }
        
        .code-header {
            padding: 0.75rem 1rem;
            background-color: var(--background);
            border-bottom: 1px solid var(--border);
            font-weight: 600;
            font-size: 0.9rem;
            color: var(--foreground);
        }
        
        .code-content {
            padding: 1rem;
            font-family: 'JetBrains Mono', monospace;
            overflow-x: auto;
            background-color: var(--card);
            color: var(--foreground);
            margin: 0;
            font-size: 0.9rem;
            line-height: 1.5;
        }
        
        /* Implementation guide */
        .implementation-guide {
            background-color: var(--card);
            border-radius: var(--border-radius);
            box-shadow: var(--shadow);
            margin-top: 1.5rem;
            margin-bottom: 1rem;
            padding: 1.5rem;
            border: 1px solid var(--border);
        }
        
        .implementation-guide h3 {
            font-size: 1.1rem;
            color: var(--primary);
            margin-top: 0;
            margin-bottom: 1rem;
            font-weight: 600;
        }
        
        .priority-list {
            list-style-type: none;
            padding-left: 0;
            margin-bottom: 0;
        }
        
        .priority-item {
            display: flex;
            align-items: center;
            margin-bottom: 1rem;
            padding: 1rem;
            border-radius: var(--border-radius);
            position: relative;
        }
        
        .priority-item:last-child {
            margin-bottom: 0;
        }
        
        .priority-item.critical {
            background-color: rgba(231, 76, 60, 0.1);
            border-left: 4px solid var(--danger);
        }
        
        .priority-item.high {
            background-color: rgba(243, 156, 18, 0.1);
            border-left: 4px solid var(--warning);
        }
        
        .priority-item.maintenance {
            background-color: rgba(52, 152, 219, 0.1);
            border-left: 4px solid var(--primary-light);
        }
        
        .timeline {
            font-weight: 600;
            width: 150px;
            color: var(--foreground);
            margin-right: 1rem;
        }
        
        .task {
            color: var(--foreground);
        }
        
        /* Errors and messages */
        .error-block {
            background-color: rgba(231, 76, 60, 0.1);
            border-radius: var(--border-radius);
            border: 1px solid rgba(231, 76, 60, 0.3);
            margin-bottom: 1rem;
            padding: 1rem;
            color: var(--danger);
        }
        
        .error-heading {
            font-size: 1rem;
            font-weight: 600;
            margin-top: 0;
            margin-bottom: 0.75rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .error-heading i {
            font-size: 1.25rem;
        }
        
        .error-details {
            margin: 0;
            display: flex;
            align-items: baseline;
            gap: 0.75rem;
            flex-wrap: wrap;
        }
        
        .error-cve {
            font-weight: 600;
            font-family: 'JetBrains Mono', monospace;
            padding: 0.25rem 0.5rem;
            background-color: rgba(231, 76, 60, 0.2);
            border-radius: var(--border-radius);
        }
        
        /* Footer */
        .report-footer {
            text-align: center;
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border);
            color: #718096;
            font-size: 0.9rem;
        }
        
        /* Dark Theme Support */
        .dark-theme .rec-card {
            background-color: var(--dark-card);
            border-color: var(--dark-border);
        }
        
        .dark-theme .rec-card-header {
            background: linear-gradient(135deg, var(--secondary), var(--secondary-dark));
        }
        
        .dark-theme .rec-section-header {
            background: var(--secondary);
        }
        
        .dark-theme .rec-section-header:hover {
            background: var(--secondary-dark);
        }
        
        .dark-theme .rec-section-content {
            background-color: var(--dark-card);
            border-color: var(--dark-border);
        }
        
        .dark-theme .cve-block {
            background-color: var(--dark-card);
            border-color: var(--dark-border);
        }
        
        .dark-theme .cve-id {
            color: var(--secondary);
        }
        
        .dark-theme .versions {
            background-color: rgba(255, 255, 255, 0.05);
            border-left-color: var(--secondary);
        }
        
        .dark-theme .action-section h4, 
        .dark-theme .reference-section h4 {
            color: var(--secondary);
        }
        
        .dark-theme .vendor-name {
            color: var(--secondary);
        }
        
        .dark-theme .vendor-action, 
        .dark-theme .reference-item {
            border-color: var(--dark-border);
        }
        
        .dark-theme .action-note {
            background-color: rgba(243, 156, 18, 0.05);
        }
        
        .dark-theme .special-flag {
            background-color: rgba(39, 174, 96, 0.05);
        }
        
        .dark-theme .code-example {
            background-color: var(--dark-card);
            border-color: var(--dark-border);
        }
        
        .dark-theme .code-header {
            background-color: rgba(255, 255, 255, 0.05);
            border-color: var(--dark-border);
        }
        
        .dark-theme .code-content {
            background-color: var(--dark-card);
        }
        
        .dark-theme .implementation-guide {
            background-color: var(--dark-card);
            border-color: var(--dark-border);
        }
        
        .dark-theme .implementation-guide h3 {
            color: var(--secondary);
        }
        
        .dark-theme .pdf-button {
            background-color: var(--secondary);
        }
        
        .dark-theme .pdf-button:hover {
            background-color: var(--secondary-dark);
        }
    </style>
    ''')

    # Start building HTML
    ip_address = vulnerabilities[0]['ip'] if vulnerabilities else 'Unknown'
    
    recommendations.append(f'''
    <div class="recommendations-container">        
        <!-- Header Card -->
        <div class="rec-card">
            <div class="rec-card-header">
                <i class="fas fa-lightbulb"></i>
                <span>IoT Security Recommendations</span>
            </div>
            <div class="rec-card-body">
                <h2>Security Recommendations</h2>
                <p><strong>Target IP:</strong> {ip_address}</p>
                <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Based on our security assessment, we've identified the following recommendations to improve your device security.</p>
            </div>
        </div>
    ''')

    # Add CVE recommendations with dropdown sections
    processed_cves = set()
    
    if collected_cve_ids:
        recommendations.append('''
        <div class="rec-section-header collapsed" id="cve-recommendations-header">
            <h3><i class="fas fa-shield-alt"></i> CVE Recommendations</h3>
            <span class="dropdown-arrow">▼</span>
        </div>
        <div class="rec-section-content collapsed" id="cve-recommendations-content">
        ''')
        
        for vuln in vulnerabilities:
            for cve_id in collected_cve_ids:
                if cve_id in processed_cves:
                    continue

                try:
                    clean_cve = cve_id.replace("CVE-CVE-", "CVE-").strip()
                    nvd_data = get_nvd_data(clean_cve)
                    
                    if nvd_data.get('error'):
                        continue

                    # Build versions section
                    versions = ""
                    if nvd_data['versions']['fixed']:
                        version_list = " → ".join(nvd_data['versions']['fixed'])
                        versions = f"""<div class="versions">
                            <p><strong>Patched Versions:</strong> {version_list}+</p>
                        </div>"""

                    # Build actions section
                    vendor_advice = generate_vendor_advice(nvd_data['description'])
                    actions = ""
                    if vendor_advice:
                        action_items = []
                        for advice in vendor_advice:
                            action_line = f"""<li class="vendor-action">
                                <span class="vendor-name">{advice['vendor']}:</span>
                                <span class="action-text">{advice['recommendation']}</span>
                                {"<span class='special-flag'>⚙️ Use flag: [UnsafeAllow3F]</span>" if 'mod_rewrite' in nvd_data['description'] else ""}
                                {"<div class='action-note'>⚠️ Note: {advice['note']}</div>" if 'note' in advice else ""}
                            </li>"""
                            action_items.append(action_line)
                        actions = f"""<div class="action-section">
                            <h4>Required Actions:</h4>
                            <ul class="action-list">{''.join(action_items)}</ul>
                        </div>"""

                    # Build references section
                    references = ""
                    if nvd_data['references']:
                        ref_items = []
                        for idx, ref in enumerate(nvd_data['references'][:3], 1):
                            domain = ref.split('//')[-1].split('/')[0]
                            ref_items.append(f"""<li class="reference-item">
                                <span class="ref-number">{idx}.</span>
                                <a href="{ref}" target="_blank" class="ref-link">{domain}</a>
                            </li>""")
                        references = f"""<div class="reference-section">
                            <h4>References:</h4>
                            <ul class="reference-list">{''.join(ref_items)}</ul>
                        </div>"""

                    # Add code example if needed
                    code_example = ""
                    if 'mod_rewrite' in nvd_data['description']:
                        code_example = f"""<div class="code-example">
                            <div class="code-header">Example Configuration</div>
                            <pre class="code-content">RewriteRule ^/path/(.*)$ /newpath/$1 [L,UnsafeAllow3F]</pre>
                        </div>"""

                    # Get severity class for styling
                    severity_text = nvd_data['severity'].lower()
                    severity_class = "medium"
                    if "critical" in severity_text or "high" in severity_text:
                        severity_class = "high"
                    elif "low" in severity_text:
                        severity_class = "low"

                    # Build full CVE block
                    cve_block = f"""<div class="cve-block">
                        <h3 class="cve-id">{clean_cve} <span class="severity {severity_class}">{nvd_data['severity']}</span></h3>
                        <div class="cve-details">
                            <p class="description"><strong>Description:</strong> {nvd_data['description'].split('.')[0]}</p>
                            {versions}
                            {actions}
                            {references}
                            {code_example}
                        </div>
                    </div>"""
                    
                    recommendations.append(cve_block)
                    processed_cves.add(cve_id)

                except Exception as e:
                    error_block = f"""<div class="error-block">
                        <h4 class="error-heading"><i class="fas fa-exclamation-triangle"></i> Processing Error</h4>
                        <p class="error-details">
                            <span class="error-cve">{clean_cve}</span>
                            <span class="error-message">Error: {str(e)}</span>
                        </p>
                    </div>"""
                    recommendations.append(error_block)
        
        recommendations.append('</div>')  # Close CVE recommendations section
    
    # Add implementation guide with dropdown
    recommendations.append('''
    <div class="rec-section-header collapsed" id="implementation-header">
        <h3><i class="fas fa-tasks"></i> Implementation Guide</h3>
        <span class="dropdown-arrow">▼</span>
    </div>
    <div class="rec-section-content collapsed" id="implementation-content">
        <div class="implementation-guide">
            <h3>Priority Implementation Guide</h3>
            <ul class="priority-list">
                <li class="priority-item critical">
                    <span class="timeline">Immediate (0-24h):</span>
                    <span class="task">Apply patches for critical CVEs and address high-impact vulnerabilities</span>
                </li>
                <li class="priority-item high">
                    <span class="timeline">Short-Term (24-72h):</span>
                    <span class="task">Implement recommended security controls and address high severity issues</span>
                </li>
                <li class="priority-item maintenance">
                    <span class="timeline">Continuous:</span>
                    <span class="task">Establish regular security monitoring and update processes</span>
                </li>
            </ul>
        </div>
    </div>
    ''')

    # Add port recommendations based on open ports
    if open_ports:
        recommendations.append('''
        <div class="rec-section-header collapsed" id="port-recommendations-header">
            <h3><i class="fas fa-network-wired"></i> Port Security Recommendations</h3>
            <span class="dropdown-arrow">▼</span>
        </div>
        <div class="rec-section-content collapsed" id="port-recommendations-content">
        ''')
        
        # Create port recommendation blocks
        common_ports = {
            '22': {'service': 'SSH', 'recommendations': ['Use key-based authentication instead of passwords', 'Implement fail2ban to prevent brute force attacks', 'Consider changing to a non-standard port']},
            '23': {'service': 'Telnet', 'recommendations': ['Disable Telnet and use SSH instead', 'Telnet transmits data in plaintext and is insecure']},
            '80': {'service': 'HTTP', 'recommendations': ['Configure redirects to HTTPS', 'Implement proper HTTP security headers', 'Consider using a Web Application Firewall']},
            '443': {'service': 'HTTPS', 'recommendations': ['Ensure you are using strong TLS configurations', 'Use modern TLS 1.2 or 1.3 only', 'Configure proper HTTPS certificates']},
            '21': {'service': 'FTP', 'recommendations': ['Replace with SFTP or FTPS', 'FTP transmits credentials in plaintext']},
            '25': {'service': 'SMTP', 'recommendations': ['Implement email authentication (SPF, DKIM, DMARC)', 'Use TLS for email transmission']},
            '3389': {'service': 'RDP', 'recommendations': ['Restrict RDP access to VPN only', 'Implement Network Level Authentication', 'Use strong passwords and account lockout policies']},
        }
        
        for port in open_ports:
            port_str = str(port)
            if port_str in common_ports:
                port_info = common_ports[port_str]
                port_block = f"""<div class="cve-block">
                    <h3 class="cve-id">Port {port} ({port_info['service']})</h3>
                    <div class="cve-details">
                        <div class="action-section">
                            <h4>Security Recommendations:</h4>
                            <ul class="action-list">"""
                
                for rec in port_info['recommendations']:
                    port_block += f"""<li class="vendor-action">
                        <span class="action-text">{rec}</span>
                    </li>"""
                
                port_block += """</ul>
                        </div>
                    </div>
                </div>"""
                recommendations.append(port_block)
            else:
                recommendations.append(f"""<div class="cve-block">
                    <h3 class="cve-id">Port {port} (Unknown Service)</h3>
                    <div class="cve-details">
                        <div class="action-section">
                            <h4>Security Recommendations:</h4>
                            <ul class="action-list">
                                <li class="vendor-action">
                                    <span class="action-text">Verify if this port is necessary for your operations</span>
                                </li>
                                <li class="vendor-action">
                                    <span class="action-text">If not required, close this port to reduce attack surface</span>
                                </li>
                                <li class="vendor-action">
                                    <span class="action-text">Implement proper firewall rules to restrict access</span>
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>""")
        
        recommendations.append('</div>')  # Close port recommendations section
    
    # Add general security recommendations section
    recommendations.append('''
    <div class="rec-section-header collapsed" id="general-recommendations-header">
        <h3><i class="fas fa-lock"></i> General Security Recommendations</h3>
        <span class="dropdown-arrow">▼</span>
    </div>
    <div class="rec-section-content collapsed" id="general-recommendations-content">
        <div class="cve-block">
            <h3 class="cve-id">Network Segmentation</h3>
            <div class="cve-details">
                <p class="description">Isolate IoT devices on a separate network segment to limit their access to sensitive systems.</p>
                <div class="action-section">
                    <h4>Implementation Steps:</h4>
                    <ul class="action-list">
                        <li class="vendor-action">
                            <span class="action-text">Create a dedicated VLAN for IoT devices</span>
                        </li>
                        <li class="vendor-action">
                            <span class="action-text">Implement firewall rules to control traffic between network segments</span>
                        </li>
                        <li class="vendor-action">
                            <span class="action-text">Use a separate Wi-Fi network for IoT devices when possible</span>
                        </li>
                    </ul>
                </div>
            </div>
        </div>
        
        <div class="cve-block">
            <h3 class="cve-id">Update Management</h3>
            <div class="cve-details">
                <p class="description">Establish a regular process for updating firmware and software on all IoT devices.</p>
                <div class="action-section">
                    <h4>Implementation Steps:</h4>
                    <ul class="action-list">
                        <li class="vendor-action">
                            <span class="action-text">Create an inventory of all IoT devices</span>
                        </li>
                        <li class="vendor-action">
                            <span class="action-text">Subscribe to vendor security notifications</span>
                        </li>
                        <li class="vendor-action">
                            <span class="action-text">Implement a regular schedule for checking and applying updates</span>
                        </li>
                    </ul>
                </div>
            </div>
        </div>
        
        <div class="cve-block">
            <h3 class="cve-id">Default Credentials</h3>
            <div class="cve-details">
                <p class="description">Change all default passwords and disable unnecessary accounts on IoT devices.</p>
                <div class="action-section">
                    <h4>Implementation Steps:</h4>
                    <ul class="action-list">
                        <li class="vendor-action">
                            <span class="action-text">Implement a strong password policy</span>
                        </li>
                        <li class="vendor-action">
                            <span class="action-text">Use a password manager to generate and store unique credentials</span>
                        </li>
                        <li class="vendor-action">
                            <span class="action-text">Disable guest and demo accounts</span>
                        </li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
    ''')

    # Add footer and close container
    recommendations.append('''
    <div class="report-footer">
        <p>Report generated by: IoT Tracker</p>
    </div>
    </div>
    ''')

    # Add JavaScript for dropdown functionality and PDF generation
    recommendations.append('''
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        // Manually initialize dropdown functionality
        function initializeDropdowns() {
            console.log("Initializing dropdown functionality");
            
            // Find all section headers
            document.querySelectorAll('.rec-section-header').forEach(header => {
                // Remove any existing event listeners
                const newHeader = header.cloneNode(true);
                header.parentNode.replaceChild(newHeader, header);
                
                // Add click event listener
                newHeader.addEventListener('click', function() {
                    console.log("Header clicked:", this.id);
                    this.classList.toggle('collapsed');
                    
                    const contentId = this.id.replace('-header', '-content');
                    const content = document.getElementById(contentId);
                    
                    if (content) {
                        content.classList.toggle('collapsed');
                        console.log("Toggled content:", contentId);
                    } else {
                        console.warn("Could not find content element:", contentId);
                    }
                });
            });
        }
        
        // Initialize dropdowns
        setTimeout(initializeDropdowns, 100);
        
        // PDF Download functionality
        const pdfButton = document.getElementById('download-recommendations-pdf');
        if (pdfButton) {
            pdfButton.addEventListener('click', function() {
                console.log("PDF button clicked");
                
                // Create a clone of the recommendations to modify for PDF
                const recommendationsElement = document.querySelector('.recommendations-container');
                const pdfContent = recommendationsElement.cloneNode(true);
                
                // Remove the PDF button from the clone
                const buttonContainer = pdfContent.querySelector('.pdf-button-container');
                if (buttonContainer) {
                    buttonContainer.remove();
                }
                
                // Expand all collapsed sections for the PDF
                pdfContent.querySelectorAll('.rec-section-content.collapsed').forEach(section => {
                    section.classList.remove('collapsed');
                    section.style.maxHeight = 'none';
                    section.style.opacity = '1';
                });
                
                pdfContent.querySelectorAll('.rec-section-header.collapsed').forEach(header => {
                    header.classList.remove('collapsed');
                });
                
                // Generate PDF with appropriate options
                const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
                const filename = `IoT-Security-Recommendations-${timestamp}.pdf`;
                
                const options = {
                    margin: [10, 10, 10, 10],
                    filename: filename,
                    image: { type: 'jpeg', quality: 0.98 },
                    html2canvas: { scale: 2, useCORS: true },
                    jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' }
                };
                
                // Apply temporary styles for better PDF formatting
                pdfContent.style.padding = '10mm';
                pdfContent.style.backgroundColor = 'white';
                
                // Create a temporary container for the PDF content
                const container = document.createElement('div');
                container.appendChild(pdfContent);
                document.body.appendChild(container);
                container.style.position = 'absolute';
                container.style.left = '-9999px';
                
                // Generate the PDF
                html2pdf().from(pdfContent).set(options).save().then(() => {
                    // Remove the temporary container after PDF generation
                    document.body.removeChild(container);
                });
            });
        } else {
            console.warn("PDF button not found");
        }
    });
    </script>
    ''')

    return ''.join(recommendations)

def save_recommendations_to_file(recommendations):
    with open("recommendations.txt", "a") as file:
        file.write("\n".join(recommendations) + "\n")
        file.write("\n"+"============================================================"+"\n")


def save_to_html(devices, vulnerabilities, traffic_data, recommendations):
    pdf_filename = "combined_report.pdf"  
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  

    with open('devices.html', 'w', encoding='utf-8') as file:  
        file.write(f"""
        <html>
        <head>
            <title>IOT Devices Report</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f4f4f9;
                    color: #333;
                }}
                h1 {{
                    text-align: center;
                    color: black;
                    margin-top: 20px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }}
                h1 img {{
                    height: 40px;
                    margin-right: 15px;
                    border: 2px solid red; /* Red border around the logo */
                    padding: 5px;
                }}
                .top-right {{
                    position: absolute;
                    top: 10px;
                    right: 20px;
                    font-size: 14px;
                    color: #333;
                    z-index: 1; /* Ensure it appears behind the title */
                }}
                h2, h3 {{
                    text-align: center;
                    color: blue;
                }}
                h2, h3 {{
                    margin-top: 40px;
                }}
                table {{
                    width: 80%;
                    margin: 20px auto;
                    border-collapse: collapse;
                    background-color: white;
                    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                }}
                table, th, td {{
                    border: 1px solid #ddd;
                }}
                th, td {{
                    padding: 10px;
                    text-align: left;
                }}
                th {{
                    background-color: #f2f2f2;
                }}
                ul, ol {{
                    list-style-position: inside;
                    padding: 0;
                    margin: 10px 0;
                }}
                li {{
                    margin: 8px 0;
                }}
                a {{
                    color: #007BFF;
                    text-decoration: none;
                    font-weight: bold;
                }}
                a:hover {{
                    text-decoration: underline;
                }}
                .section {{
                    margin-bottom: 50px;
                }}
                .center {{
                    text-align: center;
                    margin-top: 20px;
                }}
            </style>
        </head>
        <body>
            <h1><img src="Untitled design.png" alt="Logo">IOT DEVICES REPORT</h1>
            <div class="top-right">
                Generated on: {current_time}
            </div>
        """)

        # Device Information Table
        file.write("<div class='section'><h2>Device Information</h2>")
        headers = ["IP Address", "MAC Address", "Manufacturer", "Open Ports"]
        rows = []
        for device in devices:
            open_ports = scan_ports(device['ip'])
            device_details = get_device_details(device['ip'])
            rows.append([
                device_details['ip'],
                device_details.get('mac', 'N/A'),
                device_details.get('manufacturer', 'N/A'),
                ', '.join(map(str, open_ports)) if open_ports else 'N/A',
            ])
        write_table(file, headers, rows)
        file.write("</div>")  

        file.write("<div class='section'><h2>Recommendations</h2>")
        try:
            with open("recommendations.txt", "r", encoding='utf-8') as rec_file:
                recommendations_content = rec_file.read()
                file.write("<ol>")
                for rec in recommendations_content.split("\n"):
                    rec = rec.strip()  
                    if rec == "============================================================":
                        file.write(
                            f"<div style='text-align:center; margin: 10px 0;'><strong>{html.escape(rec)}</strong></div>")
                    elif rec:  
                        file.write(f"<li>{html.escape(rec)}</li>")
                file.write("</ol>")
        except FileNotFoundError:
            file.write("<p>No recommendations available.</p>")
        file.write("</div>") 

        file.write("<div class='section'><h2>Traffic Analysis Results</h2>")
        for ip, data in traffic_data.items():
            file.write(f"<h3>Traffic Data for {ip}</h3>")
            headers = ["Timestamp", "Source", "Destination", "Protocol", "Length"]
            rows = [
                [traffic.get('timestamp', 'N/A'),
                 traffic.get('source', 'N/A'),
                 traffic.get('destination', 'N/A'),
                 traffic.get('protocol', 'N/A'),
                 traffic.get('length', 'N/A')] for traffic in data
            ]
            write_table(file, headers, rows)
        file.write("</div>")  

        if os.path.exists(pdf_filename):
            file.write("<div class='section'><h2>Vulnerability Scan Results</h2>")

            file.write("<div class='center'>")
            file.write(f'<h3>Download Full Vulnerability Report in PDF Format</h3>')
            file.write(f'<a href="{pdf_filename}" download>Download Vulnerabilities PDF</a>')
            file.write("</div>")  
            file.write("</div>")  
        else:
            print(f"The PDF file '{pdf_filename}' does not exist.")

        file.write("""
        </body>
        </html>
        """)


def save_to_csv(devices, traffic_data):
    recommendations_file = "recommendations.txt"
    vulnerabilities_pdf = "combined_report.pdf"

    with open('devices.csv', mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)

        writer.writerow(["IOT Devices Report"])
        writer.writerow([])  
        writer.writerow(["Device Information"])
        writer.writerow(["IP Address", "MAC Address", "Manufacturer", "Open Ports"])
        for device in devices:
            open_ports = scan_ports(device['ip'])  
            device_details = get_device_details(device['ip'])  
            writer.writerow([
                device_details.get('ip', 'N/A'),
                device_details.get('mac', 'N/A'),
                device_details.get('manufacturer', 'N/A'),
                ', '.join(map(str, open_ports)) if open_ports else 'N/A'
            ])
        writer.writerow([]) 

        writer.writerow(["Recommendations"])
        try:
            if os.path.exists(recommendations_file):
                with open(recommendations_file, "r", encoding='utf-8') as rec_file:
                    for line in rec_file:
                        writer.writerow([line.strip()])
            else:
                writer.writerow(["No recommendations available."])
        except Exception as e:
            writer.writerow([f"Error reading recommendations: {str(e)}"])
        writer.writerow([]) 

        writer.writerow(["Traffic Analysis Results"])
        for ip, data in traffic_data.items():
            writer.writerow([f"Traffic Data for {ip}"])
            writer.writerow(["Timestamp", "Source", "Destination", "Protocol", "Length"])
            for traffic in data:
                writer.writerow([
                    traffic.get('timestamp', 'N/A'),
                    traffic.get('source', 'N/A'),
                    traffic.get('destination', 'N/A'),
                    traffic.get('protocol', 'N/A'),
                    traffic.get('length', 'N/A')
                ])
            writer.writerow([])  

        writer.writerow(["Vulnerability Results are saved to combined_report.pdf"])


def display_menu():
    print("\nPlease choose an option:")
    print("1. Scan Vulnerabilities")
    print("2. Analyze Traffic")
    print("3. IoT Security Recommendations")
    print("4. Save Results to CSV and HTML")
    print("5. Exit")


def main():
    print("Welcome to the IoT Device Scanner with Vulnerability and Traffic Analysis!")
    network = input("Enter the network range (e.g., 10.0.0.0/24): ")

    devices = scan_network(network)
    num_devices = len(devices)
    print(f"\nNumber of IoT Devices Detected: {num_devices}")
    print("=" * 50)

    vulnerabilities = []
    traffic_data = {}
    recommendations = []

    for device in devices:
        open_ports = scan_ports(device['ip'])
        device_details = get_device_details(device['ip'])

        print("\nDevice Information:")
        print("=" * 30)
        print(f"  IP Address       : {device_details['ip']}")
        print(f"  MAC Address      : {device_details['mac']}")
        print(f"  Manufacturer     : {device_details['manufacturer']}")
        print(f"  Open Ports       : {', '.join(map(str, open_ports)) if open_ports else 'None'}")
        print("=" * 30)

    while True:
        display_menu()
        choice = input("Enter your choice (1-5): ")

        if choice == '1':
            target_ip = input("Enter the target IP address: ")

            # Validate the input
            if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target_ip):
                print("Invalid IP address format. Please enter a valid IPv4 address.")
                exit(1)

            # Run all scans
            print("=" * 30)

            print("\nStarting scans...")
            vulnerabilities = []  
            other_findings = [] 
            
            try:
                vulnerabilities.extend(scan_vulnerabilities(target_ip)) 
                other_findings.append(analyze_http_headers(target_ip))  
                other_findings.append(directory_enumeration(target_ip))  
                other_findings.append(test_sql_injection(target_ip))    
                other_findings.append(test_xss(target_ip))            
                other_findings.extend(scan_services_for_issues(target_ip))         
            except Exception as e:
                print(f"An error occurred during scanning: {e}")
                exit(1)

            print("=" * 30)
            print("\nGenerating PDF report...")




        elif choice == '2':
            ip = input("Enter the IP address to analyze traffic: ")
            traffic_data[ip] = analyze_traffic(ip)
            print(f"\nTraffic Data for {ip}:")
            print("=" * 30)
            for traffic in traffic_data[ip]:
                print(f"  {traffic}")

        elif choice == '3':
            print("\nIoT Security Recommendations:")
            print("=" * 50)
            ip = input("Enter the IP address to generate recommendations for it: ")
            open_ports = scan_ports(ip)
            vulnerabilities = scan_vulnerabilities(ip)
            recommendations = generate_recommendations(vulnerabilities, open_ports)
            save_recommendations_to_file(recommendations)
            print(f"\nRecommendations for {ip} saved to recommendations.txt.")

        elif choice == '4':
            # Save to CSV and HTML
            save_to_csv(devices, traffic_data)
            # Save to HTML, which now includes vulnerabilities from scan_results.pdf
            save_to_html(devices, vulnerabilities, traffic_data, recommendations)

            print("Results saved to devices.csv, devices.html, combined_report.pdf, and recommendations.txt.")

        elif choice == '5':
            print("Exiting the program.")
            break


if __name__ == "__main__":
    main()

