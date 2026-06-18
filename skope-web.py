#!/usr/bin/env python3
import streamlit as st
import socket
import whois
import dns.resolver
import requests
import re
import concurrent.futures
from datetime import datetime
from fpdf import FPDF

# Global Configuration Constants
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "RPC", 139: "NetBIOS",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Proxy", 8443: "HTTPS-Proxy"
}

# --- ENHANCED PDF GENERATION ENGINE ---
class SkopePDFReport(FPDF):
    def header(self):
        self.set_fill_color(15, 23, 42) # #0f172a Dark Palette
        self.rect(0, 0, 210, 30, 'F')
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(56, 189, 248) # #38bdf8 Neon Blue Accent
        self.text(10, 15, "SKOPE // TARGET INTELLIGENCE REPORT")
        self.set_font("Helvetica", "I", 9)
        self.set_text_color(148, 163, 184)
        self.text(10, 22, f"Report Execution Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.ln(25)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(148, 163, 184)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}} | Confidential Target Infrastructure Asset Log", align="C")

    def section_heading(self, title):
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(244, 63, 94) # Rose Accent Red
        self.cell(0, 8, title, ln=True)
        self.set_draw_color(51, 65, 85)
        self.line(self.get_x(), self.get_y(), self.get_x() + 190, self.get_y())
        self.ln(4)

def generate_pdf(data):
    pdf = SkopePDFReport()
    pdf.alias_nb_pages()
    pdf.add_page()
    
    # Summary Header
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(15, 23, 42)
    pdf.set_fill_color(56, 189, 248)
    pdf.cell(0, 8, f" Target Footprint Scope: {data['target']} ", ln=True, fill=True)
    pdf.ln(4)

    # Section 1: Infrastructure & Geolocation
    pdf.section_heading("1. Core Network Infrastructure & Geolocation")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(40, 40, 40)
    pdf.cell(45, 6, "Target Resolving IP:", border=1)
    pdf.cell(145, 6, str(data['network'].get('IP', 'N/A')), border=1, ln=True)
    pdf.cell(45, 6, "Netblock ASN Provider:", border=1)
    pdf.cell(145, 6, str(data['network'].get('ISP/Owner', 'N/A')), border=1, ln=True)
    pdf.cell(45, 6, "Physical Host Location:", border=1)
    pdf.cell(145, 6, f"{data['location'].get('City', 'N/A')}, {data['location'].get('Country', 'N/A')} ({data['location'].get('Coordinates', 'N/A')})", border=1, ln=True)
    pdf.ln(5)

    # Section 2: Domain Registration Metadata (WHOIS)
    pdf.section_heading("2. Domain Registration Metadata (WHOIS)")
    pdf.set_font("Helvetica", "", 9)
    for k, v in data['whois'].items():
        pdf.cell(45, 6, str(k), border=1)
        pdf.cell(145, 6, str(v), border=1, ln=True)
    pdf.ln(5)

    # Section 3: DNS Zone Configurations
    pdf.section_heading("3. Active DNS Zone Records Mapped")
    if data['dns']:
        for rtype, records in data['dns'].items():
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(190, 6, f" {rtype} Records Block", border=1, ln=True, fill=True)
            pdf.set_font("Helvetica", "", 9)
            for record in records:
                pdf.cell(190, 6, f"  - {record}", border=1, ln=True)
    else:
        pdf.cell(0, 6, "No responsive DNS zone configurations cataloged.", ln=True)
    pdf.ln(5)

    # Section 4: Web Application Frameworks & Contacts
    pdf.section_heading("4. Application Stack Fingerprint & Scraped Contacts")
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(45, 6, "Server Software Banner:", border=1)
    pdf.cell(145, 6, str(data['webserver'].get('Server Banner', 'N/A')), border=1, ln=True)
    pdf.cell(45, 6, "Inferred Server OS:", border=1)
    pdf.cell(145, 6, str(data['webserver'].get('Inferred Operating System', 'N/A')), border=1, ln=True)
    pdf.cell(45, 6, "Tech Stack Frameworks:", border=1)
    pdf.cell(145, 6, str(data['webserver'].get('Tech Stack Frameworks', 'N/A')), border=1, ln=True)
    
    emails_str = ", ".join(data['contacts']['emails']) if data['contacts']['emails'] else "None Visible"
    phones_str = ", ".join(data['contacts']['phones']) if data['contacts']['phones'] else "None Visible"
    pdf.cell(45, 6, "Identified Corporate Emails:", border=1)
    pdf.cell(145, 6, emails_str, border=1, ln=True)
    pdf.cell(45, 6, "Identified Telephone Lines:", border=1)
    pdf.cell(145, 6, phones_str, border=1, ln=True)
    pdf.ln(5)

    # Section 5: Exposed Services
    pdf.section_heading("5. Exposed Infrastructure Administrative Services")
    if data['ports']:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(40, 6, "Exposed Port", border=1, align="C")
        pdf.cell(150, 6, "Service Application Info & Header Banner Grab", border=1, ln=True)
        pdf.set_font("Helvetica", "", 9)
        for p in data['ports']:
            pdf.cell(40, 6, f"Port {p['port']}", border=1, align="C")
            pdf.cell(150, 6, str(p['service']), border=1, ln=True)
    else:
        pdf.cell(0, 6, "No exposed common administrative interfaces found on root IP allocation.", ln=True)
    pdf.ln(5)

    # Section 6: Active Subdomains List
    pdf.section_heading(f"6. Verified Active Subdomain Topologies ({len(data['subdomains'])})")
    if data['subdomains']:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(110, 6, "Subdomain Host String", border=1)
        pdf.cell(80, 6, "Resolved IPv4 Address", border=1, ln=True)
        pdf.set_font("Helvetica", "", 9)
        for sub in data['subdomains']:
            pdf.cell(110, 6, str(sub['subdomain']), border=1)
            pdf.cell(80, 6, str(sub['ip']), border=1, ln=True)
    else:
        pdf.cell(0, 6, "Subdomain structural discovery modules returned empty tables.", ln=True)

    return pdf.output()

# --- HARVEST & ENUMERATION MECHANICS ---
def run_recon_engine(domain, bw_key=None):
    data = {
        "target": domain,
        "whois": {},
        "dns": {},
        "subdomains": [],
        "webserver": {},
        "network": {},
        "ports": [],
        "location": {},
        "contacts": {"emails": [], "phones": []}
    }

    # 1. Full Multi-Pathway WHOIS Parsing
    try:
        w = whois.whois(domain)
        data["whois"] = {
            "Registrar": w.registrar, "Creation Date": str(w.creation_date), "Expiration Date": str(w.expiration_date),
            "Name Servers": ", ".join(w.name_servers) if isinstance(w.name_servers, list) else w.name_servers,
            "Emails": ", ".join(w.emails) if isinstance(w.emails, list) else w.emails
        }
    except Exception:
        try:
            res = requests.get(f"https://rdap.org/domain/{domain}", timeout=5).json()
            data["whois"] = {
                "Registrar": "Parsed via RDAP Fallback", "Creation Date": "Protected Matrix", "Expiration Date": "Protected Matrix",
                "Name Servers": ", ".join([ns.get("ldhName", "") for ns in res.get("nameservers", [])]),
                "Emails": "Masked"
            }
        except Exception:
            data["whois"] = {"Error": "All registration record lookups timed out."}

    # 2. Comprehensive DNS Records Pull
    for r_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
        try:
            answers = dns.resolver.resolve(domain, r_type)
            data["dns"][r_type] = [str(rdata) for rdata in answers]
        except Exception: continue

    # 3. Synchronized Triple Subdomain Streams (Matches skope-final.py)
    raw_subs = set()
    try:
        res = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=6)
        if res.status_code == 200:
            for item in res.json():
                for p in item['name_value'].lower().split("\n"):
                    p = p.replace("*.", "").strip()
                    if domain in p: raw_subs.add(p)
    except Exception: pass
    try:
        res = requests.get(f"https://jldc.me/anubis/subdomains/{domain}", timeout=5)
        if res.status_code == 200:
            for s in res.json():
                if domain in s.strip().lower(): raw_subs.add(s.strip().lower())
    except Exception: pass
    try:
        res = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=5)
        if res.status_code == 200 and "error" not in res.text:
            for line in res.text.split("\n"):
                if "," in line:
                    sub = line.split(",")[0].lower().strip()
                    if domain in sub: raw_subs.add(sub)
    except Exception: pass

    if raw_subs:
        resolved = []
        def check_sub(s):
            try: return {"subdomain": s, "ip": socket.gethostbyname(s)}
            except Exception: return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=35) as ex:
            results = ex.map(check_sub, sorted(list(raw_subs)))
            for r in results:
                if r: resolved.append(r)
        data["subdomains"] = resolved

    # 4. Framework Signatures & Contact Mining
    frameworks = []
    sb, os_guess = "Hidden", "Unknown"
    if bw_key:
        try:
            res = requests.get(f"https://api.builtwith.com/v22/api.json?KEY={bw_key}&LOOKUP={domain}", timeout=5).json()
            for path in res.get("Paths", []):
                for tech in path.get("Technologies", []):
                    if any(c in ["framework", "cms", "javascript"] for c in tech.get("Categories", [])):
                        frameworks.append(tech.get("Name"))
            frameworks = list(set(frameworks))[:6]
        except Exception: pass
    try:
        h = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"}
        res = requests.get(f"https://{domain}", headers=h, timeout=5, allow_redirects=True)
        sb = res.headers.get('Server', 'Hidden')
        html = res.text
        if any(x in sb.lower() for x in ['ubuntu', 'debian', 'linux']): os_guess = "Likely Linux"
        elif 'iis' in sb.lower(): os_guess = "Windows Server"
        
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}', html)
        data["contacts"]["emails"] = list(set([e for e in emails if not e.endswith(('.png', '.jpg', '.w3.org'))]))[:5]
        
        phones = set()
        num_pattern = r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
        for line in html.split('\n'):
            if any(k in line.lower() for k in ["phone", "tel:", "contact"]):
                for m in re.findall(num_pattern, line): phones.add(m)
        data["contacts"]["phones"] = list(phones)[:5]
    except Exception: pass
    data["webserver"] = {"Server Banner": sb, "Tech Stack Frameworks": ", ".join(frameworks) if frameworks else "Hidden", "Inferred Operating System": os_guess}

    # 5. Core Allocation Infrastructure Scan & Active Socket Header Banner Grab
    try:
        ip = socket.gethostbyname(domain)
        data["network"]["IP"] = ip
        
        res = requests.get(f"https://rdap.arin.net/registry/ip/{ip}", timeout=4)
        data["network"]["ISP/Owner"] = res.json().get('name', 'Cloud Provider') if res.status_code == 200 else "Cloud Provider"
        
        open_p = []
        def cp(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2.0)
                    if s.connect_ex((ip, port)) == 0:
                        banner = ""
                        try:
                            if port in [80, 8080]:
                                s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + domain.encode() + b"\r\n\r\n")
                            elif port in [443, 8443]:
                                return {"port": port, "service": f"{COMMON_PORTS[port]} (SSL/TLS Active)"}
                            
                            ready_data = s.recv(1024).decode('utf-8', errors='ignore').strip()
                            if ready_data:
                                match = re.search(r'Server:\s*(.*)', ready_data, re.IGNORECASE)
                                banner = match.group(1).strip() if match else ready_data.split('\n')[0].strip()
                        except Exception: pass
                        return {"port": port, "service": f"{COMMON_PORTS[port]} [{banner}]" if banner else COMMON_PORTS[port]}
            except Exception: pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            ports_res = ex.map(cp, COMMON_PORTS.keys())
            for pr in ports_res:
                if pr: open_p.append(pr)
        data["ports"] = open_p
    except Exception: ip = None

    # 6. Physical Server Location Pipeline with Fallbacks
    if ip:
        try:
            loc = requests.get(f"http://ip-api.com/json/{ip}", timeout=4).json()
            if loc.get('status') == 'success':
                data["location"] = {"Country": loc.get('country'), "City": loc.get('city'), "Coordinates": f"{loc.get('lat')}, {loc.get('lon')}"}
        except Exception:
            try:
                loc = requests.get(f"https://freeipapi.com/api/json/{ip}", timeout=4).json()
                data["location"] = {"Country": loc.get('countryName'), "City": loc.get('cityName'), "Coordinates": f"{loc.get('latitude')}, {loc.get('longitude')}"}
            except Exception:
                data["location"] = {"Country": "Unknown", "City": "Throttled", "Coordinates": "N/A"}

    return data

# --- STREAMLIT USER INTERFACE ---
st.set_page_config(page_title="SKOPE Framework Console", page_icon="🌐", layout="wide")

st.markdown("""
    <style>
    .main { background-color: #0a0d14; color: #f3f4f6; }
    h1, h2, h3 { color: #38bdf8 !important; font-family: 'JetBrains Mono', monospace; }
    .stButton>button { background-color: #10b981 !important; color: #0a0d14 !important; font-weight: bold; border: none; }
    .stDataFrame { background-color: #111622; }
    </style>
""", unsafe_allow_html=True)

st.title("SKOPE // METADATA CONSOLE")
st.caption("Synchronized Target Footprinting Portal — Production Release Engine Pipeline")

target_input = st.text_input("Define Scan Asset Scope Parameters (Target Domain):", placeholder="example.com")
bw_key_input = st.text_input("BuiltWith Integration Key Parameter (Optional):", type="password", placeholder="Leave blank for passive lookup")

if st.button("EXECUTE ANALYSIS PLAYBOOK"):
    if not target_input:
        st.error("Missing valid infrastructure scoping input parameter.")
    else:
        clean_target = re.sub(r'(https?://)?(www\.)?', '', target_input).split('/')[0].strip()
        bw_key = bw_key_input.strip() if bw_key_input.strip() else None

        with st.spinner(f"Mapping host metrics across external registry pipelines for {clean_target}..."):
            scan_results = run_recon_engine(clean_target, bw_key)
            st.success("Target analysis processing sequence successfully concluded.")

            # Tabular Output Preview Blocks
            tab1, tab2, tab3 = st.tabs(["Infrastructure Metadata", "DNS & Registry Layout", "Verified Subdomain Assets"])
            
            with tab1:
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("### Host Information")
                    st.write(f"**Target IPv4 Core:** `{scan_results['network'].get('IP', 'N/A')}`")
                    st.write(f"**Netblock ISP Owner:** {scan_results['network'].get('ISP/Owner', 'N/A')}")
                    st.write(f"**Server Coordinates:** {scan_results['location'].get('City', 'N/A')}, {scan_results['location'].get('Country', 'N/A')}")
                with col2:
                    st.markdown("### Stack Context")
                    st.write(f"**Server Banner:** `{scan_results['webserver'].get('Server Banner', 'N/A')}`")
                    st.write(f"**Inferred Framework Stack:** {scan_results['webserver'].get('Tech Stack Frameworks', 'N/A')}")
                    st.write(f"**Exposed Communications Data:** {', '.join(scan_results['contacts']['emails']) if scan_results['contacts']['emails'] else 'None Open'}")

            with tab2:
                col3, col4 = st.columns(2)
                with col3:
                    st.markdown("### WHOIS Registration Data")
                    st.json(scan_results['whois'])
                with col4:
                    st.markdown("### Exposed Port Banner Grabs")
                    if scan_results['ports']:
                        st.dataframe(scan_results['ports'], use_container_width=True)
                    else:
                        st.info("No exposed management endpoints mapped on common ports.")

            with tab3:
                st.markdown(f"### Live Resolved Subdomains Matrix ({len(scan_results['subdomains'])})")
                if scan_results['subdomains']:
                    st.dataframe(scan_results['subdomains'], use_container_width=True, height=300)
                else:
                    st.info("Passive harvest streams returned blank historical logging metrics.")

            # Compile PDF payload directly from Memory Stream Object
            pdf_bytes = generate_pdf(scan_results)

            st.markdown("---")
            st.subheader("📥 Download Target Footprint Manifest")
            st.download_button(
                label="DOWNLOAD CONSOLIDATED REPORT (PDF)",
                data=bytes(pdf_bytes),
                file_name=f"skope_{clean_target}_payload_report.pdf",
                mime="application/pdf"
            )
