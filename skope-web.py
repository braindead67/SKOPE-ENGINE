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
import io

# Global Configuration
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "RPC", 139: "NetBIOS",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Proxy", 8443: "HTTPS-Proxy"
}

# --- PDF GENERATION ENGINE ---
class SkopePDFReport(FPDF):
    def header(self):
        self.set_fill_color(15, 23, 42) # #0f172a Dark Blue
        self.rect(0, 0, 210, 30, 'F')
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(56, 189, 248) # #38bdf8 Light Blue
        self.text(10, 15, "SKOPE // TARGET INTELLIGENCE REPORT")
        self.set_font("Helvetica", "I", 9)
        self.set_text_color(148, 163, 184)
        self.text(10, 22, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.ln(25)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(148, 163, 184)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}} | Confidential Target Footprint Payload", align="C")

    def section_heading(self, title):
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(244, 63, 94) # Rose Red Accent
        self.cell(0, 8, title, ln=True)
        self.set_draw_color(51, 65, 85)
        self.line(self.get_x(), self.get_y(), self.get_x() + 190, self.get_y())
        self.ln(4)

def generate_pdf(data):
    pdf = SkopePDFReport()
    pdf.alias_nb_pages()
    pdf.add_page()
    
    # Target Info Summary Banner
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(15, 23, 42)
    pdf.set_fill_color(56, 189, 248)
    pdf.cell(0, 8, f" Target Footprint Analysis: {data['target']} ", ln=True, fill=True)
    pdf.ln(4)

    # 1. Infrastructure & Geolocation
    pdf.section_heading("1. Infrastructure & Geolocation")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(50, 50, 50)
    pdf.cell(40, 6, "Primary IP:", border=1)
    pdf.cell(150, 6, str(data['network'].get('IP', 'N/A')), border=1, ln=True)
    pdf.cell(40, 6, "ISP/Owner:", border=1)
    pdf.cell(150, 6, str(data['network'].get('ISP/Owner', 'N/A')), border=1, ln=True)
    pdf.cell(40, 6, "Location:", border=1)
    pdf.cell(150, 6, f"{data['location'].get('City', 'N/A')}, {data['location'].get('Country', 'N/A')}", border=1, ln=True)
    pdf.ln(6)

    # 2. Web Technology & OSINT Scraping
    pdf.section_heading("2. Web Technology & OSINT Contact Data")
    pdf.cell(40, 6, "Server Banner:", border=1)
    pdf.cell(150, 6, str(data['webserver'].get('Server Banner', 'N/A')), border=1, ln=True)
    pdf.cell(40, 6, "Inferred OS:", border=1)
    pdf.cell(150, 6, str(data['webserver'].get('Inferred Operating System', 'N/A')), border=1, ln=True)
    
    emails_str = ", ".join(data['contacts']['emails']) if data['contacts']['emails'] else "None Discovered"
    pdf.cell(40, 6, "Scraped Emails:", border=1)
    pdf.cell(150, 6, emails_str, border=1, ln=True)
    pdf.ln(6)

    # 3. Exposed Administrative Infrastructure
    pdf.section_heading("3. Exposed Administrative Ports & Services")
    if data['ports']:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(30, 6, "Port", border=1, align="C")
        pdf.cell(160, 6, "Service / Grabbed Application Banner Info", border=1, ln=True)
        pdf.set_font("Helvetica", "", 9)
        for p in data['ports']:
            pdf.cell(30, 6, str(p['port']), border=1, align="C")
            pdf.cell(160, 6, str(p['service']), border=1, ln=True)
    else:
        pdf.cell(0, 6, "No common administrative services exposed directly on root IP.", ln=True)
    pdf.ln(6)

    # 4. Active Subdomains Found
    pdf.section_heading(f"4. Map of Active Subdomains Discovered ({len(data['subdomains'])})")
    if data['subdomains']:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(110, 6, "Subdomain Asset String", border=1)
        pdf.cell(80, 6, "Resolved IP Mapping Address", border=1, ln=True)
        pdf.set_font("Helvetica", "", 9)
        for sub in data['subdomains']:
            # Handle wrapping gracefully if subdomain lengths overflow the table limits
            pdf.cell(110, 6, str(sub['subdomain']), border=1)
            pdf.cell(80, 6, str(sub['ip']), border=1, ln=True)
    else:
        pdf.cell(0, 6, "Subdomain tracking matrices returned empty records.", ln=True)

    # Output back to Streamlit as a raw memory stream bytes asset
    return pdf.output()

# --- RECON MODULE LOGIC ---
def run_recon_engine(domain):
    data = {
        "target": domain,
        "subdomains": [],
        "webserver": {},
        "network": {},
        "ports": [],
        "location": {},
        "contacts": {"emails": [], "phones": []}
    }
    
    # Deep Subdomain Tracking Modules
    raw_subs = set()
    try:
        res = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=6)
        if res.status_code == 200:
            for item in res.json():
                p = item['name_value'].lower().replace("*.", "").strip()
                if domain in p: raw_subs.add(p)
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
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
            results = ex.map(check_sub, sorted(list(raw_subs)))
            for r in results:
                if r: resolved.append(r)
        data["subdomains"] = resolved

    # Core Infrastructure Resolution
    try:
        ip = socket.gethostbyname(domain)
        data["network"]["IP"] = ip
        
        # ARIN Netblock lookup
        res = requests.get(f"https://rdap.arin.net/registry/ip/{ip}", timeout=4)
        data["network"]["ISP/Owner"] = res.json().get('name', 'Cloud Provider') if res.status_code == 200 else "Cloud Provider"
        
        # Geolocation Lookups
        loc = requests.get(f"http://ip-api.com/json/{ip}", timeout=4).json()
        if loc.get('status') == 'success':
            data["location"] = {"Country": loc.get('country'), "City": loc.get('city')}
            
        # Quick Port Mapping & Banner Grabbing
        open_p = []
        def cp(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1.5)
                    if s.connect_ex((ip, port)) == 0:
                        banner = ""
                        if port in [80, 8080]:
                            s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + domain.encode() + b"\r\n\r\n")
                            ready = s.recv(512).decode('utf-8', errors='ignore')
                            match = re.search(r'Server:\s*(.*)', ready, re.IGNORECASE)
                            if match: banner = match.group(1).strip()
                        return {"port": port, "service": f"{COMMON_PORTS[port]} [{banner}]" if banner else COMMON_PORTS[port]}
            except Exception: pass
            return None
            
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
            ports_res = ex.map(cp, COMMON_PORTS.keys())
            for pr in ports_res:
                if pr: open_p.append(pr)
        data["ports"] = open_p
    except Exception: pass

    # OSINT Contact Scraper
    try:
        res = requests.get(f"https://{domain}", headers={"User-Agent": "Mozilla/5.0"}, timeout=5, allow_redirects=True)
        data["webserver"]["Server Banner"] = res.headers.get('Server', 'Hidden')
        data["webserver"]["Inferred Operating System"] = "Likely Linux" if "linux" in res.headers.get('Server', '').lower() else "Unknown"
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}', res.text)
        data["contacts"]["emails"] = list(set([e for e in emails if not e.endswith(('.png', '.jpg'))]))[:5]
    except Exception: pass

    return data

# --- STREAMLIT WEB INTERFACE ---
st.set_page_config(page_title="SKOPE Web Engine", page_icon="🌐", layout="wide")

# Modern Styling Custom Injector
st.markdown("""
    <style>
    .main { background-color: #0f172a; color: #e2e8f0; }
    h1 { color: #38bdf8 !important; font-family: 'Courier New', monospace; }
    .stButton>button { background-color: #38bdf8 !important; color: #0f172a !important; font-weight: bold; border-radius: 6px; }
    </style>
""", unsafe_allow_html=True)

st.title("SKOPE // WEB TARGET FOOTPRINTING ENGINE")
st.caption("Target Asset Intelligence Scanner — Dynamic PDF Compilation Pipeline")

target_input = st.text_input("Enter Target Domain Config (e.g., tesla.com):", placeholder="example.com")

if st.button("LAUNCH RECON ENGINE"):
    if not target_input:
        st.error("Please provide a valid asset configuration target.")
    else:
        clean_target = re.sub(r'(https?://)?(www\.)?', '', target_input).split('/')[0].strip()
        
        with st.spinner(f"Engaging footprinting modules against {clean_target}..."):
            # Execute Core Discovery Mechanics
            scan_results = run_recon_engine(clean_target)
            
            # Display Real-time Dashboard Preview to User
            st.success("Target analysis processing sequence successfully concluded.")
            
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("Infrastructure Matrix")
                st.write(f"**Target IP:** {scan_results['network'].get('IP', 'N/A')}")
                st.write(f"**Netblock Provider:** {scan_results['network'].get('ISP/Owner', 'N/A')}")
                st.write(f"**Location:** {scan_results['location'].get('City', 'N/A')}, {scan_results['location'].get('Country', 'N/A')}")
                st.write(f"**Exposed Web Software:** {scan_results['webserver'].get('Server Banner', 'N/A')}")

            with col2:
                st.subheader(f"Active Subdomain Discovery ({len(scan_results['subdomains'])})")
                if scan_results['subdomains']:
                    st.dataframe(scan_results['subdomains'], use_container_width=True, height=200)
                else:
                    st.info("No passive subdomains resolved live.")

            # Compile PDF payload instantly in RAM buffer cache layout
            pdf_bytes = generate_pdf(scan_results)
            
            st.markdown("---")
            st.subheader("📥 Download Consolidated Intelligence Payload")
            
            # Streamlit download anchor logic handles the payload transfer natively via user's browser
            st.download_button(
                label="DOWNLOAD CONSOLIDATED REPORT (PDF)",
                data=bytes(pdf_bytes),
                file_name=f"skope_{clean_target}_intelligence.pdf",
                mime="application/pdf"
            )