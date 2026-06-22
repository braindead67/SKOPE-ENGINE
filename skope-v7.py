#!/usr/bin/env python3
import socket
import whois
import dns.resolver
import requests
import json
import re
import csv
import concurrent.futures
import threading
import os
import webbrowser
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

# Global Data Model
recon_data = {
    "target": "",
    "timestamp": "",
    "whois": {},
    "dns": {},
    "subdomains": [],
    "webserver": {},
    "network": {},
    "ports": [],
    "location": {},
    "contacts": {"emails": [], "phones": [], "faxes": []}
}

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "RPC", 139: "NetBIOS",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Proxy", 8443: "HTTPS-Proxy"
}

class SkopeGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SKOPE v7.0 - Target Intelligence Engine")
        self.root.geometry("950x720")
        self.root.configure(bg="#0f172a")
        
        # Base font scale factor tracker
        self.current_font_size = 11

        # Apply modern dark styling configurations
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure(".", background="#0f172a", foreground="#e2e8f0")
        self.style.configure("TProgressbar", thickness=15, troughcolor="#1e293b", background="#38bdf8")
        
        self.style.configure("Header.TFrame", background="#1e293b")
        self.style.configure("Control.TFrame", background="#0f172a")
        self.style.configure("Footer.TFrame", background="#1e293b")

        self.build_ui()
        self.apply_font_scale()
        
    def build_ui(self):
        # Header Panel
        self.header_frame = ttk.Frame(self.root, style="Header.TFrame", padding=10)
        self.header_frame.pack(fill="x", side="top")
        
        self.title_label = tk.Label(self.header_frame, text="SKOPE // TARGET FOOTPRINTING ENGINE", bg="#1e293b", fg="#38bdf8", font=("Courier", 18, "bold"))
        self.title_label.grid(row=0, column=0, sticky="w")
        
        self.author_label = tk.Label(self.header_frame, text="Authored by Raghu67", bg="#1e293b", fg="#94a3b8", font=("Segoe UI", 9, "italic"))
        self.author_label.grid(row=1, column=0, sticky="w")

        # Font Sizing / Zoom Controller Layout
        zoom_frame = tk.Frame(self.header_frame, bg="#1e293b")
        zoom_frame.grid(row=0, column=1, rowspan=2, sticky="e", padx=20)
        
        zoom_lbl = tk.Label(zoom_frame, text="FONT SIZE ZOOM:", bg="#1e293b", fg="#e2e8f0", font=("Segoe UI", 8, "bold"))
        zoom_lbl.pack(side="left", padx=5)
        
        zoom_out_btn = tk.Button(zoom_frame, text=" A- ", bg="#334155", fg="#e2e8f0", font=("Segoe UI", 9, "bold"), bd=0, padx=5, command=self.zoom_out)
        zoom_out_btn.pack(side="left", padx=2)
        
        zoom_in_btn = tk.Button(zoom_frame, text=" A+ ", bg="#38bdf8", fg="#0f172a", font=("Segoe UI", 9, "bold"), bd=0, padx=5, command=self.zoom_in)
        zoom_in_btn.pack(side="left", padx=2)
        
        self.header_frame.columnconfigure(0, weight=1)

        # Control Panel Wrapper
        self.control_frame = ttk.Frame(self.root, style="Control.TFrame", padding=15)
        self.control_frame.pack(fill="x")

        self.lbl_target = ttk.Label(self.control_frame, text="Target Domain:")
        self.lbl_target.grid(row=0, column=0, sticky="w", padx=5, pady=5)
        
        # Text input configuration with contrasting dark font against a crisp white field background
        self.domain_entry = tk.Entry(self.control_frame, bg="#ffffff", fg="#0f172a", insertbackground="#0f172a", bd=1, relief="solid")
        self.domain_entry.insert(0, "example.com")
        self.domain_entry.grid(row=0, column=1, sticky="w", padx=5, pady=5)

        self.lbl_key = ttk.Label(self.control_frame, text="BuiltWith Key (Optional):")
        self.lbl_key.grid(row=0, column=2, sticky="w", padx=15, pady=5)
        
        self.key_entry = tk.Entry(self.control_frame, bg="#fef08a", fg="#0f172a", insertbackground="#0f172a", bd=1, relief="solid", show="*")
        self.key_entry.grid(row=0, column=3, sticky="w", padx=5, pady=5)

        self.scan_btn = tk.Button(self.control_frame, text="LAUNCH RECON", bg="#38bdf8", fg="#0f172a", activebackground="#0ea5e9", bd=0, command=self.start_scan_thread)
        self.scan_btn.grid(row=0, column=4, padx=20, pady=5)

        # Progress Indicator Frame
        self.progress = ttk.Progressbar(self.root, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", padx=15, pady=5)

        # Scrolling Monitor Output View
        self.terminal = scrolledtext.ScrolledText(self.root, bg="#020617", fg="#10b981", insertbackground="white", font=("Courier", 11), bd=0, highlightthickness=1, highlightbackground="#334155")
        self.terminal.pack(fill="both", expand=True, padx=15, pady=10)
        self.log("[+] System initialized. Ready to footprint target infrastructure.\n")

        # Action Button Footer Dock Frame
        self.footer_frame = ttk.Frame(self.root, style="Footer.TFrame", padding=10)
        self.footer_frame.pack(fill="x", side="bottom")
        self.footer_frame.pack_forget() # Kept hidden dynamically until a dataset exists in memory

        self.view_html_btn = tk.Button(self.footer_frame, text="Open HTML Dashboard", bg="#1e293b", fg="#38bdf8", activebackground="#334155", bd=1, relief="solid", command=self.open_html)
        self.view_html_btn.pack(side="left", padx=10)

        self.open_csv_btn = tk.Button(self.footer_frame, text="Open Subdomains CSV", bg="#1e293b", fg="#38bdf8", activebackground="#334155", bd=1, relief="solid", command=self.open_csv)
        self.open_csv_btn.pack(side="left", padx=10)

    def apply_font_scale(self):
        base_sz = self.current_font_size
        self.style.configure("TLabel", font=("Segoe UI", base_sz, "bold"))
        self.title_label.configure(font=("Courier", int(base_sz * 1.6), "bold"))
        self.author_label.configure(font=("Segoe UI", int(base_sz * 0.8), "italic"))
        self.lbl_target.configure(font=("Segoe UI", base_sz, "bold"))
        self.lbl_key.configure(font=("Segoe UI", base_sz, "bold"))
        self.domain_entry.configure(font=("Segoe UI", base_sz))
        self.key_entry.configure(font=("Segoe UI", base_sz))
        self.scan_btn.configure(font=("Segoe UI", base_sz, "bold"))
        self.terminal.configure(font=("Courier", base_sz))
        self.view_html_btn.configure(font=("Segoe UI", base_sz, "bold"))
        self.open_csv_btn.configure(font=("Segoe UI", base_sz, "bold"))
        
    def zoom_in(self):
        if self.current_font_size < 28:
            self.current_font_size += 2
            self.apply_font_scale()

    def zoom_out(self):
        if self.current_font_size > 8:
            self.current_font_size -= 2
            self.apply_font_scale()
        
    def log(self, text):
        self.terminal.insert(tk.END, text + "\n")
        self.terminal.see(tk.END)

    def update_progress(self, val):
        self.progress['value'] = val
        self.root.update_idletasks()

    def start_scan_thread(self):
        target = self.domain_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please provide a valid target domain configuration.")
            return
        
        target = re.sub(r'(https?://)?(www\.)?', '', target).split('/')[0]
        bw_key = self.key_entry.get().strip() or None

        self.scan_btn.config(state="disabled")
        self.footer_frame.pack_forget()
        self.terminal.delete("1.0", tk.END)
        self.progress['value'] = 0
        
        threading.Thread(target=self.run_engine, args=(target, bw_key), daemon=True).start()

    def run_engine(self, domain, bw_key):
        global recon_data
        
        # Flush old state metrics cleanly to guarantee data accuracy between sequential runs
        recon_data = {
            "target": domain,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "whois": {},
            "dns": {},
            "subdomains": [],
            "webserver": {},
            "network": {},
            "ports": [],
            "location": {},
            "contacts": {"emails": [], "phones": [], "faxes": []}
        }

        # Dynamic output filenames matching requested convention profiles
        self.html_out = f"skope_{domain}.html"
        self.csv_out = f"skope_{domain}_subdomains.csv"

        # Step 1: WHOIS Registry Mapping
        self.log(f"[*] Task 1/6: Querying Registry WHOIS for {domain}...")
        try:
            w = whois.whois(domain)
            recon_data["whois"] = {
                "Registrar": w.registrar, "Creation Date": str(w.creation_date),
                "Expiration Date": str(w.expiration_date),
                "Name Servers": ", ".join(w.name_servers) if isinstance(w.name_servers, list) else w.name_servers,
                "Emails": ", ".join(w.emails) if isinstance(w.emails, list) else w.emails
            }
            self.log("[+] WHOIS records scraped over Port 43.")
        except Exception:
            self.log("[!] Port 43 blocked. Testing web RDAP backup pipelines...")
            try:
                res = requests.get(f"https://rdap.org/domain/{domain}", timeout=5).json()
                recon_data["whois"] = {
                    "Registrar": "Parsed via RDAP", "Creation Date": "N/A", "Expiration Date": "N/A",
                    "Name Servers": ", ".join([ns.get("ldhName", "") for ns in res.get("nameservers", [])]),
                    "Emails": "Protected/Masked"
                }
                self.log("[+] Fallback WHOIS data mapped successfully.")
            except Exception:
                recon_data["whois"] = {"Error": "All registration record requests timed out."}
        self.update_progress(15)

        # Step 2: Zone Records Check
        self.log(f"\n[*] Task 2/6: Resolving core DNS zone configurations...")
        for r_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
            try:
                answers = dns.resolver.resolve(domain, r_type)
                recon_data["dns"][r_type] = [str(rdata) for rdata in answers]
                self.log(f"  - Discovered {len(recon_data['dns'][r_type])} native {r_type} structural mapping rows.")
            except Exception: 
                continue
        self.update_progress(30)

        # Step 3: Deep Subdomain Aggregation
        self.log(f"\n[*] Task 3/6: Spawning multi-source passive subdomain harvest modules...")
        raw_subs = set()
        try:
            res = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=6)
            if res.status_code == 200:
                for item in res.json():
                    p = item['name_value'].lower().replace("*.", "").strip()
                    if domain in p: raw_subs.add(p)
        except Exception: pass
        try:
            res = requests.get(f"https://jldc.me/anubis/subdomains/{domain}", timeout=5)
            if res.status_code == 200:
                for s in res.json(): 
                    if domain in s: raw_subs.add(s.strip().lower())
        except Exception: pass
        try:
            backup_res = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=5)
            if backup_res.status_code == 200 and "error" not in backup_res.text:
                for line in backup_res.text.split("\n"):
                    if "," in line:
                        sub = line.split(",")[0].lower().strip()
                        if domain in sub: raw_subs.add(sub)
        except Exception: pass

        if raw_subs:
            self.log(f"[+] Total passive structures harvested: {len(raw_subs)} unique references.")
            self.log("[*] Engaging thread matrix to verify live operational status...")
            resolved = []
            def check_sub(sub):
                try:
                    return {"subdomain": sub, "ip": socket.gethostbyname(sub)}
                except socket.gaierror: return None
            with concurrent.futures.ThreadPoolExecutor(max_workers=35) as executor:
                results = executor.map(check_sub, sorted(list(raw_subs)))
                for r in results:
                    if r: resolved.append(r)
            recon_data["subdomains"] = resolved
            self.log(f"[+] Operational asset discovery mapped: {len(resolved)} hosts responded active.")
        else:
            self.log("[-] Subdomain analysis modules returned clean matrices.")
        self.update_progress(60)

        # Step 4: Web Application Footprint & Scraping
        self.log(f"\n[*] Task 4/6: Analysing HTTP structural elements & scraping contact layers...")
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
            valid_e = [e for e in set(emails) if not e.endswith(('.png', '.jpg', '.w3.org'))]
            
            phones = set()
            num_pattern = r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
            for line in html.split('\n'):
                if any(k in line.lower() for k in ["phone", "tel:", "contact"]):
                    for m in re.findall(num_pattern, line): phones.add(m)
            
            recon_data["contacts"] = {"emails": list(valid_e)[:5], "phones": list(phones)[:5], "faxes": []}
            self.log(f"[+] Harvested {len(valid_e)} active emails and {len(phones)} telephone markers via OSINT regex.")
        except Exception: pass
        recon_data["webserver"] = {"Server Banner": sb, "Tech Stack Frameworks": ", ".join(frameworks) if frameworks else "Hidden", "Inferred Operating System": os_guess}
        self.update_progress(75)

        # Step 5: Primary Infrastructure Review (FIXED: Integrated Socket Banner Grabbing here)
        self.log(f"\n[*] Task 5/6: Resolving primary data core mapping and scanning services...")
        try:
            ip = socket.gethostbyname(domain)
            recon_data["network"]["IP"] = ip
            
            ip_url = f"https://rdap.arin.net/registry/ip/{ip}"
            res = requests.get(ip_url, timeout=4)
            if res.status_code == 200:
                recon_data["network"]["ISP/Owner"] = res.json().get('name', 'Unknown')
            else:
                recon_data["network"]["ISP/Owner"] = "Cloud/Hosting Provider"

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
                                    return port, f"{COMMON_PORTS[port]} (SSL/TLS Service)"
                                
                                ready_data = s.recv(1024).decode('utf-8', errors='ignore').strip()
                                if ready_data:
                                    server_match = re.search(r'Server:\s*(.*)', ready_data, re.IGNORECASE)
                                    if server_match:
                                        banner = server_match.group(1).strip()
                                    else:
                                        banner = ready_data.split('\n')[0].strip()
                            except Exception: pass
                            
                            service_desc = f"{COMMON_PORTS[port]} [{banner}]" if banner else COMMON_PORTS[port]
                            return port, service_desc
                except Exception: pass
                return None

            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
                res = ex.map(cp, COMMON_PORTS.keys())
                for r in res:
                    if r:
                        open_p.append({"port": r[0], "service": r[1], "status": "Open"})
                        self.log(f"  [!] Found Active Service: Port {r[0]} - {r[1]} is exposed open.")
            recon_data["ports"] = open_p
        except Exception: ip = None
        self.update_progress(90)

        # Step 6: Location Lookups
        self.log(f"\n[*] Task 6/6: Tracking physical server geolocation coordinate indexes...")
        if ip:
            try:
                res = requests.get(f"http://ip-api.com/json/{ip}", timeout=4).json()
                if res.get('status') == 'success':
                    recon_data["location"] = {"Country": res.get('country'), "City": res.get('city'), "Coordinates": f"{res.get('lat')}, {res.get('lon')}"}
            except Exception:
                try:
                    res = requests.get(f"https://freeipapi.com/api/json/{ip}", timeout=4).json()
                    recon_data["location"] = {"Country": res.get('countryName'), "City": res.get('cityName'), "Coordinates": f"{res.get('latitude')}, {res.get('longitude')}"}
                except Exception:
                    recon_data["location"] = {"Country": "Unknown", "City": "Throttled", "Coordinates": "N/A"}
        self.update_progress(95)

        # File Compilation Outputs
        self.log(f"\n[*] Compiling intelligence payload output formats...")
        self.export_payloads()
        self.update_progress(100)
        
        self.log("\n[++] SKOPE processing sequence successfully concluded. View outputs below.")
        self.scan_btn.config(state="normal")
        self.footer_frame.pack(fill="x", side="bottom")

    def export_payloads(self):
        with open(self.csv_out, mode='w', newline='') as f:
            w = csv.writer(f)
            w.writerow(["Subdomain", "IP Address"])
            for entry in recon_data["subdomains"]:
                w.writerow([entry["subdomain"], entry["ip"]])
                
        emails_html = "".join([f"<li>{e}</li>" for e in recon_data["contacts"]["emails"]]) if recon_data["contacts"]["emails"] else "<li>No exposed business emails found</li>"
        phones_html = "".join([f"<li>{p}</li>" for p in recon_data["contacts"]["phones"]]) if recon_data["contacts"]["phones"] else "<li>No standard telephone tags visible</li>"
        
        dns_rows_html = ""
        if recon_data["dns"]:
            for rtype, records in recon_data["dns"].items():
                rec_list = "".join([f"<li>{r}</li>" for r in records])
                dns_rows_html += f"<tr><th>{rtype} Zone Block</th><td><ul>{rec_list}</ul></td></tr>"
        else:
            dns_rows_html = "<tr><td colspan='2'>No active records cataloged.</td></tr>"

        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8"><title>SKOPE Target Intelligence - {recon_data['target']}</title>
            <style>
                body {{ font-family: 'Segoe UI', sans-serif; background-color: #0f172a; color: #e2e8f0; margin: 0; padding: 20px; }}
                .container {{ max-width: 1100px; margin: auto; }}
                h1 {{ color: #38bdf8; border-bottom: 2px solid #1e293b; padding-bottom: 10px; }}
                .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(450px, 1fr)); gap: 20px; }}
                .card {{ background-color: #1e293b; border-radius: 8px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                h3 {{ color: #f43f5e; margin-top: 0; border-bottom: 1px solid #334155; padding-bottom: 5px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
                th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #334155; }}
                th {{ color: #38bdf8; font-size: 0.9em; }}
                ul {{ padding-left: 20px; margin: 5px 0; }}
                li {{ font-family: monospace; color: #cbd5e1; font-size: 0.9em; }}
                .badge {{ background-color: #10b981; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>SKOPE Intelligence Dashboard</h1>
                <p><strong>Target:</strong> {recon_data['target']} | <strong>Executed:</strong> {recon_data['timestamp']}</p>
                <div class="grid">
                    <div class="card">
                        <h3>Infrastructure & Geolocation</h3>
                        <table>
                            <tr><th>IP Address</th><td>{recon_data['network'].get('IP', 'N/A')}</td></tr>
                            <tr><th>ISP Ownership</th><td>{recon_data['network'].get('ISP/Owner', 'N/A')}</td></tr>
                            <tr><th>Location</th><td>{recon_data['location'].get('City', 'N/A')}, {recon_data['location'].get('Country', 'N/A')} ({recon_data['location'].get('Coordinates', 'N/A')})</td></tr>
                        </table>
                    </div>
                    <div class="card">
                        <h3>Scraped Contacts (OSINT)</h3>
                        <table>
                            <tr><th>Emails</th><td><ul>{emails_html}</ul></td></tr>
                            <tr><th>Phones</th><td><ul>{phones_html}</ul></td></tr>
                        </table>
                    </div>
                    <div class="card">
                        <h3>Web Technology</h3>
                        <table>
                            <tr><th>Server Banner</th><td>{recon_data['webserver'].get('Server Banner', 'N/A')}</td></tr>
                            <tr><th>Frameworks</th><td>{recon_data['webserver'].get('Tech Stack Frameworks', 'N/A')}</td></tr>
                            <tr><th>Inferred OS</th><td>{recon_data['webserver'].get('Inferred Operating System', 'N/A')}</td></tr>
                        </table>
                    </div>
                    <div class="card">
                        <h3>Exposed Ports & Services</h3>
                        {"<table><tr><th>Port</th><th>Service Banner Info</th></tr>" if recon_data['ports'] else "<p>No common administrative infrastructure exposed open.</p>"}
                        {"".join([f"<tr><td><strong>{p['port']}</strong></td><td>{p['service']} <span class='badge'>Open</span></td></tr>" for p in recon_data['ports']]) if recon_data['ports'] else ""}
                        {"</table>" if recon_data['ports'] else ""}
                    </div>
                    <div class="card" style="grid-column: span 2;">
                        <h3>DNS Zone Records</h3>
                        <table>
                            {dns_rows_html}
                        </table>
                    </div>
                    <div class="card" style="grid-column: span 2;">
                        <h3>Active Subdomains Found ({len(recon_data['subdomains'])})</h3>
                        <div style="max-height: 300px; overflow-y: auto; background: #0f172a; padding: 15px; border-radius: 6px; border: 1px solid #334155;">
                            <ul style="display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 10px; list-style-type: none; padding-left: 0;">
                                {"".join([f"<li style='background:#1e293b; padding:6px; border-radius:4px; border-left:3px solid #38bdf8;'><strong>{entry['subdomain']}</strong><br><span style='color:#94a3b8; font-size:0.9em;'>{entry['ip']}</span></li>" for entry in recon_data['subdomains']]) if recon_data['subdomains'] else "<li>No subdomains mapped</li>"}
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        with open(self.html_out, 'w') as f: f.write(html_content)

    def open_html(self):
        if os.path.exists(self.html_out):
            webbrowser.open(f"file://{os.path.abspath(self.html_out)}")

    def open_csv(self):
        if os.path.exists(self.csv_out):
            os.system(f"xdg-open {self.csv_out}" if os.name != 'nt' else f"start {self.csv_out}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SkopeGUI(root)
    root.mainloop()