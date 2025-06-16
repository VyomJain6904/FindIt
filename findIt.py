#!/usr/bin/env python3
import argparse
import concurrent.futures
import json
import nmap # Requires python-nmap library and nmap installed
import os
import re
import requests
import socket
import subprocess
import sys
import time
# Disable InsecureRequestWarning warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from colorama import init # For cross-platform terminal colors, though Rich handles most
from rich.console import Console
from rich.table import Table, box
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn, SpinnerColumn

# Initialize colorama (optional if Rich handles all coloring)
init(autoreset=True)

class FindIt:
    def __init__(self, target, threads=10, wordlist=None, port_scan=False, timeout=5,
                 verbose=False, output=None, tech_detect=True, dir_wordlist=None):
        self.target = target
        self.threads = threads
        # Use provided wordlist or default, check existence later
        self.subdomain_wordlist = wordlist if wordlist else "subdomains.txt" # Example default
        self.dir_wordlist = dir_wordlist if dir_wordlist else "directories.txt" # Example default for dirs
        self.port_scan = port_scan
        self.timeout = timeout
        self.verbose = verbose
        self.output = output
        self.tech_detect = tech_detect
        self.subdomains = set()
        self.ip_addresses = set()
        self.open_ports = {} # Stores {ip: [port_info_dict]}
        self.os_info = {} # Stores {ip: os_string}
        self.directories = {} # Stores {base_url: [dir_url_list]}
        self.s3_buckets = set()
        self.gcp_buckets = set()
        self.tftp_servers = set()
        self.technologies = {} # Stores {domain: [tech_info_dict]}
        self.console = Console()
        self.results = {} # Dictionary to hold all results for saving
        self.nm = None # Initialize nmap scanner instance variable


    def banner(self):
        """Display the tool banner"""
        self.console.print(f"""
[bold blue]╔═══════════════════════════════════════════╗[/]
[bold blue]║                                           ║[/]
[bold blue]║  [bold green]findIt[/bold green] - Advanced Domain Scanner         ║[/]
[bold blue]║  Created by Vyom                          ║[/]
[bold blue]║                                           ║[/]
[bold blue]╚═══════════════════════════════════════════╝[/]
        """)

    def resolve_domain(self):
        """Resolve domain to IP address"""
        try:
            self.console.print(f"[yellow][*] Resolving {self.target}...")
            ip = socket.gethostbyname(self.target)
            self.ip_addresses.add(ip)
            self.results['target_ip'] = ip

            table = Table(title=f"Target Resolution: {self.target}", box=box.ROUNDED, show_header=True, header_style="bold magenta")
            table.add_column("Domain", style="cyan")
            table.add_column("IP Address", style="green")
            table.add_row(self.target, ip)
            self.console.print(table)
            return ip
        except socket.gaierror as e:
            self.console.print(f"[red][-] Failed to resolve domain {self.target}: {e}")
            return None
        except Exception as e:
            self.console.print(f"[red][-] An unexpected error occurred during resolution: {e}")
            return None

    def _check_subdomain(self, subdomain):
        """Check if a subdomain exists"""
        try:
            ip = socket.gethostbyname(subdomain)
            return subdomain, ip
        except socket.gaierror:
            return None, None # Subdomain does not resolve
        except Exception as e:
            if self.verbose:
                self.console.print(f"[red][-] Error checking {subdomain}: {e}")
            return None, None # Other error

    def enumerate_subdomains(self):
        """Enumerate subdomains using brute force"""
        self.console.print("\n[yellow][*] Enumerating subdomains...")
        wordlist_path = self.subdomain_wordlist

        try:
            with open(wordlist_path, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
            self.console.print(f"[cyan][+] Using wordlist: {wordlist_path} ({len(words)} words)")
        except FileNotFoundError:
            self.console.print(f"[red][-] Wordlist file not found: {wordlist_path}")
            # Provide a small fallback list
            words = ["www", "mail", "ftp", "localhost", "webmail", "admin", "test",
                     "dev", "api", "staging", "prod", "beta", "app", "ns1", "ns2",
                     "smtp", "vpn", "cdn", "support", "remote", "shop", "blog"]
            self.console.print(f"[yellow][*] Using built-in fallback wordlist ({len(words)} words).")
        except Exception as e:
            self.console.print(f"[red][-] Error reading wordlist {wordlist_path}: {e}")
            return # Cannot proceed without a wordlist

        found_subdomains = {} # subdomain -> ip
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            transient=True, # Removes progress bar on completion
        ) as progress:
            task = progress.add_task("[cyan]Scanning subdomains...", total=len(words))
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_word = {executor.submit(self._check_subdomain, f"{word}.{self.target}"): word for word in words}

                for future in concurrent.futures.as_completed(future_to_word):
                    progress.update(task, advance=1)
                    try:
                        subdomain, ip = future.result()
                        if subdomain and ip:
                            self.subdomains.add(subdomain)
                            self.ip_addresses.add(ip)
                            found_subdomains[subdomain] = ip
                            if self.verbose:
                                self.console.print(f"[green][+] Found: {subdomain} ({ip})")
                    except Exception as e:
                        word = future_to_word[future]
                        if self.verbose:
                            self.console.print(f"[red][-] Error processing result for '{word}.{self.target}': {e}")

        self.results['subdomains'] = found_subdomains
        if found_subdomains:
            table = Table(title=f"Found Subdomains ({len(found_subdomains)})", box=box.ROUNDED, show_header=True, header_style="bold magenta")
            table.add_column("Subdomain", style="cyan")
            table.add_column("IP Address", style="green")
            for subdomain in sorted(found_subdomains.keys()):
                table.add_row(subdomain, found_subdomains[subdomain])
            self.console.print(table)
        else:
            self.console.print("[yellow][-] No subdomains found using the specified wordlist.")

    def scan_ports(self):
        """Scan for open ports and detect OS/services using nmap"""
        if not self.port_scan:
            self.console.print("[yellow][*] Port scanning disabled. Use --port-scan to enable.")
            return

        if not self.ip_addresses:
            self.console.print("[red][-] No IP addresses found to scan.")
            return

        self.console.print("\n[yellow][*] Starting port scan and OS detection (requires nmap)...")
        self.console.print("[cyan][!] Note: SYN scan (-sS) and OS detection (-O) may require root/administrator privileges.")

        if self.nm is None: # Initialize nmap scanner if not already done
             self.nm = nmap.PortScanner()

        ip_list = list(self.ip_addresses)
        ip_string = ' '.join(ip_list)

        try:
             # Adjust arguments as needed. -sV: Version Detection, -O: OS Detection, -T4: Timing template
            scan_args = '-sS -sV -O -T4 --osscan-guess' # Example args, adjust if no root
            self.console.print(f"[cyan][*] Running nmap with arguments: {scan_args} on {ip_string}")
            self.nm.scan(hosts=ip_string, arguments=scan_args)
        except nmap.PortScannerError as e:
            self.console.print(f"[red][-] Nmap error: {e}. Is nmap installed and in PATH?")
            self.console.print("[yellow][*] Trying TCP connect scan (-sT) instead...")
            try:
                scan_args = '-sT -sV -T4' # Fallback without OS detection or SYN scan
                self.console.print(f"[cyan][*] Running nmap with arguments: {scan_args} on {ip_string}")
                self.nm.scan(hosts=ip_string, arguments=scan_args)
            except nmap.PortScannerError as e2:
                 self.console.print(f"[red][-] Nmap fallback scan also failed: {e2}")
                 return
            except Exception as e_generic_fallback:
                 self.console.print(f"[red][-] Unexpected error during nmap fallback scan: {e_generic_fallback}")
                 return
        except Exception as e_generic:
            self.console.print(f"[red][-] Unexpected error during nmap scan: {e_generic}")
            return

        self.results['port_scan'] = {}
        for host in self.nm.all_hosts():
            if host not in self.results['port_scan']:
                 self.results['port_scan'][host] = {'ports': [], 'os': 'Unknown'}

            # Process OS Info
            os_name = "Unknown"
            if 'osmatch' in self.nm[host] and self.nm[host]['osmatch']:
                os_name = self.nm[host]['osmatch'][0]['name']
                self.os_info[host] = os_name
                self.results['port_scan'][host]['os'] = os_name

            # Process Port Info
            host_ports = []
            # Check TCP ports
            if 'tcp' in self.nm[host]:
                for port, port_data in self.nm[host]['tcp'].items():
                    if port_data['state'] == 'open':
                        service_info = {
                            'port': port,
                            'protocol': 'tcp',
                            'state': port_data['state'],
                            'service': port_data.get('name', 'unknown'),
                            'product': port_data.get('product', ''),
                            'version': port_data.get('version', '')
                        }
                        host_ports.append(service_info)
            # Check UDP ports (Note: Requires UDP scan like -sU in args)
            if 'udp' in self.nm[host]:
                 for port, port_data in self.nm[host]['udp'].items():
                    # UDP state might be 'open|filtered' or 'open'
                    if 'open' in port_data['state']:
                         service_info = {
                              'port': port,
                              'protocol': 'udp',
                              'state': port_data['state'],
                              'service': port_data.get('name', 'unknown'),
                              'product': port_data.get('product', ''),
                              'version': port_data.get('version', '')
                         }
                         host_ports.append(service_info)

            self.open_ports[host] = sorted(host_ports, key=lambda x: (x['protocol'], x['port'])) # Sort by proto then port
            self.results['port_scan'][host]['ports'] = self.open_ports[host]

        # Print Port Scan Results
        self.console.print("\n[green][+] Port Scan Results:")
        for ip in sorted(self.open_ports.keys()):
            ports = self.open_ports[ip]
            os_name = self.os_info.get(ip, "Unknown")
            if ports:
                table = Table(title=f"Open Ports for {ip} (OS: {os_name})", box=box.ROUNDED, show_header=True, header_style="bold magenta")
                table.add_column("Port", style="cyan", justify="right")
                table.add_column("Protocol", style="yellow")
                table.add_column("Service", style="blue")
                table.add_column("Product", style="green")
                table.add_column("Version", style="green")
                for p_info in ports:
                    table.add_row(str(p_info['port']), p_info['protocol'], p_info['service'], p_info['product'], p_info['version'])
                self.console.print(table)
            else:
                self.console.print(f"[yellow][-] No open ports found for {ip} (OS: {os_name}).")

    def _analyze_tech(self, domain, url, response):
        """Analyze technologies using headers and content"""
        techs = []
        headers = response.headers
        content = response.text

        # Simple Header Checks
        server = headers.get('Server')
        if server:
            techs.append({'name': server.split('/')[0], 'version': server.split('/')[1] if '/' in server else None, 'category': 'Web Server'})
        x_powered_by = headers.get('X-Powered-By')
        if x_powered_by:
            techs.append({'name': x_powered_by.split('/')[0], 'version': x_powered_by.split('/')[1] if '/' in x_powered_by else None, 'category': 'Language/Framework'})
        if headers.get('CF-Ray') or 'cloudflare' in headers.get('Server', '').lower():
             techs.append({'name': 'Cloudflare', 'version': None, 'category': 'CDN/WAF'})

        # Simple Content Checks (Examples - can be significantly expanded)
        if '<meta name="generator" content="WordPress' in content:
            version = re.search(r'WordPress\s+([0-9.]+)', content)
            techs.append({'name': 'WordPress', 'version': version.group(1) if version else None, 'category': 'CMS'})
        elif 'Joomla!' in content: # Basic check
            techs.append({'name': 'Joomla', 'version': None, 'category': 'CMS'})
        elif 'Drupal' in content: # Basic check
             techs.append({'name': 'Drupal', 'version': None, 'category': 'CMS'})
        if 'cdn.shopify.com' in content:
             techs.append({'name': 'Shopify', 'version': None, 'category': 'eCommerce'})
        if 'bootstrap' in content.lower():
            techs.append({'name': 'Bootstrap', 'version': None, 'category': 'Frontend Framework'}) # Version detection harder
        if 'jquery' in content.lower():
             techs.append({'name': 'jQuery', 'version': None, 'category': 'JavaScript Library'})
        if 'react' in content.lower():
             techs.append({'name': 'React', 'version': None, 'category': 'JavaScript Framework'})
        if 'angular' in content.lower():
            techs.append({'name': 'Angular', 'version': None, 'category': 'JavaScript Framework'})
        if 'vue' in content.lower():
             techs.append({'name': 'Vue.js', 'version': None, 'category': 'JavaScript Framework'})
        if 'google-analytics.com/analytics.js' in content or 'gtag/js' in content:
             techs.append({'name': 'Google Analytics', 'version': None, 'category': 'Analytics'})
        if 'googletagmanager.com/gtm.js' in content:
             techs.append({'name': 'Google Tag Manager', 'version': None, 'category': 'Analytics'})

        # Deduplicate based on name
        unique_techs = {tech['name'].lower(): tech for tech in techs}
        self.technologies[domain] = list(unique_techs.values())

    def detect_technologies(self):
        """Detect web technologies on the main domain and subdomains"""
        if not self.tech_detect:
            self.console.print("\n[yellow][*] Technology detection disabled.")
            return

        self.console.print("\n[yellow][*] Detecting web technologies...")
        targets = [self.target] + list(self.subdomains)
        urls_to_check = []

        # Generate potential HTTP/HTTPS URLs
        for domain in targets:
            urls_to_check.append(f"https://{domain}")
            urls_to_check.append(f"http://{domain}")

        processed_domains = set() # Avoid processing same domain twice if http/https both work

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            transient=True
        ) as progress:
            task = progress.add_task("[cyan]Checking technologies...", total=len(urls_to_check))
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_url = {executor.submit(self._fetch_url_for_tech, url): url for url in urls_to_check}

                for future in concurrent.futures.as_completed(future_to_url):
                    progress.update(task, advance=1)
                    try:
                        domain, url, response = future.result()
                        if response and domain not in processed_domains:
                            self._analyze_tech(domain, url, response)
                            processed_domains.add(domain)
                            if self.verbose:
                                self.console.print(f"[cyan][*] Analyzed: {url} (Status: {response.status_code})")
                        elif response is None and self.verbose:
                            url = future_to_url[future]
                            # self.console.print(f"[grey][-] Failed or skipped tech check: {url}") # Reduce noise
                    except Exception as e:
                         url = future_to_url[future]
                         if self.verbose:
                              self.console.print(f"[red][-] Error processing tech result for {url}: {e}")

        self.results['technologies'] = self.technologies
        if self.technologies:
            self.console.print("\n[green][+] Detected Technologies:")
            for domain, techs in sorted(self.technologies.items()):
                if techs:
                    table = Table(title=f"Technologies for {domain}", box=box.ROUNDED, show_header=True, header_style="bold magenta")
                    table.add_column("Technology", style="blue")
                    table.add_column("Version", style="green")
                    table.add_column("Category", style="yellow")
                    for tech in sorted(techs, key=lambda x: x['name']):
                        table.add_row(tech['name'], tech['version'] or 'N/A', tech['category'])
                    self.console.print(table)
        else:
            self.console.print("[yellow][-] No web technologies detected.")

    def _fetch_url_for_tech(self, url):
        """Helper to fetch URL content for tech detection"""
        domain = url.split("://")[1].split("/")[0] # Extract domain from URL
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            response = requests.get(url, timeout=self.timeout, allow_redirects=True, headers=headers, verify=False) # Added verify=False for simplicity, consider security implications
            # Only process successful responses
            if response.status_code < 400:
                return domain, url, response
            else:
                 return domain, url, None # Return domain/url even on failure for tracking
        except requests.exceptions.RequestException as e:
            if self.verbose:
                 # Keep verbose logging minimal to avoid flooding console
                 pass # self.console.print(f"[grey][-] Tech check failed for {url}: {type(e).__name__}")
            return domain, url, None # Return domain/url even on failure
        except Exception as e_generic:
             if self.verbose:
                  self.console.print(f"[red][-] Unexpected error fetching {url} for tech check: {e_generic}")
             return domain, url, None

    def _check_directory(self, base_url, directory):
        """Check if a web directory exists"""
        url = f"{base_url}/{directory.lstrip('/')}" # Ensure directory doesn't start with /
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.head(url, timeout=self.timeout, allow_redirects=False, headers=headers, verify=False) # Use HEAD, don't follow redirects initially
            # Consider 2xx and 3xx as potentially interesting directories initially
            # We will filter 301 & 302 & 307 later in the calling function
            if 200 <= response.status_code < 400:
                return url, response.status_code
            # Handle 403 Forbidden - might still indicate a directory exists
            elif response.status_code == 403:
                 return url, response.status_code # Report 403 as well
            return None, None
        except requests.exceptions.RequestException:
            return None, None
        except Exception as e:
            if self.verbose:
                 self.console.print(f"[red][-] Error checking directory {url}: {e}")
            return None, None

    def brute_force_directories(self):
        """Brute force common directories on identified web servers"""
        self.console.print("\n[yellow][*] Brute forcing web directories...")

        # Identify potential web targets (http/https on main domain and subdomains)
        web_targets = set() # Use a set to store base URLs (e.g., http://example.com)
        targets_to_probe = [self.target] + list(self.subdomains)
        for domain in targets_to_probe:
             # Simple check: assume port 80/443 might be open or rely on tech detection results
             # A more robust check would use self.open_ports if available
             web_targets.add(f"http://{domain}")
             web_targets.add(f"https://{domain}")

        if not web_targets:
            self.console.print("[red][-] No potential web targets identified for directory brute force.")
            return

        # Load directory wordlist
        wordlist_path = self.dir_wordlist
        try:
            with open(wordlist_path, 'r') as f:
                dirs_to_check = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            self.console.print(f"[cyan][+] Using directory wordlist: {wordlist_path} ({len(dirs_to_check)} entries)")
        except FileNotFoundError:
            self.console.print(f"[red][-] Directory wordlist not found: {wordlist_path}")
            dirs_to_check = ["admin", "login", "wp-admin", "uploads", "backup", "test", "dev", "api", "static", "images", "assets", "config"]
            self.console.print(f"[yellow][*] Using built-in fallback directory list ({len(dirs_to_check)} entries).")
        except Exception as e:
            self.console.print(f"[red][-] Error reading directory wordlist {wordlist_path}: {e}")
            return

        found_any_dirs = False
        self.results['directories'] = {}

        for base_url in sorted(list(web_targets)):
            found_dirs_for_target = []
            # Quick check if the base URL is even reachable before scanning directories
            try:
                base_response = requests.head(base_url, timeout=self.timeout, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0'}, verify=False)
                if base_response.status_code >= 400:
                    if self.verbose: self.console.print(f"[grey][-] Skipping directory scan for unreachable base: {base_url} (Status: {base_response.status_code})")
                    continue # Skip this base URL if it's not responding successfully
            except requests.exceptions.RequestException:
                 if self.verbose: self.console.print(f"[grey][-] Skipping directory scan for unreachable base: {base_url} (Connection Error)")
                 continue # Skip on connection errors too

            self.console.print(f"[cyan][*] Scanning directories on: {base_url}")
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TaskProgressColumn(), TimeRemainingColumn(), transient=True) as progress:
                task = progress.add_task(f"[cyan]Checking {base_url}...", total=len(dirs_to_check))
                with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                    future_to_dir = {executor.submit(self._check_directory, base_url, directory): directory for directory in dirs_to_check}

                    for future in concurrent.futures.as_completed(future_to_dir):
                        progress.update(task, advance=1)
                        try:
                            url, status_code = future.result()
                            # --- MODIFICATION HERE ---
                            # Filter out status code 301 & 302 & 307 before adding to results
                            if url and status_code and status_code not in [301, 302, 307]:
                                found_dirs_for_target.append({'url': url, 'status': status_code})
                                if self.verbose:
                                     # Decide verbosity for non-200 codes (like 403)
                                     if 200 <= status_code < 300:
                                          self.console.print(f"[green][+] Found Directory: {url} (Status: {status_code})")
                                     else: # e.g., 403 might still be interesting
                                          self.console.print(f"[yellow][?] Potential Directory: {url} (Status: {status_code})")
                            elif url and status_code == 301 & 302 & 307 and self.verbose:
                                 self.console.print(f"[grey][-] Skipping Redirect (301 & 302 & 307): {url}") # Verbose only
                        except Exception as e:
                             directory = future_to_dir[future]
                             if self.verbose:
                                  self.console.print(f"[red][-] Error processing directory result for '{directory}' on {base_url}: {e}")

            if found_dirs_for_target:
                found_any_dirs = True
                # Sort results, e.g., by status code then URL
                self.directories[base_url] = sorted(found_dirs_for_target, key=lambda x: (x['status'], x['url']))
                self.results['directories'][base_url] = self.directories[base_url]

                table = Table(title=f"Found Directories for {base_url} ({len(found_dirs_for_target)})", box=box.ROUNDED, show_header=True, header_style="bold magenta")
                table.add_column("URL", style="cyan", no_wrap=True) # Prevent wrapping long URLs
                table.add_column("Status Code", style="green", justify="right")
                for item in self.directories[base_url]:
                    table.add_row(item['url'], str(item['status']))
                self.console.print(table)
            # else:
            #     if self.verbose: self.console.print(f"[yellow][-] No non-301 & 302 & 307 directories found for {base_url}")

        if not found_any_dirs:
            self.console.print("[yellow][-] No interesting web directories found (excluding 301 & 302 & 307 redirects).")


    def check_cloud_buckets(self):
        """Check for common S3 and GCP bucket names based on the target domain"""
        self.console.print("\n[yellow][*] Checking for potential open cloud storage buckets...")
        if '.' not in self.target:
             self.console.print("[yellow][-] Cannot generate bucket names from target (not a standard domain).")
             return

        # Generate potential names (simple variations)
        domain_parts = self.target.split('.')
        base_name = domain_parts[0] # Often the company name or main part
        potential_bases = [base_name, self.target.replace('.', '-'), self.target.replace('.', '')]
        suffixes = ["", "-prod", "-dev", "-staging", "-test", "-data", "-backup", "-public", "-media", "-assets", "-storage", "-files", "-web"]
        potential_names = {f"{b}{s}" for b in potential_bases for s in suffixes}

        found_s3 = []
        found_gcp = []

        # --- Check S3 ---
        self.console.print("[cyan][*] Checking potential S3 buckets...")
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TaskProgressColumn(), transient=True) as progress:
            task = progress.add_task("[cyan]S3 Buckets...", total=len(potential_names))
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_name = {executor.submit(self._check_s3_bucket, name): name for name in potential_names}
                for future in concurrent.futures.as_completed(future_to_name):
                    progress.update(task, advance=1)
                    try:
                        name, url, status_code = future.result()
                        if url:
                             self.s3_buckets.add(url)
                             found_s3.append({'name': name, 'url': url, 'status': status_code})
                             if self.verbose: self.console.print(f"[green][+] Found S3 Bucket: {url} (Status: {status_code})")
                    except Exception as e:
                        if self.verbose: self.console.print(f"[red]Error checking S3 name {future_to_name[future]}: {e}")

        # --- Check GCP ---
        self.console.print("[cyan][*] Checking potential GCP buckets...")
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TaskProgressColumn(), transient=True) as progress:
             task = progress.add_task("[cyan]GCP Buckets...", total=len(potential_names))
             with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_name = {executor.submit(self._check_gcp_bucket, name): name for name in potential_names}
                for future in concurrent.futures.as_completed(future_to_name):
                    progress.update(task, advance=1)
                    try:
                        name, url, status_code = future.result()
                        if url:
                             self.gcp_buckets.add(gcp_url)
                             found_gcp.append({'name': name, 'url': url, 'status': status_code})
                             if self.verbose: self.console.print(f"[green][+] Found GCP Bucket: {url} (Status: {status_code})")
                    except Exception as e:
                         if self.verbose: self.console.print(f"[red]Error checking GCP name {future_to_name[future]}: {e}")

        # --- Report Results ---
        self.results['s3_buckets'] = sorted(list(self.s3_buckets))
        self.results['gcp_buckets'] = sorted(list(self.gcp_buckets))

        if found_s3:
            table = Table(title=f"Potential S3 Buckets ({len(found_s3)})", box=box.ROUNDED, show_header=True, header_style="bold magenta")
            table.add_column("Bucket Name", style="cyan")
            table.add_column("URL", style="blue")
            table.add_column("Status Code", style="green", justify="right")
            for bucket in sorted(found_s3, key=lambda x: x['name']):
                table.add_row(bucket['name'], bucket['url'], str(bucket['status']))
            self.console.print(table)
        else:
             self.console.print("[yellow][-] No potential S3 buckets found with common naming schemes.")

        if found_gcp:
            table = Table(title=f"Potential GCP Buckets ({len(found_gcp)})", box=box.ROUNDED, show_header=True, header_style="bold magenta")
            table.add_column("Bucket Name", style="cyan")
            table.add_column("URL", style="blue")
            table.add_column("Status Code", style="green", justify="right")
            for bucket in sorted(found_gcp, key=lambda x: x['name']):
                 table.add_row(bucket['name'], bucket['url'], str(bucket['status']))
            self.console.print(table)
        else:
             self.console.print("[yellow][-] No potential GCP buckets found with common naming schemes.")

    def _check_s3_bucket(self, name):
        """Check a single potential S3 bucket"""
        url = f"http://{name}.s3.amazonaws.com"
        try:
            # Use GET for S3 as HEAD might not reveal listability
            response = requests.get(url, timeout=self.timeout)
            # Check for non-404 responses (could be public, private, non-existent with different error)
            if response.status_code != 404:
                return name, url, response.status_code
            return name, None, None # Not found or standard 404
        except requests.exceptions.RequestException:
            return name, None, None
        except Exception: # Catch broad exceptions during network calls
             return name, None, None

    def _check_gcp_bucket(self, name):
        """Check a single potential GCP bucket"""
        url = f"https://storage.googleapis.com/{name}"
        try:
            # Use GET for GCP as well
            response = requests.get(url, timeout=self.timeout, verify=False)
            # GCP often returns 403 for private, 200 for public, 404 if doesn't exist
            if response.status_code != 404:
                return name, url, response.status_code
            return name, None, None # Not found
        except requests.exceptions.RequestException:
            return name, None, None
        except Exception:
             return name, None, None

    def check_tftp_servers(self):
        """Check if TFTP port (UDP 69) is open based on port scan results"""
        self.console.print("\n[yellow][*] Checking for potential TFTP servers (UDP Port 69)...")
        if not self.port_scan or self.nm is None:
            self.console.print("[yellow][-] TFTP check requires port scanning results (--port-scan). Skipping.")
            return

        found_tftp = []
        # Nmap UDP scans (-sU) are needed for TFTP. Check if results contain UDP info.
        # We rely on the scan_ports function having run nmap appropriately.

        for ip in self.nm.all_hosts():
            if 'udp' in self.nm[ip]:
                 for port, port_data in self.nm[ip]['udp'].items():
                     if port == 69 and 'open' in port_data.get('state', ''):
                          self.tftp_servers.add(ip)
                          found_tftp.append(ip)
                          break # Found TFTP for this IP

        self.results['tftp_servers'] = sorted(list(self.tftp_servers))
        if found_tftp:
            # Ensure unique IPs before printing
            unique_tftp_ips = sorted(list(set(found_tftp)))
            table = Table(title=f"Potential TFTP Servers ({len(unique_tftp_ips)})", box=box.ROUNDED, show_header=True, header_style="bold magenta")
            table.add_column("IP Address", style="cyan")
            for ip in unique_tftp_ips:
                table.add_row(ip)
            self.console.print(table)
            self.console.print("[yellow][!] Note: Port 69/UDP being open doesn't guarantee a functional TFTP server. UDP scans can be unreliable.")
        else:
            self.console.print("[yellow][-] No potential TFTP servers identified (Port 69/UDP open). Ensure UDP scanning (-sU) was included in nmap args if expected.")


    def generate_report(self):
        """Generate a summary report to console"""
        self.console.print("\n" + "="*60)
        self.console.print(f"[bold blue] Summary Report for: {self.target} [/]")
        scan_time_str = time.strftime('%Y-%m-%d %H:%M:%S')
        self.console.print(f"Scan completed at: {scan_time_str}")
        self.console.print("="*60 + "\n")

        # Combine all results into the self.results dictionary before printing/saving
        self.results.update({
             'target': self.target,
             'scan_time': scan_time_str,
             'target_ip': self.results.get('target_ip'),
             'subdomains': self.results.get('subdomains', {}),
             'all_ips': sorted(list(self.ip_addresses)),
             'port_scan': self.results.get('port_scan', {}), # Contains ports and OS
             'technologies': self.results.get('technologies', {}),
             'directories': self.results.get('directories', {}), # Filtered directories
             's3_buckets': sorted(list(self.results.get('s3_buckets', []))), # Ensure list for JSON
             'gcp_buckets': sorted(list(self.results.get('gcp_buckets', []))), # Ensure list for JSON
             'tftp_servers': sorted(list(self.results.get('tftp_servers', []))) # Ensure list for JSON
        })

        # --- Print sections based on results ---
        if self.results.get('target_ip'):
             self.console.print(f"[green][+] Target IP Address:[/]\n  {self.results['target_ip']}")

        if self.results.get('subdomains'):
            self.console.print(f"\n[green][+] Found Subdomains ({len(self.results['subdomains'])}):[/]")
            table = Table(box=box.MINIMAL_HEAVY_HEAD)
            table.add_column("Subdomain", style="cyan")
            table.add_column("IP Address", style="green")
            for sub, ip in sorted(self.results['subdomains'].items()):
                 table.add_row(sub, ip)
            self.console.print(table)

        if self.results.get('port_scan'):
            self.console.print("\n[green][+] Port Scan & OS Detection:[/]")
            for ip, data in sorted(self.results['port_scan'].items()):
                os_info = data.get('os', 'Unknown')
                ports = data.get('ports', [])
                if ports:
                    table = Table(title=f"{ip} (OS: {os_info})", box=box.MINIMAL_HEAVY_HEAD, show_header=True, header_style="bold blue")
                    table.add_column("Port", style="cyan", justify="right")
                    table.add_column("Proto", style="yellow")
                    table.add_column("Service", style="blue")
                    table.add_column("Product/Version", style="green")
                    for p in ports:
                        prod_ver = f"{p['product']} {p['version']}".strip()
                        table.add_row(str(p['port']), p['protocol'], p['service'], prod_ver)
                    self.console.print(table)
                # else: # Reduce noise - don't print if no ports found for an IP unless verbose?
                #    self.console.print(f"[yellow]- {ip} (OS: {os_info}): No open ports found in scan results.")

        if self.results.get('technologies'):
            self.console.print("\n[green][+] Detected Web Technologies:[/]")
            for domain, techs in sorted(self.results['technologies'].items()):
                 if techs:
                    table = Table(title=f"{domain}", box=box.MINIMAL_HEAVY_HEAD, show_header=True, header_style="bold blue")
                    table.add_column("Technology", style="blue")
                    table.add_column("Version", style="green")
                    table.add_column("Category", style="yellow")
                    for t in sorted(techs, key=lambda x: x['name']):
                        table.add_row(t['name'], t['version'] or 'N/A', t['category'])
                    self.console.print(table)

        if self.results.get('directories'):
             self.console.print("\n[green][+] Found Web Directories (excluding 301 & 302 & 307):[/]")
             any_dirs_printed = False
             for base_url, dirs in sorted(self.results['directories'].items()):
                  if dirs:
                       any_dirs_printed = True
                       table = Table(title=f"{base_url}", box=box.MINIMAL_HEAVY_HEAD, show_header=True, header_style="bold blue")
                       table.add_column("URL", style="cyan", no_wrap=True)
                       table.add_column("Status", style="green", justify="right")
                       for d in dirs:
                            table.add_row(d['url'], str(d['status']))
                       self.console.print(table)
             # if not any_dirs_printed: # Message moved to brute_force_directories end
             #      self.console.print("[yellow]- None found.")


        if self.results.get('s3_buckets'):
             self.console.print(f"\n[green][+] Potential S3 Buckets ({len(self.results['s3_buckets'])}):[/]")
             for url in self.results['s3_buckets']: self.console.print(f"  - {url}")
        if self.results.get('gcp_buckets'):
             self.console.print(f"\n[green][+] Potential GCP Buckets ({len(self.results['gcp_buckets'])}):[/]")
             for url in self.results['gcp_buckets']: self.console.print(f"  - {url}")
        if self.results.get('tftp_servers'):
             self.console.print(f"\n[green][+] Potential TFTP Servers ({len(self.results['tftp_servers'])}):[/]")
             for ip in self.results['tftp_servers']: self.console.print(f"  - {ip}")

        self.console.print("\n" + "="*60)
        self.console.print("[bold blue] End of Summary Report [/]")
        self.console.print("="*60 + "\n")

        # Save report to file if output is specified
        if self.output:
            self._save_report() # Uses the self.results dict

    def _save_report(self):
        """Save the aggregated results to a file (JSON or TXT)"""
        if not self.output:
            return

        output_format = 'txt'
        # Ensure output path exists if directories are specified
        output_dir = os.path.dirname(self.output)
        if output_dir and not os.path.exists(output_dir):
             try:
                  os.makedirs(output_dir)
                  self.console.print(f"[cyan][*] Created output directory: {output_dir}")
             except OSError as e:
                  self.console.print(f"[red][-] Failed to create output directory {output_dir}: {e}")
                  return # Cannot save if dir creation fails

        if self.output.lower().endswith('.json'):
            output_format = 'json'

        try:
            if output_format == 'json':
                # Make sure results are JSON serializable (sets converted to lists already)
                with open(self.output, 'w') as f:
                    json.dump(self.results, f, indent=4)
            else: # Default to TXT
                with open(self.output, 'w') as f:
                    f.write(f"findIt Scan Report for: {self.results.get('target')}\n")
                    f.write(f"Scan Time: {self.results.get('scan_time')}\n")
                    f.write("="*40 + "\n\n")

                    if self.results.get('target_ip'): f.write(f"Target IP: {self.results['target_ip']}\n\n")

                    if self.results.get('subdomains'):
                        f.write("Subdomains:\n")
                        for sub, ip in sorted(self.results['subdomains'].items()): f.write(f"  - {sub} ({ip})\n")
                        f.write("\n")

                    if self.results.get('port_scan'):
                         f.write("Port Scan & OS Detection:\n")
                         for ip, data in sorted(self.results['port_scan'].items()):
                              os_info = data.get('os', 'Unknown')
                              ports = data.get('ports', [])
                              f.write(f"  {ip} (OS: {os_info}):\n")
                              if ports:
                                   for p in ports:
                                        prod_ver = f"{p['product']} {p['version']}".strip()
                                        f.write(f"    - Port {p['port']}/{p['protocol']} ({p['state']}): {p['service']} {prod_ver}\n")
                              else:
                                   f.write("    - No open ports found.\n")
                         f.write("\n")

                    if self.results.get('technologies'):
                         f.write("Detected Web Technologies:\n")
                         for domain, techs in sorted(self.results['technologies'].items()):
                              if techs:
                                   f.write(f"  {domain}:\n")
                                   for t in sorted(techs, key=lambda x: x['name']):
                                        f.write(f"    - {t['name']} (Version: {t['version'] or 'N/A'}, Category: {t['category']})\n")
                         f.write("\n")

                    if self.results.get('directories'):
                         f.write("Found Web Directories (excluding 301 & 302 & 307):\n")
                         for base_url, dirs in sorted(self.results['directories'].items()):
                              if dirs:
                                   f.write(f"  {base_url}:\n")
                                   for d in dirs: f.write(f"    - {d['url']} (Status: {d['status']})\n")
                         f.write("\n")

                    if self.results.get('s3_buckets'):
                         f.write("Potential S3 Buckets:\n")
                         for url in self.results['s3_buckets']: f.write(f"  - {url}\n")
                         f.write("\n")
                    if self.results.get('gcp_buckets'):
                         f.write("Potential GCP Buckets:\n")
                         for url in self.results['gcp_buckets']: f.write(f"  - {url}\n")
                         f.write("\n")
                    if self.results.get('tftp_servers'):
                         f.write("Potential TFTP Servers:\n")
                         for ip in self.results['tftp_servers']: f.write(f"  - {ip}\n")
                         f.write("\n")

            self.console.print(f"[green][+] Report saved successfully to {self.output}")

        except Exception as e:
            self.console.print(f"[red][-] Failed to save report to {self.output}: {e}")


    def run(self):
        """Run the full scan sequence"""
        self.banner()
        start_time = time.time()

        # 1. Resolve main domain
        if not self.resolve_domain():
            self.console.print(f"[red][-] Cannot proceed without resolving the main target: {self.target}. Exiting.")
            sys.exit(1)

        # 2. Enumerate Subdomains
        self.enumerate_subdomains()

        # 3. Port Scan (if enabled) - requires IPs from steps 1 & 2
        if self.port_scan:
            self.scan_ports() # This also attempts OS detection

        # 4. Technology Detection (if enabled) - uses target + subdomains
        if self.tech_detect:
            self.detect_technologies()

        # 5. Directory Brute Force - uses target + subdomains
        self.brute_force_directories() # Now filters 301 & 302 & 307 internally

        # 6. Cloud Bucket Checks
        self.check_cloud_buckets()

        # 7. TFTP Check (if port scan was enabled)
        # Note: TFTP check effectiveness depends on nmap UDP scan results
        self.check_tftp_servers()

        # 8. Generate Console Report & Save File
        self.generate_report() # This now also calls _save_report if self.output is set

        end_time = time.time()
        elapsed_time = end_time - start_time
        self.console.print(f"\n[bold green][+] Scan completed in {elapsed_time:.2f} seconds.[/]")


def show_help():
    """Show detailed help information using Rich for better formatting"""
    console = Console()
    console.print(f"""
[bold blue]╔═══════════════════════════════════════════════════════════════════════════╗[/]
[bold blue]║ [bold green]findIt - Advanced Domain Scanner[/]                                          ║[/]
[bold blue]╚═══════════════════════════════════════════════════════════════════════════╝[/]

[bold yellow]USAGE:[/bold yellow]
  [cyan]python findit.py[/] [OPTIONS] TARGET

[bold yellow]DESCRIPTION:[/bold yellow]
  findIt is a comprehensive domain reconnaissance tool that performs:
  - Domain to IP resolution
  - Subdomain enumeration (via wordlist brute-force)
  - Port scanning and OS fingerprinting ([italic]optional, requires nmap[/italic])
  - Web directory brute forcing ([italic]optional wordlist[/italic])
  - Cloud storage bucket detection (S3 and GCP, common names)
  - TFTP server detection ([italic]requires port scan results[/italic])
  - Basic web technology detection

[bold yellow]ARGUMENTS:[/bold yellow]
  [green]TARGET[/]                        Target domain name to scan (e.g., example.com)

[bold yellow]OPTIONS:[/bold yellow]
  [green]-h, --help[/]                    Show this help message and exit
  [green]-t, --threads[/] [blue]INT[/]             Number of concurrent threads for scans (default: 10)

  [green]-w, --wordlist[/] [blue]FILE[/]           Path to custom wordlist for subdomain enumeration
                                ([italic]default: subdomains.txt[/italic])

  [green]-dw, --dir-wordlist[/] [blue]FILE[/]      Path to custom wordlist for directory brute-forcing
                                ([italic]default: directories.txt[/italic])

  [green]-p, --port-scan[/]               Enable port scanning, service/version detection, and OS detection using nmap.
                                [bold red]Requires nmap installed and potentially root/admin privileges.[/]

  [green]--timeout[/] [blue]INT[/]                 Connection timeout in seconds for network requests (default: 5)
  [green]-v, --verbose[/]                 Enable verbose output (shows more progress and errors)
  [green]-o, --output[/] [blue]FILE[/]             Save results to a file. Supports [cyan].json[/] or defaults to [cyan].txt[/] format.
  [green]--no-tech-detect[/]              Disable web technology detection scan.

[bold yellow]EXAMPLES:[/bold yellow]
  [cyan]python findit.py example.com[/]
  [cyan]python findit.py example.com -p -t 20 -v[/]
  [cyan]python findit.py example.com -p -o report.json[/]
  [cyan]python findit.py example.com -w custom_subs.txt -dw custom_dirs.txt --timeout 10[/]

[bold yellow]AUTHOR:[/bold yellow]
  Created by Vyom

[bold yellow]NOTES:[/bold yellow]
  - Ensure required libraries are installed: [cyan]requests, python-nmap, colorama, rich[/]
  - [bold]Port scanning ([cyan]-p[/]) requires the 'nmap' executable[/] to be installed and in your system's PATH.
  - Some scans ([cyan]-sS, -O[/] in nmap) may require root/administrator privileges.
  - Wordlists significantly impact subdomain and directory discovery success. Defaults are basic.
  - Use responsibly and ethically. [bold red]Do not scan targets without explicit permission.[/]
    """)

def main():
    # Setup Argument Parser
    parser = argparse.ArgumentParser(
        description="findIt - Advanced Domain Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter, # Preserve formatting in help
        add_help=False # We use our custom help function
    )

    # Required Argument
    parser.add_argument("target", nargs="?", help="Target domain to scan (e.g., example.com)") # Optional here to allow --help without target

    # Optional Arguments
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")
    parser.add_argument("-t", "--threads", type=int, default=10, metavar='INT', help="Number of concurrent threads (default: 10)")
    parser.add_argument("-w", "--wordlist", metavar='FILE', help="Custom wordlist for subdomain brute force")
    parser.add_argument("-dw", "--dir-wordlist", metavar='FILE', help="Custom wordlist for directory brute force")
    parser.add_argument("-p", "--port-scan", action="store_true", help="Enable port scanning with nmap (requires nmap, may need root)")
    parser.add_argument("--timeout", type=int, default=5, metavar='INT', help="Connection timeout in seconds (default: 5)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-o", "--output", metavar='FILE', help="Save results to a file (.txt or .json)")
    parser.add_argument("--no-tech-detect", action="store_false", dest='tech_detect', help="Disable technology detection") # Set default to True implicitly

    # Parse Arguments
    args = parser.parse_args()

    # Handle Help Request or Missing Target
    if args.help or not args.target:
        show_help()
        sys.exit(0)

    # --- Input Validation ---
    if args.threads <= 0:
        print("[!] Error: Number of threads must be positive.")
        sys.exit(1)
    if args.timeout <= 0:
        print("[!] Error: Timeout must be positive.")
        sys.exit(1)

    # Create Scanner Instance
    scanner = FindIt(
        target=args.target,
        threads=args.threads,
        wordlist=args.wordlist, # Pass None if not provided, __init__ handles default
        dir_wordlist=args.dir_wordlist, # Pass None if not provided
        port_scan=args.port_scan,
        timeout=args.timeout,
        verbose=args.verbose,
        output=args.output,
        tech_detect=args.tech_detect # Use the result of dest='tech_detect'
    )

    # Run the Scanner
    try:
        scanner.run()
    except KeyboardInterrupt:
        scanner.console.print("\n[bold red][!] Scan interrupted by user. Exiting.[/]")
        sys.exit(0)
    except Exception as e:
        # Catch unexpected errors during the run
        scanner.console.print(f"\n[bold red][!] An unexpected error occurred during the scan: {e}[/]")
        import traceback
        if args.verbose: # Print traceback if verbose
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
